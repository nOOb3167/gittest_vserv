#ifndef _VSERV_NET_H_
#define _VSERV_NET_H_

#include <stddef.h>

#include <gittest/config.h>

/* intended to be forward-declared in header (API use pointer only) */
struct GsVServCtl;
struct GsVServRespond;
struct GsVServWrite;
struct GsAddr;

#ifdef __cplusplus
struct gs_addr_hash_t { size_t operator()(const struct GsAddr &k) const; };
struct gs_addr_equal_t { bool operator()(const GsAddr &a, const GsAddr &b) const; };
#endif /* __cplusplus */

enum GsSockType
{
	GS_SOCK_TYPE_NORMAL = 2,
	GS_SOCK_TYPE_EVENT = 3,
};

struct GsPacket
{
	uint8_t *data;
	size_t   dataLength;
};

struct GsVServCtlCb
{
	int(*CbCrank)(struct GsVServCtlCb *Cb, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond);
};

int gs_vserv_ctl_create_part(
	size_t ThreadNum,
	int *ioSockFdVec, size_t SockFdNum, /*owned*/
	struct GsVServCtlCb *Cb,
	struct GsVServCtl **oServCtl);
int gs_vserv_ctl_create_finish(
	struct GsVServCtl *ServCtl);
int gs_vserv_ctl_destroy(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_request(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_wait(struct GsVServCtl *ServCtl);

int gs_vserv_write_create(
	struct GsVServWrite **oWrite)
{
	int r = 0;

	struct GsVServWrite *Write = NULL;

	Write = new GsVServWrite();
	Write->mTryAtOnce = false;
	Write->mQueue;

	if (!!(r = pthread_mutex_init(&Write->mMutex, NULL)))
		GS_GOTO_CLEAN();

	if (oWrite)
		*oWrite = GS_ARGOWN(&Write);

clean:
	GS_DELETE(&Write, struct GsVServWrite);

	return r;
}

int gs_vserv_write_destroy(struct GsVServWrite *Write)
{
	if (Write) {
		if (!! pthread_mutex_destroy(&Write->mMutex))
			GS_ASSERT(0);
		GS_DELETE(&Write, struct GsVServWrite);
	}
	return 0;
}

/** oCallAgain and oHaveEAGAIN mutually exclusive
    (ex once EAGAIN occurs, no way calling this function again would write more data)

    oCallAgain indicates calling this function again may result in more data being written
	oHaveEAGAIN indicates syscall EAGAIN occurred attempting to write

	for epoll(2) EPOLLET edge-triggered mode specifically, writing until EAGAIN is important
	  as no further EPOLLOUT (writability) events will be received otherwise (socket remains writable)
*/
int gs_vserv_write_drain_to(struct GsVServWrite *Write, int Fd, int *oCallAgain, int *oHaveEAGAIN)
{
	int r = 0;

	int CallAgain = 0;
	int HaveLock = 0;
	int HaveEAGAIN = 0;
	gs_inflight_map_t::iterator it;

	if (!!(r = pthread_mutex_lock(&Write->mMutex)))
		GS_GOTO_CLEAN();
	HaveLock = 1;

	/* nothing to write and no EAGAIN */

	if (Write->mQueue.empty())
		GS_ERR_NO_CLEAN(0);

	/* otherwise - proceed attemping to write the first Queue Entry */

	it = Write->mQueue.front();
	Write->mQueue.pop_front();

	struct GsVServWriteEntry &Entry = it->second;

	while (! HaveEAGAIN && ! Entry.mElt.empty()) {
		/* writes are coalesced via sendmsg call */
		struct iovec IoVec[GS_VSERV_SEND_NUMIOVEC] = {};
		const size_t NumIoVec = GS_MIN(Entry.mElt.size(), GS_VSERV_SEND_NUMIOVEC);
		struct msghdr Hdr = {};
		ssize_t NSent = 0;
		/* queries multiple Elts but does not pop any here - see below for post-write adjustment */
		for (size_t i = 0; i < NumIoVec; i++) {
			struct GsVServWriteElt &Elt = Entry.mElt[i];
			IoVec[i].iov_base = Elt.mData.get();
			IoVec[i].iov_len = Elt.mLenData;
		}
		Hdr.msg_name = Entry.mAddr;
		Hdr.msg_namelen = sizeof Entry.mAddr;
		Hdr.msg_iov = IoVec;
		Hdr.msg_iovlen = NumIoVec;
		Hdr.msg_control = NULL;
		Hdr.msg_controllen = 0;
		Hdr.flags = 0;
		while (0 > (NSent = sendmsg(Fd, &Hdr, MSG_NOSIGNAL))) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				HaveEAGAIN = 1;
				goto endofwhilebody;
			}
			GS_ERR_CLEAN(1);
		}
		/* post-write adjustment - Elts popped wrt amount of data successfully written */
		GS_ASSERT(NSent >= 0);
		while (NSent > 0) {
			GS_ASSERT(! Entry.mElt.empty() && Entry.mElt.front().mLenData <= NSent);
			NSent -= Entry.mElt.front().mLenData;
			Entry.mElt.pop_front();
		}
	endofwhilebody:
	}

	if (Entry.mElt.empty()) {
		/* if succeeded sending all Elts, remove Entry */
		Write->mAddrInFlight.erase(it);
	}
	else {
		/* if failed to send all Elts (ex EAGAIN), requeue Entry */
		Write->mQueue.push_back(it);
	}

	/* if socket hasnt been filled up to the point of causing EAGAIN, we can send more data if any is available
	   data availability indicated by queue non-emptiness */

	if (! HaveEAGAIN && ! Write->mQueue.empty())
		CallAgain = 1;

noclean:
	if (oCallAgain)
		*oCallAgain = CallAgain;

	if (oHaveEAGAIN)
		*oHaveEAGAIN = HaveEAGAIN;

clean:
	if (HaveLock)
		if (!! pthread_mutex_unlock(&Write->mMutex))
			GS_ASSERT(0);

	return r;
}

int gs_vserv_write_elt_del_free(char **DataBuf)
{
	if (*DataBuf) {
		free(*DataBuf);
		*DataBuf = NULL;
	}
	return 0;
}

int gs_vserv_respond_enqueue(struct GsVServRespond *Respond, struct GsAddr *Addr, char *DataBuf, size_t LenData)
{
	int r = 0;

	struct GsVServCtl *ServCtl = Respond->mServCtl;

	struct GsVServWrite *Write = ServCtl->mWriteVec[Respond->mSockFdIdx];
	int Fd = ServCtl->mSockFdVec[Respond->mSockFdIdx];
	int HaveLock = 0;

	if (Fd == -1)
		GS_ERR_CLEAN(1);

	if (!!(r = pthread_mutex_lock(&Write->mMutex)))
		GS_GOTO_CLEAN();
	HaveLock = 1;

	// FIXME: not implemented yet
	if (Write->mTryAtOnce) {}

	{
		/* ensure Addr is or becomes handled by 'Write' (presence of map entry) */
		gs_inflight_map_t::iterator it = Write->mAddrInFlight.find(*Addr);
		if (it == Write->mAddrInFlight.end()) {
			struct GsVServWriteEntry Entry;
			Entry.mQueuedAlready = false;
			Entry.mAddr = *Addr;
			Entry.mElt; /*dummy*/
			auto itb = Write->mAddrInFlight.insert(std::make_pair(Entry.mAddr, std::move(Entry)));
			GS_ASSERT(itb.second);
			it = itb.first;
		}
		/* queue the data */
		struct GsVServWriteElt Elt = {};
		Elt.mData = std::shared_ptr<char>(DataBuf, gs_vserv_write_elt_del_free);
		Elt.mLenData = LenData;
		it->second.mElt.push_back(std::move(Elt));
		/* ensure Addr (map entry) is in the ready list / queue */
		if (! it->second.mQueuedAlready) {
			Write->mQueue.push_back(it);
			it->second.mQueuedAlready = true;
		}
	}

clean:
	if (HaveLock)
		if (!! pthread_mutex_unlock(&Write->mMutex))
			GS_ASSERT(0);

	return r;
}

int gs_vserv_sockets_create(
	const char *Port,
	int *ioSockFdVec, size_t SockFdNum);

int gs_vserv_start(struct GsAuxConfigCommonVars *CommonVars);

#endif /* _VSERV_NET_H_ */
