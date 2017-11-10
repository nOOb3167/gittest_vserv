#ifndef _VSERV_NET_H_
#define _VSERV_NET_H_

#include <stddef.h>

#include <gittest/config.h>

#define GS_ADDR_RAWHASH_BUCKET(RAWHASH, NUM_BUCKETS) ((RAWHASH) % (NUM_BUCKETS))

/* intended to be forward-declared in header (API use pointer only) */
struct GsVServCtl;
struct GsVServRespond;
struct GsVServWrite;
struct GsAddr;

#ifdef __cplusplus
struct gs_addr_hash_t { size_t operator()(const struct GsAddr &k) const; };
struct gs_addr_equal_t { bool operator()(const GsAddr &a, const GsAddr &b) const; };
#endif /* __cplusplus */

/* receives pointer (Data) to the to-be-deleted data pointer (*Data)
   deletion must be skipped if *Data is NULL
   deletion must cause *Data to become NULL */
typedef int (*gs_data_deleter_t)(char **Data);

enum GsSockType
{
	GS_SOCK_TYPE_NORMAL = 2,
	GS_SOCK_TYPE_EVENT = 3,
	GS_SOCK_TYPE_WAKE = 4,
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

size_t gs_addr_rawhash(struct GsAddr *Addr)
{
	return gs_addr_hash_t()(*Addr);
}

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

int gs_vserv_write_elt_del_free(char **DataBuf)
{
	if (*DataBuf) {
		free(*DataBuf);
		*DataBuf = NULL;
	}
	return 0;
}

/** 
	for epoll(2) EPOLLET edge-triggered mode specifically, writing until EAGAIN is important
	  as no further EPOLLOUT (writability) events will be received otherwise (socket remains writable)
*/
int gs_vserv_write_drain_to(struct GsVServCtl *ServCtl, size_t SockIdx, int *oHaveEAGAIN)
{
	int r = 0;

	struct GsVServWrite *Write = ServCtl->mWriteVec[SockIdx];
	int Fd = ServCtl->mSockFdVec[SockIdx];

	int HaveEAGAIN = 0;

	std::deque<GsVServWriteEntry>::iterator it;

	if (Write->mQueue.empty())
		GS_ERR_NO_CLEAN(0);

	for (it = Write->mQueue.begin(); it != Write->mQueue.end(); ++it) {
		ssize_t NSent = 0;
		while (-1 == (NSent = sendto(Fd, it->mElt.mData, it->mElt.mLenData, MSG_NOSIGNAL, &it->mAddr.mAddr, sizeof it->mAddr.mAddr))) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				HaveEAGAIN = 1;
				goto donewriting;
			}
			GS_ERR_CLEAN(1);
		}
	}
donewriting:
	Write->mQueue.erase(Write->mQueue.begin(), it);

noclean:
	if (oHaveEAGAIN)
		*oHaveEAGAIN = HaveEAGAIN;

clean:

	return r;
}

/** WARNING: this function is affected by caller CPU
      the designed flow is: x-th receiver calls crank with 'Respond',
	  crank on x-th receiver calls ex gs_vserv_respond_enqueue.
	  maybe should just acquire mutexes */
int gs_vserv_respond_enqueue(
	struct GsVServRespond *Respond,
	gs_data_deleter_t DataDeleter,
	char **EntryDataVec, /*owned*/
	size_t *EntryLenDataVec,
	struct GsAddr *EntryAddrVec,
	size_t LenEntryVecs)
{
	int r = 0;

	struct GsVServCtl *ServCtl = Respond->mServCtl;
	struct GsVServWrite *Write = ServCtl->mWriteVec[Respond->mSockIdx];
	int Fd = ServCtl->mSockFdVec[Respond->mSockIdx];

	size_t NumWrite = 0;

	/* feature may send some messages immediately */

	if (Write->mTryAtOnce) {
		for (size_t NumWrite = 0; NumWrite < LenEntryVecs; NumWrite++) {
			ssize_t NSent = 0;
			while (-1 == (NSent = sendto(Fd, EntryDataVec[NumWrite], EntryLenDataVec, MSG_NOSIGNAL, &EntryAddrVec[NumWrite].mAddr, sizeof EntryAddrVec[NumWrite].mAddr))) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					goto donewriting;
				GS_ERR_CLEAN(1);
			}
			if (!! DataDeleter(&EntryDataVec[NumWrite]))
				GS_ASSERT(0);
		}
	donewriting:
	}

	/* queue any not yet sent */

	for (size_t i = NumWrite; i < LenEntryVecs; i++) {
		struct GsVServWriteEntry Entry;
		Entry.mAddr = EntryAddrVec[i];
		Entry.mElt.mLenData = EntryLenDataVec[i];
		Entry.mElt.mData = std::move(std::shared_ptr<char>(EntryDataVec[i], DataDeleter));
		EntryDataVec[i] = NULL;
		Write->mQueue.push_back(std::move(Entry));
	}

clean:

	return r;
}

int gs_vserv_sockets_create(
	const char *Port,
	int *ioSockFdVec, size_t SockFdNum);

int gs_vserv_start(struct GsAuxConfigCommonVars *CommonVars);

#endif /* _VSERV_NET_H_ */
