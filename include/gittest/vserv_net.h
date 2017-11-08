#ifndef _VSERV_NET_H_
#define _VSERV_NET_H_

#include <stddef.h>

#include <gittest/config.h>

/* intended to be forward-declared in header (API use pointer only) */
struct GsVServRespond;
struct GsVServCtl;
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

int gs_vserv_write_drain_to(struct GsVServWrite *Write, int Fd)
{
	int r = 0;

	int HaveLock = 0;

	if (!!(r = pthread_mutex_lock(&Write->mMutex)))
		GS_GOTO_CLEAN();
	HaveLock = 1;

	while (true) {
		struct iovec IoVec[GS_VSERV_SEND_NUMIOVEC] = {};
		const size_t NumIoVec = GS_MIN(Write->mQueue.size(), GS_VSERV_SEND_NUMIOVEC);
		struct msghdr Hdr = {};
		if (NumIoVec) {
			for (size_t i = 0; i < NumIoVec; i++) {
				struct GsVServWriteElt &Elt = Write->mQueue[i];
				IoVec[i].iov_base = Elt.mDataBuf;
				IoVec[i].iov_len = Elt.mLenData;
			}
			Hdr.msg_name = ;
			if (!!(qqqq = sendmsg(Fd, , MSG_NOSIGNAL))) {

			}
		}
	}

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
	struct GsVServWriteElt Elt = {};

	if (Fd == -1)
		GS_ERR_CLEAN(1);

	if (!!(r = pthread_mutex_lock(&Write->mMutex)))
		GS_GOTO_CLEAN();
	HaveLock = 1;

	// FIXME: not implemented yet
	if (Write->mTryAtOnce) {}

	Elt.mDataBuf = DataBuf;
	Elt.mLenData = LenData;
	Elt.mDel = gs_vserv_write_elt_del_free;
	Elt.mAddr = *Addr;

	Write->mQueue.push_back(Elt);

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
