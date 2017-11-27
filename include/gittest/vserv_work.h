#ifndef _VSERV_WORK_H_
#define _VSERV_WORK_H_

#include <stddef.h>

#include <deque>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>

#define GS_VSERV_EPOLL_NUMEVENTS 8
#define GS_VSERV_UDP_SIZE_MAX 65535

struct GsVServRespond
{
	struct GsVServCtl *mServCtl;
	size_t mSockIdx;
};

struct GsVServWriteElt
{
	sp<uint8_t> mData; size_t mLenData;
};

struct GsVServWriteEntry
{
	struct GsAddr mAddr;
	struct GsVServWriteElt mElt;
};

/** @sa
       ::gs_vserv_respond_enqueue
*/
struct GsVServWrite
{
	bool mTryAtOnce;
	std::deque<GsVServWriteEntry> mQueue;
};

struct GsVServWork
{
	int *mSockFdVec; size_t mSockFdNum;
	int *mEPollFdVec; size_t mEPollFdNum;
	struct GsVServWrite **mWriteVec; size_t mWriteNum;
	int *mWakeAsyncVec; size_t mWakeAsyncNum;
};

struct GsEPollCtx
{
	enum GsSockType mType;
	struct GsVServCtl *mServCtl; /*notowned*/
	size_t mSockIdx;
	size_t mFd; /*notowned - informative*/
};

int gs_vserv_receive_func(
	struct GsVServCtl *ServCtl,
	size_t SockIdx);

int gs_vserv_work_create(
	size_t ThreadNum,
	int *ioSockFdVec, size_t SockFdNum, /*owned/stealing*/
	struct GsVServCtl *ServCtl, /*partial/refonly*/
	struct GsVServQuitCtl *QuitCtl, /*notowned*/
	struct GsVServWork **oWork);
int gs_vserv_work_destroy(struct GsVServWork *Work);

#endif /* _VSERV_WORK_H_ */
