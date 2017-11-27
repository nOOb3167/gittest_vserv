#include <cstddef>
#include <cstdint>

#include <deque>

// FIXME: some day figure which of these are ACTUALLY needed
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_net.h>
#include <gittest/vserv_work.h>

static int gs_vserv_epollctx_add_for(
	int EPollFd,
	size_t SockIdx,
	int Fd,
	enum GsSockType Type,
	struct GsVServCtl *ServCtl);
static int gs_vserv_receive_evt_normal(
	struct GsVServWork *Work,
	struct GsVServCtl *ServCtl,
	struct GsEPollCtx *EPollCtx,
	uint8_t *UdpBuf, size_t UdpSize);
static int gs_vserv_receive_evt_event(
	struct GsVServWork *Work,
	struct GsEPollCtx *EPollCtx);
static int gs_vserv_receive_writable(
	struct GsVServWork *Work,
	struct GsEPollCtx *EPollCtx);

int gs_vserv_epollctx_add_for(
	int EPollFd,
	size_t SockIdx,
	int Fd,
	enum GsSockType Type,
	struct GsVServCtl *ServCtl)
{
	int r = 0;

	struct epoll_event Evt = {};

	struct GsEPollCtx **EvtDataPtr = (struct GsEPollCtx **) &Evt.data.ptr;

	if (Type == GS_SOCK_TYPE_NORMAL)
		Evt.events = EPOLLOUT | EPOLLIN | EPOLLET;    /* NOTE: no EPOLLONESHOT this time */
	else
		Evt.events = EPOLLIN | EPOLLET;
	/* remainder effectively setting up Evt.data.ptr */
	(*EvtDataPtr) = new GsEPollCtx();
	(*EvtDataPtr)->mType = Type;
	(*EvtDataPtr)->mServCtl = ServCtl;
	(*EvtDataPtr)->mSockIdx = SockIdx;
	(*EvtDataPtr)->mFd = Fd;

	if (-1 == epoll_ctl(EPollFd, EPOLL_CTL_ADD, Fd, &Evt))
		GS_ERR_CLEAN(1);
	(*EvtDataPtr) = NULL;

clean:
	GS_DELETE(&(*EvtDataPtr), struct GsEPollCtx);

	return r;
}

int gs_vserv_receive_evt_normal(
	struct GsVServWork *Work,
	struct GsVServCtl *ServCtl,
	struct GsEPollCtx *EPollCtx,
	uint8_t *UdpBuf, size_t UdpSize)
{
	int r = 0;

	struct GsVServWorkCb *WorkCb = gs_vserv_ctl_get_workcb(ServCtl);

	const int Fd = Work->mSockFdVec[GS_MIN(EPollCtx->mSockIdx, Work->mSockFdNum - 1)];
	bool DoneReading = 0;

	GS_ASSERT(Fd == EPollCtx->mFd);

	/* remember to read until EAGAIN for edge-triggered epoll (EPOLLET) */
	while (! DoneReading) {
		ssize_t NRecv = 0;
		struct sockaddr_in SockAddr = {};
		socklen_t SockAddrSize = sizeof SockAddr;
		struct GsPacket Packet = {};
		struct GsAddr Addr = {};
		struct GsVServRespond Respond = {};
		while (-1 == (NRecv = recvfrom(Fd, UdpBuf, UdpSize, MSG_TRUNC, (struct sockaddr *)&SockAddr, &SockAddrSize))) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				DoneReading = 1;
				goto donereading;
			}
			GS_ERR_CLEAN(1);
		}
		/* detect datagram truncation (see MSG_TRUNC) */
		if (NRecv > UdpSize)
			GS_ERR_CLEAN(1);
		/* detect somehow receiving from wrong address family? */
		if (SockAddrSize != sizeof SockAddr || SockAddr.sin_family != AF_INET)
			GS_ERR_CLEAN(1);
		/* dispatch datagram */
		Packet.data = UdpBuf;
		Packet.dataLength = NRecv;
		Addr.mSinFamily = SockAddr.sin_family;
		Addr.mSinPort = ntohs(SockAddr.sin_port);
		Addr.mSinAddr = ntohl(SockAddr.sin_addr.s_addr);
		Respond.mServCtl = ServCtl;
		Respond.mSockIdx = EPollCtx->mSockIdx;
		if (!!(r = WorkCb->CbCrank(ServCtl, &Packet, &Addr, &Respond)))
			GS_GOTO_CLEAN();
	}
donereading:

clean:

	return r;
}

int gs_vserv_receive_evt_event(
	struct GsVServWork *Work,
	struct GsEPollCtx *EPollCtx)
{
	int r = 0;

	const int Fd = Work->mSockFdVec[GS_MIN(EPollCtx->mSockIdx, Work->mSockFdNum - 1)];

	GS_ASSERT(Fd == EPollCtx->mFd);

	if (!!(r = gs_eventfd_read(Fd)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_receive_writable(
	struct GsVServWork *Work,
	struct GsEPollCtx *EPollCtx)
{
	int r = 0;

	const int Fd = Work->mSockFdVec[GS_MIN(EPollCtx->mSockIdx, Work->mSockFdNum - 1)];
	struct GsVServWrite *Write = Work->mWriteVec[EPollCtx->mSockIdx];

	GS_ASSERT(Fd == EPollCtx->mFd);

	if (!!(r = gs_vserv_write_drain_to(ServCtl, EPollCtx->mSockIdx, NULL)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_receive_func(
	struct GsVServCtl *ServCtl,
	size_t SockIdx)
{
	int r = 0;

	struct GsVServWork *Work = gs_vserv_ctl_get_work(ServCtl);

	GS_ALLOCA_VAR(UdpBuf, uint8_t, GS_VSERV_UDP_SIZE_MAX);
	size_t UdpSize = GS_VSERV_UDP_SIZE_MAX;

	while (true) {
		int EPollFd = -1;
		struct epoll_event Events[GS_VSERV_EPOLL_NUMEVENTS] = {};
		int NReady = 0;

		EPollFd = Work->mEPollFdVec[SockIdx];

		/* https://lkml.org/lkml/2011/11/17/234
		     epoll_wait completing on fd registered with MASK
			 (epoll_ctl(fd,MASK) where MASK is EPOLLIN|EPOLLOUT for example)
			 will deliver event with full MASK set. consider adding twice with separate mask. */

		while (-1 == (NReady = epoll_wait(EPollFd, Events, GS_VSERV_EPOLL_NUMEVENTS, 100))) {
			if (errno == EINTR)
				continue;
			GS_ERR_CLEAN(1);
		}
		if (NReady == 0)
			continue;

		for (int i = 0; i < NReady; i++) {
			struct GsEPollCtx *EPollCtx = (struct GsEPollCtx *) Events[i].data.ptr;

			GS_ASSERT(EPollCtx->mServCtl == ServCtl);

			if (Events[i].events & EPOLLIN) {
				switch (EPollCtx->mType)
				{

				case GS_SOCK_TYPE_NORMAL:
				{
					if (!!(r = gs_vserv_receive_evt_normal(Work, EPollCtx->mServCtl, EPollCtx, UdpBuf, UdpSize)))
						GS_GOTO_CLEAN();
					if (!!(r = gs_vserv_receive_writable(EPollCtx->mServCtl, EPollCtx)))
						GS_GOTO_CLEAN();
				}
				break;

				case GS_SOCK_TYPE_EVENT:
				{
					if (!!(r = gs_vserv_receive_evt_event(EPollCtx->mServCtl, EPollCtx)))
						GS_GOTO_CLEAN();
					GS_ERR_NO_CLEAN(0);
				}
				break;

				case GS_SOCK_TYPE_WAKE:
				{
					// FIXME: not implemented yet
					GS_ASSERT(0);
				}
				break;

				default:
					GS_ASSERT(0);

				}
			}
			if (Events[i].events & EPOLLOUT) {
				switch (EPollCtx->mType)
				{

				case GS_SOCK_TYPE_NORMAL:
				{
					if (!!(r = gs_vserv_receive_writable(EPollCtx->mServCtl, EPollCtx)))
						GS_GOTO_CLEAN();
				}
				break;

				}
			}
		}
	}

noclean:

clean:
	free(UdpBuf);

	return r;
}

int gs_vserv_work_create(
	size_t ThreadNum,
	int *ioSockFdVec, size_t SockFdNum, /*owned/stealing*/
	struct GsVServCtl *ServCtl, /*partial/refonly*/
	struct GsVServQuitCtl *QuitCtl, /*notowned*/
	struct GsVServWork **oWork)
{
	int r = 0;

	struct GsVServWork *Work = NULL;

	int EvtFdExit = -1; /*notowned*/

	if (!!(r = gs_vserv_quit_ctl_reflect_evt_fd_exit(QuitCtl, &EvtFdExit)))
		GS_GOTO_CLEAN();

	Work = new GsVServWork();
	Work->mSockFdNum = 0;
	Work->mSockFdVec = NULL;
	Work->mEPollFdNum = 0;
	Work->mEPollFdVec = NULL;
	Work->mWakeAsyncNum = 0;
	Work->mWakeAsyncVec = NULL;
	Work->mWriteNum = 0;
	Work->mWriteVec = NULL;

	Work->mSockFdNum = ThreadNum;
	Work->mSockFdVec = new int[ThreadNum];
	for (size_t i = 0; i < ThreadNum; i++)
		Work->mSockFdVec[i] = GS_FDOWN(&ioSockFdVec[i]);
	Work->mEPollFdNum = ThreadNum;
	Work->mEPollFdVec = new int[ThreadNum];
	for (size_t i = 0; i < ThreadNum; i++)
		Work->mEPollFdVec[i] = -1;
	Work->mWakeAsyncNum = ThreadNum;
	Work->mWakeAsyncVec = new int[ThreadNum];
	for (size_t i = 0; i < ThreadNum; i++)
		Work->mWakeAsyncVec[i] = -1;

	if (! Work->mSockFdVec || ! Work->mEPollFdVec || ! Work->mWakeAsyncVec)
		GS_ERR_CLEAN(1);

	Work->mWriteNum = ThreadNum;
	Work->mWriteVec = new GsVServWrite *[ThreadNum];
	for (size_t i = 0; i < ThreadNum; i++)
		if (!!(r = gs_vserv_write_create(&Work->mWriteVec[i])))
			GS_GOTO_CLEAN();

	/* create epoll sets */

	for (size_t i = 0; i < ThreadNum; i++)
		if (-1 == (Work->mEPollFdVec[i] = epoll_create1(EPOLL_CLOEXEC)))
			GS_ERR_CLEAN(1);

	/* add socks, exit, wake events to epoll sets */

	for (size_t i = 0; i < ThreadNum; i++) {
		if (!!(r = gs_vserv_epollctx_add_for(Work->mEPollFdVec[i], -1, EvtFdExit, GS_SOCK_TYPE_EVENT, ServCtl)))
			GS_GOTO_CLEAN();
		GS_ASSERT(ThreadNum == SockFdNum);
		if (!!(r = gs_vserv_epollctx_add_for(Work->mEPollFdVec[i], i, Work->mSockFdVec[i], GS_SOCK_TYPE_NORMAL, ServCtl)))
			GS_GOTO_CLEAN();
		if (!!(r = gs_vserv_epollctx_add_for(Work->mEPollFdVec[i], -1, Work->mWakeAsyncVec[i], GS_SOCK_TYPE_WAKE, ServCtl)))
			GS_GOTO_CLEAN();
	}

	/* meant to interrupt a sleeping worker (inside ex epoll_wait) */

	for (size_t i = 0; i < ThreadNum; i++) {
		if (-1 == (Work->mWakeAsyncVec[i] = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
			GS_ERR_CLEAN(1);
	}

	if (oWork)
		*oWork = GS_ARGOWN(&Work);

clean:
	GS_DELETE_F(&Work, gs_vserv_work_destroy);

	return r;
}

int gs_vserv_work_destroy(struct GsVServWork *Work)
{
	if (Work) {
		for (size_t i = 0; i < Work->mSockFdNum; i++)
			gs_close_cond(Work->mSockFdVec + i);
		GS_DELETE_ARRAY(&Work->mSockFdVec, int);

		for (size_t i = 0; i < Work->mEPollFdNum; i++)
			gs_close_cond(Work->mEPollFdVec + i);
		GS_DELETE_ARRAY(&Work->mEPollFdVec, int);

		for (size_t i = 0; i < Work->mWriteNum; i++)
			GS_DELETE_F(&Work->mWriteVec[i], gs_vserv_write_destroy);
		GS_DELETE_ARRAY(&Work->mWriteVec, struct GsVServWrite *);

		for (size_t i = 0; i < Work->mWakeAsyncNum; i++)
			gs_close_cond(Work->mWakeAsyncVec + i);
		GS_DELETE_ARRAY(&Work->mWakeAsyncVec, int);

		GS_DELETE(&Work, struct GsVServWork);
	}
	return 0;
}
