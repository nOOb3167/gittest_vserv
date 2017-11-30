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
	   ::gs_vserv_write_create
	   ::gs_vserv_write_destroy
	   ::gs_vserv_write_elt_del_free
	   ::gs_vserv_write_elt_del_sp_free
	   ::gs_vserv_write_drain_to
       ::gs_vserv_respond_enqueue
*/
struct GsVServWrite
{
	bool mTryAtOnce;
	std::deque<GsVServWriteEntry> mQueue;
};

enum GsSockType
{
	GS_SOCK_TYPE_NORMAL = 2,
	GS_SOCK_TYPE_EVENT = 3,
	GS_SOCK_TYPE_WAKE = 4,
};

/** @sa
		::gs_vserv_epollctx_add_for
*/
struct GsEPollCtx
{
	enum GsSockType mType;
	struct GsVServCtl *mServCtl; /*notowned*/
	size_t mSockIdx;
	size_t mFd; /*notowned - informative*/
};

/** @sa
		::gs_vserv_respond_work_cb_respond
		::gs_vserv_respond_work_enqueue
		::gs_vserv_respond_work_enqueue_free
*/
struct GsVServRespondWork
{
	struct GsVServRespond base;
	struct GsVServWork *mWork;
	size_t mSockIdx;
};

/** @sa
		::gs_vserv_work_create
		::gs_vserv_work_destroy
*/
struct GsVServWork
{
	struct GsVServQuitCtl *mQuitCtl;
	int *mSockFdVec; size_t mSockFdNum;
	int *mEPollFdVec; size_t mEPollFdNum;
	struct GsVServWrite **mWriteVec; size_t mWriteNum;
	int *mWakeAsyncVec; size_t mWakeAsyncNum;
};

static int gs_addr_sockaddr_in(const struct GsAddr *Addr, struct sockaddr_in *SockAddr);

static int gs_vserv_write_create(
	struct GsVServWrite **oWrite);
static int gs_vserv_write_destroy(struct GsVServWrite *Write);
static int gs_vserv_write_drain_to(
	struct GsVServWrite *Write,
	int Fd,
	int *oHaveEAGAIN);

static int gs_vserv_epollctx_add_for(
	int EPollFd,
	size_t SockIdx,
	int Fd,
	enum GsSockType Type,
	struct GsVServCtl *ServCtl);
static int gs_vserv_respond_work_cb_respond(
	struct GsVServRespond *RespondBase,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);
static int gs_vserv_respond_work_enqueue(
	struct GsVServRespondWork *Respond,
	gs_data_deleter_sp_t DataDeleterSp,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);
static int gs_vserv_respond_work_enqueue_free(
	struct GsVServRespondWork *Respond,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);
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

int gs_addr_sockaddr_in(const struct GsAddr *Addr, struct sockaddr_in *SockAddr)
{
	if (Addr->mSinFamily != AF_INET)
		return 1;
	SockAddr->sin_family = AF_INET;
	SockAddr->sin_port = htons(Addr->mSinPort);
	SockAddr->sin_addr.s_addr = htonl(Addr->mSinAddr);
	return 0;
}

int gs_vserv_write_create(
	struct GsVServWrite **oWrite)
{
	int r = 0;

	struct GsVServWrite *Write = NULL;

	Write = new GsVServWrite();
	Write->mTryAtOnce = false;
	Write->mQueue;

	if (oWrite)
		*oWrite = GS_ARGOWN(&Write);

clean:
	GS_DELETE(&Write, struct GsVServWrite);

	return r;
}

int gs_vserv_write_destroy(struct GsVServWrite *Write)
{
	if (Write) {
		GS_DELETE(&Write, struct GsVServWrite);
	}
	return 0;
}

/**
	for epoll(2) EPOLLET edge-triggered mode specifically, writing until EAGAIN is important
	  as no further EPOLLOUT (writability) events will be received otherwise (socket remains writable)
*/
int gs_vserv_write_drain_to(
	struct GsVServWrite *Write,
	int Fd,
	int *oHaveEAGAIN)
{
	int r = 0;

	int HaveEAGAIN = 0;

	std::deque<GsVServWriteEntry>::iterator it;

	if (Write->mQueue.empty())
		GS_ERR_NO_CLEAN(0);

	for (it = Write->mQueue.begin(); it != Write->mQueue.end(); ++it) {
		ssize_t NSent = 0;
		struct sockaddr_in SockAddr = {};
		if (!!(r = gs_addr_sockaddr_in(&it->mAddr, &SockAddr)))
			GS_GOTO_CLEAN();
		while (-1 == (NSent = sendto(Fd, it->mElt.mData.get(), it->mElt.mLenData, MSG_NOSIGNAL, (struct sockaddr *) &SockAddr, sizeof SockAddr))) {
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

int gs_vserv_respond_work_cb_respond(
	struct GsVServRespond *RespondBase,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec)
{
	struct GsVServRespondWork *Respond = (struct GsVServRespondWork *) RespondBase;

	return gs_vserv_respond_work_enqueue_free(Respond, DataBuf, LenData, AddrVec, LenAddrVec);
}

/** WARNING: this function is affected by caller CPU
      the designed flow is: x-th receiver calls crank with 'Respond',
	  crank on x-th receiver calls ex gs_vserv_respond_enqueue.
	  maybe should just acquire mutexes */
int gs_vserv_respond_work_enqueue(
	struct GsVServRespondWork *Respond,
	gs_data_deleter_sp_t DataDeleterSp,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec)
{
	int r = 0;

	struct GsVServWork *Work = Respond->mWork;
	struct GsVServWrite *Write = Work->mWriteVec[Respond->mSockIdx];
	int Fd = Work->mSockFdVec[Respond->mSockIdx];

	size_t NumWrite = 0;

	/* feature may send some messages immediately */

	if (Write->mTryAtOnce) {
		for (size_t NumWrite = 0; NumWrite < LenAddrVec; NumWrite++) {
			ssize_t NSent = 0;
			struct sockaddr_in SockAddr = {};
			if (!!(r = gs_addr_sockaddr_in(AddrVec[NumWrite], &SockAddr)))
				GS_GOTO_CLEAN();
			while (-1 == (NSent = sendto(Fd, DataBuf, LenData, MSG_NOSIGNAL, (struct sockaddr *) &SockAddr, sizeof SockAddr))) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					goto donewriting;
				GS_ERR_CLEAN(1);
			}
		}
	}

donewriting:

	/* queue any not yet sent */

	if (NumWrite < LenAddrVec) {
		std::shared_ptr<uint8_t> Sp(GS_ARGOWN(&DataBuf), DataDeleterSp);
		for (size_t i = NumWrite; i < LenAddrVec; i++) {
			struct GsVServWriteEntry Entry;
			Entry.mAddr = *AddrVec[i];
			Entry.mElt.mLenData = LenData;
			Entry.mElt.mData = Sp;
			Write->mQueue.push_back(std::move(Entry));
		}
	}

clean:
	GS_DELETE_F(&DataBuf, DataDeleterSp);

	return r;
}

int gs_vserv_respond_work_enqueue_free(
	struct GsVServRespondWork *Respond,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec)
{
	return gs_vserv_respond_work_enqueue(Respond, gs_vserv_write_elt_del_sp_free, DataBuf, LenData, AddrVec, LenAddrVec);
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
		struct GsVServRespondWork Respond = {};
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
		Respond.base.CbRespond = gs_vserv_respond_work_cb_respond;
		Respond.mWork = Work;
		Respond.mSockIdx = EPollCtx->mSockIdx;
		if (!!(r = WorkCb->CbCrank(ServCtl, &Packet, &Addr, &Respond.base)))
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

	int EvtFdExit = -1;

	GS_ASSERT(! gs_vserv_quit_ctl_reflect_evt_fd_exit(Work->mQuitCtl, &EvtFdExit));
	GS_ASSERT(EvtFdExit == EPollCtx->mFd);

	if (!!(r = gs_vserv_quit_ctl_acknowledge(Work->mQuitCtl)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_receive_writable(
	struct GsVServWork *Work,
	struct GsEPollCtx *EPollCtx)
{
	int r = 0;

	struct GsVServWrite *Write = Work->mWriteVec[EPollCtx->mSockIdx];
	int Fd = Work->mSockFdVec[EPollCtx->mSockIdx];

	GS_ASSERT(Fd == EPollCtx->mFd);

	if (!!(r = gs_vserv_write_drain_to(Write, Fd, NULL)))
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
					if (!!(r = gs_vserv_receive_writable(Work, EPollCtx)))
						GS_GOTO_CLEAN();
				}
				break;

				case GS_SOCK_TYPE_EVENT:
				{
					if (!!(r = gs_vserv_receive_evt_event(Work, EPollCtx)))
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
					if (!!(r = gs_vserv_receive_writable(Work, EPollCtx)))
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

int gs_vserv_write_elt_del_free(uint8_t **DataBuf)
{
	if (*DataBuf) {
		free(*DataBuf);
		*DataBuf = NULL;
	}
	return 0;
}

int gs_vserv_write_elt_del_sp_free(uint8_t *DataBuf)
{
	free(DataBuf);
	return 0;
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
	Work->mQuitCtl = GS_ARGOWN(&QuitCtl);
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

	/* meant to interrupt a sleeping worker (inside ex epoll_wait) */

	for (size_t i = 0; i < ThreadNum; i++) {
		if (-1 == (Work->mWakeAsyncVec[i] = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
			GS_ERR_CLEAN(1);
	}

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
