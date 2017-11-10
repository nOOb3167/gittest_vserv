#include <cassert>
#include <cstdlib>

#include <functional>  // std::hash
#include <utility>
#include <memory>
#include <vector>
#include <deque>
#include <map>

#include <alloca.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/log.h>
#include <gittest/vserv_net.h>

#define GS_VSERV_EPOLL_NUMEVENTS 8
#define GS_VSERV_SEND_NUMIOVEC 3
#define GS_VSERV_UDP_SIZE_MAX 65535

struct GsAddr;
struct GsVServWriteEntry;
// FIXME: unordered_map may be possible https://stackoverflow.com/questions/16781886/can-we-store-unordered-maptiterator/16782536#16782536
typedef std::map<struct GsAddr, struct GsVServWriteEntry> gs_inflight_map_t;

/* intended to be forward-declared in header (API use pointer only) */
struct GsVServCtl
{
	size_t mNumThread;
	pthread_t *mThreadVec; size_t mThreadNum;
	int *mSockFdVec; size_t mSockFdNum;
	int *mEPollFdVec; size_t mEPollFdNum;
	struct GsVServWrite **mWriteVec; size_t mWriteNum;
	int *mWakeAsyncVec; size_t mWakeAsyncNum;
	int mEvtFdExitReq;
	int mEvtFdExit;
	struct GsVServCtlCb *mCb;
};

struct GsVServRespond
{
	struct GsVServCtl *mServCtl;
	size_t mSockIdx;
};

struct GsVServWriteElt
{
	std::shared_ptr<char> mData; size_t mLenData;
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

struct GsAddr
{
	struct sockaddr_in mAddr;
};

struct GsEPollCtx
{
	enum GsSockType mType;
	struct GsVServCtl *mServCtl; /*notowned*/
	size_t mSockIdx;
	size_t mFd; /*notowned - informative*/
};

struct GsVServConExt
{
	struct GsAuxConfigCommonVars mCommonVars; /*notowned*/
};

struct GsVServCtlCb1
{
	struct GsVServCtlCb base;
	struct GsVServConExt *Ext; /*owned*/
};

static int gs_eventfd_read(int EvtFd);
static int gs_eventfd_write(int EvtFd, int Value);
static int gs_vserv_receive_evt_normal(
	struct GsVServCtl *ServCtl,
	struct GsEPollCtx *EPollCtx,
	char *UdpBuf, size_t LenUdp);
static int gs_vserv_receive_evt_event(
	struct GsVServCtl *ServCtl,
	struct GsEPollCtx *EPollCtx);
static int gs_vserv_receive_writable(
	struct GsVServCtl *ServCtl,
	struct GsEPollCtx *EPollCtx);
static int gs_vserv_receive_func(
	struct GsVServCtl *ServCtl);
static void * gs_vserv_receive_func_pthread(
	void *arg);
static int gs_vserv_epollctx_add_for(
	int EPollFd,
	size_t SockIdx,
	int Fd,
	enum GsSockType Type,
	struct GsVServCtl *ServCtl);

size_t gs_addr_hash_t::operator()(const struct GsAddr &k) const {
	// FIXME: https://stackoverflow.com/questions/35985960/c-why-is-boosthash-combine-the-best-way-to-combine-hash-values
	return (    (std::hash<unsigned long long>()(k.mAddr.sin_family) << 1)
		     ^ ((std::hash<unsigned long long>()(k.mAddr.sin_port) << 1) >> 1)
			 ^ ((std::hash<unsigned long long>()(k.mAddr.sin_addr.s_addr) << 2) >> 2));
}

bool gs_addr_equal_t::operator()(const GsAddr &a, const GsAddr &b) const {
	return a.mAddr.sin_family == b.mAddr.sin_family
		&& a.mAddr.sin_port == b.mAddr.sin_port
		&& a.mAddr.sin_addr.s_addr == b.mAddr.sin_addr.s_addr;
}

int gs_eventfd_read(int EvtFd)
{
	int r = 0;
	char    Buf[8] = {};
	ssize_t NRead  = 0;

	while (-1 == (NRead = read(EvtFd, Buf, 8))) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			continue;
		GS_ERR_CLEAN(1);
	}
	GS_ASSERT(NRead == 8);

clean:

	return r;
}

int gs_eventfd_write(int EvtFd, int Value)
{
	int r = 0;

	uint64_t Val    = (uint64_t)Value;
	char     Buf[8] = {};
	ssize_t  NWrite = 0;

	GS_ASSERT(sizeof Val == sizeof Buf);

	memcpy(Buf, &Val, 8);

	while (-1 == (NWrite = write(EvtFd, Buf, 8))) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			continue;
		GS_ERR_CLEAN(1);
	}
	GS_ASSERT(NWrite == 8);

clean:

  return 0;
}

int gs_vserv_receive_evt_normal(
	struct GsVServCtl *ServCtl,
	struct GsEPollCtx *EPollCtx,
	char *UdpBuf, size_t LenUdp)
{
	int r = 0;

	const int Fd = ServCtl->mSockFdVec[GS_MAX(EPollCtx->mSockIdx, ServCtl->mSockFdNum)];
	bool DoneReading = 0;

	GS_ASSERT(Fd == EPollCtx->mFd);

	/* remember to read until EAGAIN for edge-triggered epoll (EPOLLET) */
	while (! DoneReading) {
		ssize_t NRecv = 0;
		struct sockaddr_in Addr = {};
		socklen_t AddrSize = sizeof Addr;
		struct GsPacket Packet = {};
		struct GsAddr Address = {};
		while (-1 == (NRecv = recvfrom(Fd, UdpBuf, LenUdp, MSG_TRUNC, (struct sockaddr *)&Addr, &AddrSize))) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				DoneReading = 1;
				break;
			}
			GS_ERR_CLEAN(1);
		}
		/* detect datagram truncation (see MSG_TRUNC) */
		if (NRecv > LenUdp)
			GS_ERR_CLEAN(1);
		/* detect somehow receiving from wrong address family? */
		if (AddrSize != sizeof Addr || Addr.sin_family != AF_INET)
			GS_ERR_CLEAN(1);
		/* dispatch datagram */
		Packet.data = (uint8_t *)UdpBuf;
		Packet.dataLength = LenUdp;
		Address.mAddr = Addr;
		if (!!(r = ServCtl->mCb->CbCrank(ServCtl->mCb, &Packet, &Address)))
			GS_GOTO_CLEAN();
	}

clean:

	return r;
}

int gs_vserv_receive_evt_event(
	struct GsVServCtl *ServCtl,
	struct GsEPollCtx *EPollCtx)
{
	int r = 0;

	const int Fd = ServCtl->mSockFdVec[GS_MAX(EPollCtx->mSockIdx, ServCtl->mSockFdNum)];

	GS_ASSERT(Fd == EPollCtx->mFd);

	if (!!(r = gs_eventfd_read(Fd)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_receive_writable(
	struct GsVServCtl *ServCtl,
	struct GsEPollCtx *EPollCtx)
{
	int r = 0;

	const int Fd = ServCtl->mSockFdVec[GS_MAX(EPollCtx->mSockIdx, ServCtl->mSockFdNum)];
	struct GsVServWrite *Write = ServCtl->mWriteVec[EPollCtx->mSockIdx];

	GS_ASSERT(Fd == EPollCtx->mFd);

	if (!!(r = gs_vserv_write_drain_to(ServCtl, EPollCtx->mSockIdx, NULL)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_receive_func(
	struct GsVServCtl *ServCtl)
{
	int r = 0;

	char *UdpBuf = NULL;
	size_t LenUdp = 0;
	
	if (!(UdpBuf = (char *)malloc(GS_VSERV_UDP_SIZE_MAX)))
		GS_ERR_CLEAN(1);
	LenUdp = GS_VSERV_UDP_SIZE_MAX;

	while (true) {
		struct epoll_event Events[GS_VSERV_EPOLL_NUMEVENTS] = {};
		int NReady = 0;

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
					if (!!(r = gs_vserv_receive_evt_normal(EPollCtx->mServCtl, EPollCtx, UdpBuf, LenUdp)))
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
				if (!!(r = gs_vserv_receive_writable(EPollCtx->mServCtl, EPollCtx)))
					GS_GOTO_CLEAN();
			}
		}
	}

noclean:

clean:
	free(UdpBuf);

	return r;
}

void * gs_vserv_receive_func_pthread(
	void *arg)
{
	int r = 0;

	struct GsVServCtl *ServCtl = (struct GsVServCtl *) arg;

	log_guard_t Log(GS_LOG_GET("serv"));

	if (!!(r = gs_vserv_receive_func(ServCtl)))
		GS_GOTO_CLEAN();

clean:
	if (!!r)
		GS_ASSERT(0);

	return NULL;
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

	Evt.events = EPOLLIN | EPOLLOUT | EPOLLET;    /* NOTE: no EPOLLONESHOT this time */
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

int gs_vserv_ctl_create_part(
	size_t ThreadNum,
	int *ioSockFdVec, size_t SockFdNum, /*owned/stealing*/
	struct GsVServCtlCb *Cb,
	struct GsVServCtl **oServCtl)
{
	int r = 0;

	struct GsVServCtl *ServCtl = new GsVServCtl();

	*ServCtl = {};
	ServCtl->mThreadNum = ThreadNum;
	ServCtl->mThreadVec = new pthread_t[ThreadNum];
	ServCtl->mSockFdNum = ThreadNum;
	ServCtl->mSockFdVec = new int[ThreadNum];
	for (size_t i = 0; i < ThreadNum; i++)
		ServCtl->mSockFdVec[i] = GS_FDOWN(&ioSockFdVec[i]);
	ServCtl->mEPollFdNum = ThreadNum;
	ServCtl->mEPollFdVec = new int[ThreadNum];
	for (size_t i = 0; i < ThreadNum; i++)
		ServCtl->mEPollFdVec[i] = -1;
	ServCtl->mWakeAsyncNum = ThreadNum;
	ServCtl->mWakeAsyncVec = new int[ThreadNum];
	for (size_t i = 0; i < ThreadNum; i++)
		ServCtl->mWakeAsyncVec[i] = -1;
	if (! ServCtl->mThreadVec || ! ServCtl->mSockFdVec || ! ServCtl->mEPollFdVec || ! ServCtl->mWakeAsyncVec)
		GS_ERR_CLEAN(1);

	// thread requesting exit 0 -> 1 -> 0
	if (-1 == (ServCtl->mEvtFdExitReq = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);
	// controller (servctl) ordering exit 0 -> NumThread -> -=1 -> .. -> 0
	if (-1 == (ServCtl->mEvtFdExit = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);

	/* meant to interrupt a sleeping worker (inside ex epoll_wait) */

	for (size_t i = 0; i < ThreadNum; i++) {
		if (-1 == (ServCtl->mWakeAsyncVec[i] = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
			GS_ERR_CLEAN(1);
	}

	/* create epoll sets */

	for (size_t i = 0; i < ThreadNum; i++)
		if (-1 == (ServCtl->mEPollFdVec[i] = epoll_create1(EPOLL_CLOEXEC)))
			GS_ERR_CLEAN(1);

	/* add socks, exit, wake events to epoll sets */

	for (size_t i = 0; i < ThreadNum; i++) {
		if (!!(r = gs_vserv_epollctx_add_for(ServCtl->mEPollFdVec[i], i, ServCtl->mEvtFdExit, GS_SOCK_TYPE_EVENT, ServCtl)))
			GS_GOTO_CLEAN();
		GS_ASSERT(ThreadNum == SockFdNum);
		if (!!(r = gs_vserv_epollctx_add_for(ServCtl->mEPollFdVec[i], i, ServCtl->mSockFdVec[i], GS_SOCK_TYPE_NORMAL, ServCtl)))
			GS_GOTO_CLEAN();
		if (!!(r = gs_vserv_epollctx_add_for(ServCtl->mEPollFdVec[i], i, ServCtl->mWakeAsyncVec[i], GS_SOCK_TYPE_WAKE, ServCtl)))
			GS_GOTO_CLEAN();
	}

	/*  */

	ServCtl->mCb = Cb;

	if (oServCtl)
		*oServCtl = GS_ARGOWN(&ServCtl);

clean:
	if (ServCtl) {
		gs_close_cond(&ServCtl->mEvtFdExit);
		gs_close_cond(&ServCtl->mEvtFdExitReq);

		GS_DELETE_ARRAY(&ServCtl->mThreadVec, pthread_t);

		for (size_t i = 0; i < ServCtl->mSockFdNum; i++)
			gs_close_cond(ServCtl->mSockFdVec + i);
		GS_DELETE_ARRAY(&ServCtl->mSockFdVec, int);

		for (size_t i = 0; i < ServCtl->mEPollFdNum; i++)
			gs_close_cond(ServCtl->mEPollFdVec + i);
		GS_DELETE_ARRAY(&ServCtl->mEPollFdVec, int);

		for (size_t i = 0; i < ServCtl->mWakeAsyncNum; i++)
			gs_close_cond(ServCtl->mWakeAsyncVec + i);
		GS_DELETE_ARRAY(&ServCtl->mWakeAsyncVec, int);

		GS_DELETE(&ServCtl, struct GsVServCtl);

		for (size_t i = 0; i < SockFdNum; i++)
			gs_close_cond(&ioSockFdVec[i]);
	}

	return r;
}

int gs_vserv_ctl_create_finish(
	struct GsVServCtl *ServCtl)
{
	int r = 0;

	size_t ThreadsInitedCnt = 0;
	bool AttrInited = false;
	pthread_attr_t Attr = {};

	/* create threads */

	if (!!(r = pthread_attr_init(&Attr)))
		GS_GOTO_CLEAN();
	AttrInited = true;

	for (size_t i = 0; i < ServCtl->mNumThread; i++) {
		if (!!(r = pthread_create(ServCtx->mThreadVec + i, &Attr, receiver_func, ServCtl)))
			GS_GOTO_CLEAN();
		ThreadsInitedCnt++;
	}

clean:
	if (AttrInited)
		if (!!(r = pthread_attr_destroy(&Attr)))
			GS_ASSERT(0);

	return r;
}

int gs_vserv_sockets_create(
	const char *Port,
	int *ioSockFdVec, size_t SockFdNum)
{
	int r = 0;

	struct addrinfo Hints = {};
	struct addrinfo *Res = NULL, *Rp = NULL;
	int TmpFd = -1;

	/* AI_PASSIVE causes INADDR_ANY equivalent */
	Hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	// FIXME: RIP ipv6, see AF_UNSPEC
	Hints.ai_family = AF_INET;
	Hints.ai_socktype = SOCK_DGRAM;
	Hints.ai_protocol = 0;

	for (size_t i = 0; i < SockFdNum; i++)
		ioSockFdVec[i] = -1;

	if (!!(r = getaddrinfo(NULL, Port, &Hints, &Res)))
		GS_GOTO_CLEAN();

	for (Rp = Res; Rp != NULL; Rp = Rp->ai_next) {
		bool RpFound = false;

		if (-1 == (TmpFd = socket(Rp->ai_family, Rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, Rp->ai_protocol)))
			GS_ERR_CLEAN(1);
		if (0 == bind(TmpFd, Rp->ai_addr, Rp->ai_addrlen))
			RpFound = true;

		gs_close_cond(&TmpFd);

		if (RpFound)
			break;
	}

	if (Rp == NULL)
		GS_ERR_CLEAN(1);

	for (size_t i = 0; i < SockFdNum; i++) {
		int OptReuseport = 1;
		if (-1 == (ioSockFdVec[i] = socket(Rp->ai_family, Rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, Rp->ai_protocol)))
			GS_ERR_CLEAN(1);
		if (-1 == setsockopt(ioSockFdVec[i], SOL_SOCKET, SO_REUSEPORT, &OptReuseport, sizeof OptReuseport))
			GS_ERR_CLEAN(1);
		if (-1 == bind(TmpFd, Rp->ai_addr, Rp->ai_addrlen))
			GS_ERR_CLEAN(1);
	}

clean:
	if (!!r) {
		for (size_t i = 0; i < SockFdNum; i++)
			gs_close_cond(ioSockFdVec + i);
	}

	gs_close_cond(&TmpFd);
	if (Res)
		freeaddrinfo(Res);

	return r;
}

int gs_vserv_start_2(
	int *ServFdVec, size_t ServFdNum, /*owned/stealing*/
	struct GsVServCtlCb *Cb,
	struct GsVServCtl **oServCtl)
{
	int r = 0;

	struct GsVServCtl *ServCtl = NULL;

	size_t ThreadNum = ServFdNum;

	if (!!(r = gs_vserv_ctl_create_part(ThreadNum, ServFdVec, ServFdNum, Cb, &ServCtl)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_ctl_create_finish(ServCtl)))
		GS_GOTO_CLEAN();

	if (oServCtl)
		*oServCtl = GS_ARGOWN(&ServCtl);

clean:
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);

	for (size_t i = 0; i < ServFdNum; i++)
		gs_close_cond(ServFdVec + i);

	return r;
}

int gs_vserv_start(struct GsAuxConfigCommonVars *CommonVars)
{
	int r = 0;

	std::vector<int> ServFd;
	struct GsVServConExt *Ext = NULL;
	struct GsVServCtlCb1 *Cb1 = NULL;
	struct GsVServCtl *ServCtl = NULL;

	Ext = new GsVServConExt();
	Ext->mCommonVars = *CommonVars;
	Cb1 = new GsVServCtlCb1();
	Cb1->base.CbCrank = NULL;
	Cb1->Ext = GS_ARGOWN(&Ext);

	ServFd.resize(1, -1);

	if (!!(r = gs_vserv_sockets_create(std::to_string(CommonVars->ServPort).c_str(), ServFd.data(), ServFd.size())))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_start_2(ServFd.data(), ServFd.size(), &Cb1->base, &ServCtl)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_ctl_quit_wait(ServCtl)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE(&Ext, struct GsVServConExt);
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);
	for (size_t i = 0; i < ServFd.size(); i++)
		gs_close_cond(&ServFd[i]);

	return r;
}

int stuff(int argc, char **argv)
{
	int r = 0;

	int ListenFd = -1;

	if (!!(r = gs_vserv_net_sockets_create("3757", &ListenFd, 1)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int main(int argc, char **argv)
{
	int r = 0;

	if (!!(r = stuff(argc, argv)))
		goto clean;

clean:
	if (!!r)
		assert(0);

	return EXIT_SUCCESS;
}
