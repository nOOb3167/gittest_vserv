#include <cassert>
#include <cstdlib>

#include <vector>

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/vserv_net.h>

/* intended to be forward-declared in header (API use pointer only) */
struct GsVServCtl
{
	size_t mNumThread;
	pthread_t *mThreadVec; size_t mThreadNum;
	int *mSockFdVec; size_t mSockFdNum;
	int *mEPollFdVec; size_t mEPollFdNum;
	int mEvtFdExitReq;
	int mEvtFdExit;
};

struct GsEPollCtx
{
	enum GsSockType mType;
	struct GsVServConCtx *mCtx; /*notowned*/
};

static int gs_vserv_epollctx_add_for(
	int EPollFd,
	int Fd,
	enum GsSockType Type,
	gs_cb_vserv_con_ctx_create_t CbCtxCreate,
	struct GsVServConExt *Ext);

int gs_vserv_epollctx_add_for(
	int EPollFd,
	int Fd, /*owned*/
	enum GsSockType Type,
	gs_cb_vserv_con_ctx_create_t CbCtxCreate,
	struct GsVServConExt *Ext)
{
	int r = 0;

	struct epoll_event Evt = {};

	struct GsEPollCtx **EvtDataPtr = (struct GsEPollCtx **) &Evt.data.ptr;

	Evt.events = EPOLLIN | EPOLLET;    /* NOTE: no EPOLLONESHOT this time */
	/* remainder effectively setting up Evt.data.ptr */
	(*EvtDataPtr) = new GsEPollCtx();
	(*EvtDataPtr)->mType = Type;
	if (!!(r = CbCtxCreate(&(*EvtDataPtr)->mCtx, Type, Ext)))
		GS_GOTO_CLEAN();
	(*EvtDataPtr)->mCtx->mFd = GS_FDOWN(&Fd);
	(*EvtDataPtr)->mCtx->mExt = Ext;

	if (-1 == epoll_ctl(EPollFd, EPOLL_CTL_ADD, (*EvtDataPtr)->mCtx->mFd, &Evt))
		GS_ERR_CLEAN(1);
	(*EvtDataPtr) = NULL;

clean:
	if ((*EvtDataPtr) && (*EvtDataPtr)->mCtx)
		gs_close_cond(&(*EvtDataPtr)->mCtx->mFd);
	if ((*EvtDataPtr))
		GS_DELETE_VF(&(*EvtDataPtr)->mCtx, CbCtxDestroy);
	GS_DELETE(&(*EvtDataPtr), struct GsEPollCtx);
	gs_close_cond(&Fd);

	return r;
}

int gs_vserv_ctl_create_part(
	size_t ThreadNum,
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
		ServCtl->mSockFdVec[i] = -1;
	ServCtl->mEPollFdNum = ThreadNum;
	ServCtl->mEPollFdVec = new int[ThreadNum];
	for (size_t i = 0; i < ThreadNum; i++)
		ServCtl->mEPollFdVec[i] = -1;
	if (! ServCtl->mThreadVec || ! ServCtl->mSockFdVec || ! ServCtl->mEPollFdVec)
		GS_ERR_CLEAN(1);

	// thread requesting exit 0 -> 1 -> 0
	if (-1 == (ServCtl->mEvtFdExitReq = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);
	// controller (servctl) ordering exit 0 -> NumThread -> -=1 -> .. -> 0
	if (-1 == (ServCtl->mEvtFdExit = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);

	/* create epoll sets */

	for (size_t i = 0; i < ThreadNum; i++)
		if (-1 == (ServCtl->mEPollFdVec[i] = epoll_create1(EPOLL_CLOEXEC)))
			GS_ERR_CLEAN(1);

	if (oServCtl)
		*oServCtl = GS_ARGOWN(&ServCtl);

clean:
	if (ServCtl)
		for (size_t i = 0; i < ThreadNum; i++)
			gs_close_cond(ServCtl->mEPollFdVec + i);
	if (ServCtl)
		gs_close_cond(&ServCtl->mEvtFdExit);
	if (ServCtl)
		gs_close_cond(&ServCtl->mEvtFdExitReq);
	if (ServCtl)
		GS_DELETE_ARRAY(&ServCtl->mThreadVec, pthread_t);
	if (ServCtl)
		GS_DELETE_ARRAY(&ServCtl->mSockFdVec, int);
	if (ServCtl)
		GS_DELETE_ARRAY(&ServCtl->mEPollFdVec, int);
	GS_DELETE(&ServCtl, struct GsVServCtl);

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
	int *ServFdVec /*owned*/, size_t ServFdNum /*owned*/,
	gs_cb_ctx_create_t CbCtxCreate,
	struct GsVServConExt *Ext,
	struct GsVServCtl **oServCtl)
{
	int r = 0;

	struct GsVServCtl *ServCtl = NULL;

	size_t ThreadNum = ServFdNum;
	size_t ThreadsInitedCnt = 0;
	bool AttrInited = false;
	pthread_attr_t Attr = {};

	if (!!(r = gs_vserv_ctl_create_part(ThreadNum, &ServCtl)))
		GS_GOTO_CLEAN();

	/* add socks and exit events to epoll sets */

	for (size_t i = 0; i < ThreadNum; i++) {
		int DupedFdExit = dup(ServCtl->mEvtFdExit);
		while (-1 == dup3(ServCtl->mEvtFdExit, DupedFdExit, O_CLOEXEC)) {
			if (errno == EINTR || errno == EBUSY)
				continue;
			GS_ERR_CLEAN_J(initfdexit, 1);
		}
		if (!!(r = gs_vserv_epollctx_add_for(ServCtl->mEPollFdVec[i], GS_FDOWN(&DupedFdExit), GS_SOCK_TYPE_EVENT, CbCtxCreate, Ext)))
			GS_GOTO_CLEAN();
		if (!!(r = gs_vserv_epollctx_add_for(ServCtl->mEPollFdVec[i], GS_FDOWN(&xxxxx), GS_SOCK_TYPE_NORMAL, CbCtxCreate, Ext)))
			GS_GOTO_CLEAN();
	clean_initfdexit:
		gs_close_cond(&DupedFdExit);
		if (!!r)
			GS_GOTO_CLEAN();
	}

	/* create threads */

	if (!!(r = pthread_attr_init(&Attr)))
		GS_GOTO_CLEAN_J(initthr);
	AttrInited = true;

	for (size_t i = 0; i < NumThread; i++) {
		if (!!(r = pthread_create(ServCtx->mThreadVec + i, &Attr, receiver_func, NULL)))
			GS_GOTO_CLEAN();
		ThreadsInitedCnt++;
	}

	if (oServCtl)
		*oServCtl = GS_ARGOWN(&ServCtl);

clean:
	if (AttrInited)
		if (!!(r = pthread_attr_destroy(&Attr)))
			GS_ASSERT(0);
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
	struct GsVServCtl *ServCtl = NULL;

	Ext = new GsVServConExt();
	Ext->mCommonVars = *CommonVars;

	ServFd.resize(1, -1);

	if (!!(r = gs_vserv_sockets_create(std::to_string(CommonVars->ServPort).c_str(), ServFd.data(), ServFd.size())))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_start_2(ServFd.data(), ServFd.size(), cbctxcreate, Ext, &ServCtl)))
		GS_GOTO_CLEAN();
	for (size_t i = 0; i < ServFd.size(); i++) /* transfer ownership */
		gs_close_cond(&ServFd[i]);

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
