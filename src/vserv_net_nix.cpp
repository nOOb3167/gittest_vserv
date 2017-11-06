#include <cassert>
#include <cstdlib>

#include <vector>

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>

/* intended to be forward-declared in header (API use pointer only) */
struct GsVServCtl
{
	size_t mNumThread;
	std::vector<pthread_t> mThread;
	int mEvtFdExitReq;
	int mEvtFdExit;
	int mEPollFd;
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

	struct GsEPollCtx *EPollCtx = NULL;
	struct GsVServConCtx *Ctx = NULL;
	struct epoll_event Evt = {};

	if (!!(r = CbCtxCreate(&Ctx, Type, Ext)))
		GS_GOTO_CLEAN();

	Ctx->mFd = GS_FDOWN(&Fd);
	Ctx->mExt = Ext;
	EPollCtx = new GsEPollCtx();
	EPollCtx->mType = Type;
	EPollCtx->mCtx = GS_ARGOWN(&Ctx);
	Evt.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
	Evt.data.ptr = GS_ARGOWN(&EPollCtx);

	if (-1 == epoll_ctl(EPollFd, EPOLL_CTL_ADD, ((struct GsEPollCtx *)Evt.data.ptr)->mCtx->mFd, &Evt))
		GS_ERR_CLEAN(1);
	Evt.data.ptr = NULL;

clean:
	GS_DELETE(&Evt.data.ptr, struct GsEPollCtx);
	GS_DELETE_VF(&Ctx, CbCtxDestroy);
	GS_DELETE(&EPollCtx, struct GsEPollCtx);

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

		close(TmpFd);
		TmpFd = -1;

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
			if (ioSockFdVec[i] != -1) {
				close(ioSockFdVec[i]);
				ioSockFdVec[i] = -1;
			}
	}

	if (TmpFd != -1)
		close(TmpFd);
	if (Res)
		freeaddrinfo(Res);

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

int gs_vserv_start_2(
	int *ServFdVec /*owned*/, size_t ServFdNum /*owned*/,
	gs_cb_ctx_create_t CbCtxCreate,
	struct GsVServConExt *Ext,
	struct GsVServCtl **oServCtl)
{
	int r = 0;

	struct GsVServCtl *ServCtl = NULL;

	std::vector<pthread_t> Thread;

	size_t NumThread = ServFdNum;

	// thread requesting exit 0 -> 1 -> 0
	int EvtFdExitReq = -1;
	// controller (this) ordering exit 0 -> NumThread -> -=1 -> .. -> 0
	int EvtFdExit = -1;
	int EPollFd = -1;

	if (-1 == (EvtFdExitReq = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);

	if (-1 == (EvtFdExit = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);

	if (-1 == (EPollFd = epoll_create1(EPOLL_CLOEXEC)))
		GS_ERR_CLEAN(1);

	if (!!(r = CbCtxCreate(&ExitCtx, XS_SOCK_TYPE_EVENT, Ext)))
		GS_GOTO_CLEAN();

	ExitCtx->mFd = EvtFdExit;
	ExitCtx->mExt = Ext;
	ExitEPollCtx = new XsEPollCtx();
	ExitEPollCtx->mType = XS_SOCK_TYPE_EVENT;
	ExitEPollCtx->mCtx = ExitCtx;
	ExitEvt.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
	ExitEvt.data.ptr = ExitEPollCtx;

	if (-1 == epoll_ctl(EPollFd, EPOLL_CTL_ADD, ExitCtx->mFd, &ExitEvt))
		GS_ERR_CLEAN(1);

	if (!!(r = CbCtxCreate(&SockCtx, XS_SOCK_TYPE_LISTEN, Ext)))
		GS_GOTO_CLEAN();

	SockCtx->mFd = ListenFd;
	SockCtx->mExt = Ext;
	SockEPollCtx = new XsEPollCtx();
	SockEPollCtx->mType = XS_SOCK_TYPE_LISTEN;
	SockEPollCtx->mCtx = SockCtx;
	SockEvt.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
	SockEvt.data.ptr = SockEPollCtx;

	if (-1 == epoll_ctl(EPollFd, EPOLL_CTL_ADD, SockCtx->mFd, &SockEvt))
		GS_ERR_CLEAN(1);

	for (size_t i = 0; i < NumThread; i++)
		ThreadRecv.push_back(std::make_shared<std::thread>(receiver_func, i, EPollFd, EvtFdExitReq));

	ServCtl = new XsServCtl();
	ServCtl->mNumThread = NumThread;
	ServCtl->mThread = ThreadRecv;
	ServCtl->mEvtFdExitReq = EvtFdExitReq;
	ServCtl->mEvtFdExit = EvtFdExit;
	ServCtl->mEPollFd = EPollFd;

	if (oServCtl)
		*oServCtl = ServCtl;

clean:
	if (!!r) {
		GS_DELETE_F(&ServCtl, xs_serv_ctl_destroy);
		GS_DELETE_VF(&SockCtx, CbCtxDestroy);
		GS_DELETE(&SockEPollCtx, struct XsEPollCtx);
		GS_DELETE_VF(&ExitCtx, CbCtxDestroy);
		GS_DELETE(&ExitEPollCtx, struct XsEPollCtx);
	}

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
	/* transfer ownership */
	for (size_t i = 0; i < ServFd.size(); i++)
		if (ServFd[i] != -1)
			close(ServFd[i]);

	if (!!(r = gs_vserv_ctl_quit_wait(ServCtl)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE(&Ext, struct GsVServConExt);
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);
	for (size_t i = 0; i < ServFd.size(); i++)
		if (ServFd[i] != -1)
			close(ServFd[i]);

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
