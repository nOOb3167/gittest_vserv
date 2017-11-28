#include <pthread.h>

// FIXME: some day figure which of these are ACTUALLY needed
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/vserv_helpers_plat.h>

struct GsVServPthreadCtx
{
	struct GsVServCtl *mServCtl;
	size_t mSockIdx;
};

struct GsVServThreads
{
	size_t mNumThread;
	pthread_t *mThreadVec; size_t mThreadNum;
	pthread_t *mThreadMgmt; size_t mThreadMgmtNum;
};

struct GsVServLock
{
	pthread_mutex_t mMutex;
	bool mHaveLock;
};

struct GsVServQuitCtl
{
	int mEvtFdExitReq;
	int mEvtFdExit;
};

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
		if (-1 == bind(ioSockFdVec[i], Rp->ai_addr, Rp->ai_addrlen))
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

int gs_vserv_threads_create(
	size_t NumThread,
	struct GsVServThreads **oThreads)
{
	int r = 0;

	struct GsVServThreads *Threads = NULL;

	pthread_t *ThreadVec = new pthread_t[NumThread];
	pthread_t *ThreadMgmt = new pthread_t[1];

	Threads = new GsVServThreads();
	Threads->mNumThread = NumThread;
	Threads->mThreadNum = NumThread;
	Threads->mThreadVec = GS_ARGOWN(&ThreadVec);
	Threads->mThreadMgmtNum = 1;
	Threads->mThreadMgmt = GS_ARGOWN(&ThreadMgmt);

	if (! ThreadVec || ! ThreadMgmt)
		GS_ERR_CLEAN(1);

	if (oThreads)
		*oThreads = GS_ARGOWN(&Threads);

clean:
	GS_DELETE_ARRAY(&ThreadVec, pthread_t);
	GS_DELETE_ARRAY(&ThreadMgmt, pthread_t);
	GS_DELETE_F(&Threads, gs_vserv_threads_destroy);

	return r;
}

int gs_vserv_threads_destroy(struct GsVServThreads *Threads)
{
	if (Threads) {
		/* does nothing about any initialized pthread_t inside the vectors though */
		GS_DELETE_ARRAY(&Threads->mThreadVec, pthread_t);
		GS_DELETE_ARRAY(&Threads->mThreadMgmt, pthread_t);
		GS_DELETE(&Threads, struct GsVServThreads);
	}
	return 0;
}

int gs_vserv_threads_init_and_start(
	struct GsVServThreads *Threads,
	struct GsVServCtl *ServCtl,
	void *(*WorkFunc)(void *),
	void *(*MgmtFunc)(void *))
{
	int r = 0;

	pthread_attr_t Attr = {};
	bool AttrInited = false;

	if (!!(r = pthread_attr_init(&Attr)))
		GS_GOTO_CLEAN();
	AttrInited = true;

	for (size_t i = 0; i < Threads->mThreadNum; i++) {
		struct GsVServPthreadCtx *Ctx = new GsVServPthreadCtx();
		Ctx->mServCtl = ServCtl;
		Ctx->mSockIdx = i;
		if (!!(r = pthread_create(Threads->mThreadVec + i, &Attr, WorkFunc, Ctx)))
			GS_GOTO_CLEAN();
		Ctx = NULL;
	}

	{
		GS_ASSERT(Threads->mThreadMgmtNum == 1);
		struct GsVServPthreadCtx *Ctx = new GsVServPthreadCtx();
		Ctx->mServCtl = ServCtl;
		Ctx->mSockIdx = -1;
		if (!!(r = pthread_create(Threads->mThreadMgmt + 0, &Attr, MgmtFunc, Ctx)))
			GS_GOTO_CLEAN();
		Ctx = NULL;
	}

clean:
	if (AttrInited)
		if (!!(r = pthread_attr_destroy(&Attr)))
			GS_ASSERT(0);

	return r;
}

int gs_vserv_lock_create(struct GsVServLock **oLock)
{
	int r = 0;

	struct GsVServLock *Lock = new GsVServLock();

	if (!! pthread_mutex_init(&Lock->mMutex, NULL))
		GS_ERR_CLEAN(1);
	Lock->mHaveLock = 0;

	if (oLock)
		*oLock = GS_ARGOWN(&Lock);

clean:
	GS_DELETE(&Lock, struct GsVServLock);

	return r;
}

int gs_vserv_lock_destroy(struct GsVServLock *Lock)
{
	if (Lock) {
		if (!! pthread_mutex_destroy(&Lock->mMutex))
			GS_ASSERT(0);
		GS_DELETE(&Lock, struct GsVServLock);
	}
	return 0;
}

int gs_vserv_lock_lock(struct GsVServLock *Lock)
{
	if (!! pthread_mutex_lock(&Lock->mMutex))
		return 1;
	Lock->mHaveLock = 1;
	return 0;
}

int gs_vserv_lock_unlock(struct GsVServLock *Lock)
{
	/* NOTE: HaveLock zeroes before actually unlocking */
	Lock->mHaveLock = 0;
	if (!! pthread_mutex_unlock(&Lock->mMutex))
		return 1;
	return 0;
}

int gs_vserv_lock_release(struct GsVServLock *Lock)
{
	if (Lock->mHaveLock)
		if (!! pthread_mutex_unlock(&Lock->mMutex))
			return 1;
	return 0;
}

int gs_vserv_quit_ctl_create(struct GsVServQuitCtl **oQuitCtl)
{
	int r = 0;

	struct GsVServQuitCtl *QuitCtl = NULL;

	int EvtFdExitReq = -1;
	int EvtFdExit = -1;

	// thread requesting exit 0 -> 1 -> 0
	if (-1 == (EvtFdExitReq = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);
	// controller (servctl) ordering exit 0 -> NumThread -> -=1 -> .. -> 0
	if (-1 == (EvtFdExit = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);

	QuitCtl = new GsVServQuitCtl();
	QuitCtl->mEvtFdExitReq = GS_FDOWN(&EvtFdExitReq);
	QuitCtl->mEvtFdExit = GS_FDOWN(&EvtFdExit);

	if (oQuitCtl)
		*oQuitCtl = GS_ARGOWN(&QuitCtl);

clean:
	gs_close_cond(&EvtFdExit);
	gs_close_cond(&EvtFdExitReq);

	return r;
}

int gs_vserv_quit_ctl_destroy(struct GsVServQuitCtl *QuitCtl)
{
	if (QuitCtl) {
		gs_close_cond(&QuitCtl->mEvtFdExitReq);
		gs_close_cond(&QuitCtl->mEvtFdExit);
	}

	return 0;
}

int gs_vserv_quit_ctl_reflect_evt_fd_exit(struct GsVServQuitCtl *QuitCtl, int *oFd)
{
	if (oFd)
		*oFd = QuitCtl->mEvtFdExit;
	return 0;
}
