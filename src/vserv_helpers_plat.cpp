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
