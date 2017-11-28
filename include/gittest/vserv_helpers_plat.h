#ifndef _VSERV_HELPERS_PLAY_H_
#define _VSERV_HELPERS_PLAY_H_

struct GsVServThreads;
struct GsVServLock;
struct GsVServQuitCtl;

int gs_vserv_sockets_create(
	const char *Port,
	int *ioSockFdVec, size_t SockFdNum);

int gs_vserv_threads_create(
	size_t NumThread,
	struct GsVServThreads **oThreads);
int gs_vserv_threads_destroy(struct GsVServThreads *Threads);
int gs_vserv_threads_init_and_start(
	struct GsVServThreads *Threads,
	struct GsVServCtl *ServCtl,
	int(*WorkFunc)(struct GsVServCtl *ServCtl, size_t SockIdx),
	int(*MgmtFunc)(struct GsVServCtl *ServCtl, size_t SockIdx));

int gs_vserv_lock_create(struct GsVServLock **oLock);
int gs_vserv_lock_destroy(struct GsVServLock *Lock);
int gs_vserv_lock_lock(struct GsVServLock *Lock);
int gs_vserv_lock_unlock(struct GsVServLock *Lock);
int gs_vserv_lock_release(struct GsVServLock *Lock);

int gs_vserv_quit_ctl_create(struct GsVServQuitCtl **oQuitCtl);
int gs_vserv_quit_ctl_destroy(struct GsVServQuitCtl *QuitCtl);
int gs_vserv_quit_ctl_reflect_evt_fd_exit(struct GsVServQuitCtl *QuitCtl, int *oFd);

#endif /* _VSERV_HELPERS_PLAY_H_ */
