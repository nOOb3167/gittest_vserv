#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include <functional>  // std::hash
#include <utility>
#include <memory>
#include <vector>
#include <deque>
#include <map>

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
#include <gittest/log.h>
#include <gittest/vserv_helpers_plat.h>
#include <gittest/vserv_net.h>

struct GsVServCtl
{
	struct GsVServThreads *mThreads;
	struct GsVServQuitCtl *mQuitCtl;
	struct GsVServWork *mWork;
	// FIXME: no mMgmt - mCon provides access to what SHOULD be mMgmt via CbGetMgmt() (helper gs_vserv_ctl_get_mgmt())
	/* shared (work&mgmt) context */
	struct GsVServCon *mCon; /*notowned*/ // FIXME: needs CbDestroy?
	struct GsVServWorkCb mWorkCb;
	struct GsVServMgmtCb mMgmtCb;
};

static int gs_addr_sockaddr_in(const struct GsAddr *Addr, struct sockaddr_in *SockAddr);
static int gs_eventfd_read(int EvtFd);
static int gs_eventfd_write(int EvtFd, int Value);
static int gs_vserv_thread_func_work(struct GsVServCtl *ServCtl, size_t SockIdx);
static int gs_vserv_thread_func_mgmt(struct GsVServCtl *ServCtl, size_t SockIdx);

size_t gs_addr_hash_t::operator()(const struct GsAddr &k) const {
	// FIXME: https://stackoverflow.com/questions/35985960/c-why-is-boosthash-combine-the-best-way-to-combine-hash-values
	return (    (std::hash<unsigned long long>()(k.mSinFamily) << 1)
		     ^ ((std::hash<unsigned long long>()(k.mSinPort) << 1) >> 1)
			 ^ ((std::hash<unsigned long long>()(k.mSinAddr) << 2) >> 2));
}

bool gs_addr_equal_t::operator()(const GsAddr &a, const GsAddr &b) const {
	return a.mSinPort == b.mSinFamily
		&& a.mSinPort == b.mSinPort
		&& a.mSinAddr == b.mSinAddr;
}

bool gs_addr_less_t::operator()(const GsAddr &a, const GsAddr &b) const {
	return gs_addr_hash_t()(a) < gs_addr_hash_t()(b);
}

size_t gs_addr_rawhash(struct GsAddr *Addr)
{
	return gs_addr_hash_t()(*Addr);
}

size_t gs_addr_port(struct GsAddr *Addr)
{
	return Addr->mSinPort;
}

int gs_addr_sockaddr_in(const struct GsAddr *Addr, struct sockaddr_in *SockAddr)
{
	if (Addr->mSinFamily != AF_INET)
		return 1;
	SockAddr->sin_family = AF_INET;
	SockAddr->sin_port = htons(Addr->mSinPort);
	SockAddr->sin_addr.s_addr = htonl(Addr->mSinAddr);
	return 0;
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

int gs_vserv_thread_func_work(struct GsVServCtl *ServCtl, size_t SockIdx)
{
	int r = 0;

	log_guard_t Log(GS_LOG_GET("serv"));

	if (!!(r = ServCtl->mWorkCb.CbThreadFunc(ServCtl, SockIdx)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_thread_func_mgmt(struct GsVServCtl *ServCtl, size_t SockIdx)
{
	int r = 0;

	GS_ASSERT(SockIdx == -1);

	log_guard_t Log(GS_LOG_GET("mgmt"));

	if (!!(r = ServCtl->mMgmtCb.CbThreadFuncM(ServCtl)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_ctl_create_part(
	size_t ThreadNum,
	struct GsVServCon *Con, /*owned*/
	struct GsVServWorkCb WorkCb,
	struct GsVServMgmtCb MgmtCb,
	struct GsVServCtl **oServCtl)
{
	int r = 0;

	struct GsVServCtl *ServCtl = NULL;

	ServCtl = new GsVServCtl();
	ServCtl->mThreads = NULL;
	ServCtl->mQuitCtl = NULL;
	ServCtl->mWork = NULL;
	ServCtl->mCon = GS_ARGOWN(&Con);
	ServCtl->mWorkCb = WorkCb;
	ServCtl->mMgmtCb = MgmtCb;

	if (!!(r = gs_vserv_threads_create(ThreadNum, &ServCtl->mThreads)))
		GS_GOTO_CLEAN();

	if (oServCtl)
		*oServCtl = GS_ARGOWN(&ServCtl);

clean:
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);

	return r;
}

int gs_vserv_ctl_create_finish(
	struct GsVServCtl *ServCtl,
	struct GsVServQuitCtl *QuitCtl, /*owned*/
	struct GsVServWork *Work /*owned*/)
{
	int r = 0;

	/**/

	GS_ASSERT(ServCtl->mQuitCtl == NULL);
	GS_ASSERT(ServCtl->mWork    == NULL);

	ServCtl->mQuitCtl = GS_ARGOWN(&QuitCtl);
	ServCtl->mWork    = GS_ARGOWN(&Work);

	/* create threads */

	if (!!(r = gs_vserv_threads_init_and_start(
		ServCtl->mThreads,
		ServCtl,
		gs_vserv_thread_func_work,
		gs_vserv_thread_func_mgmt)))
	{
		GS_GOTO_CLEAN();
	}

clean:
	GS_DELETE_F(&QuitCtl, gs_vserv_quit_ctl_destroy);
	GS_DELETE_F(&Work, gs_vserv_work_destroy);

	return r;
}

int gs_vserv_ctl_destroy(struct GsVServCtl *ServCtl)
{
	int r = 0;

	if (ServCtl) {
		GS_DELETE_F(&ServCtl->mThreads, gs_vserv_threads_destroy);
		GS_DELETE_F(&ServCtl->mQuitCtl, gs_vserv_quit_ctl_destroy);
		GS_DELETE_F(&ServCtl->mWork, gs_vserv_work_destroy);
		GS_DELETE(&ServCtl, struct GsVServCtl);
	}

clean:

	return r;
}

int gs_vserv_ctl_quit_request(struct GsVServCtl *ServCtl)
{
	int r = 0;

	if (!!(r = gs_eventfd_write(ServCtl->mEvtFdExitReq, 1)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_ctl_quit_wait(struct GsVServCtl *ServCtl)
{
	int r = 0;

	// FIXME: port to GsVServQuitCtl
	GS_ASSERT(0);

	GS_ALLOCA_VAR(RetVal, void *, ServCtl->mThreadNum);

	if (!!(r = gs_eventfd_read(ServCtl->mEvtFdExitReq)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_eventfd_write(ServCtl->mEvtFdExit, ServCtl->mNumThread)))
		GS_GOTO_CLEAN();

	for (size_t i = 0; i < ServCtl->mThreadNum; i++)
		if (!!(r = pthread_join(ServCtl->mThreadVec[i], RetVal + i)))
			GS_GOTO_CLEAN();

clean:

	return r;
}

struct GsVServWork * gs_vserv_ctl_get_work(struct GsVServCtl *ServCtl)
{
	return ServCtl->mWork;
}

struct GsVServMgmt * gs_vserv_ctl_get_mgmt(struct GsVServCtl *ServCtl)
{
	return ServCtl->mCon->CbGetMgmt(ServCtl->mCon);
}

struct GsVServCon * gs_vserv_ctl_get_con(struct GsVServCtl *ServCtl)
{
	return ServCtl->mCon;
}

struct GsVServWorkCb * gs_vserv_ctl_get_workcb(struct GsVServCtl *ServCtl)
{
	return &ServCtl->mWorkCb;
}

struct GsVServMgmtCb * gs_vserv_ctl_get_mgmtcb(struct GsVServCtl *ServCtl)
{
	return &ServCtl->mMgmtCb;
}
