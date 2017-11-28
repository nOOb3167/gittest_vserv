#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include <functional>  // std::hash
#include <utility>

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

static int gs_vserv_thread_func_work(struct GsVServCtl *ServCtl, size_t SockIdx);
static int gs_vserv_thread_func_mgmt(struct GsVServCtl *ServCtl, size_t SockIdx);

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

	if (!!(r = gs_vserv_quit_ctl_request(ServCtl->mQuitCtl)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_ctl_quit_wait(struct GsVServCtl *ServCtl)
{
	int r = 0;

	if (!!(r = gs_vserv_quit_ctl_wait_nt(ServCtl->mQuitCtl, gs_vserv_threads_get_numthread(ServCtl->mThreads))))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_threads_join(ServCtl->mThreads)))
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
