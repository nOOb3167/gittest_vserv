#include <cstdlib>
#include <climits>

#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <deque>
#include <random>

#include <AL/al.h>
#include <AL/alc.h>

#include <gittest/misc.h>
#include <gittest/config.h>
#include <gittest/log.h>
#include <gittest/vserv_clnt.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_record.h>
// FIXME: BLAH GetHostByName
#include <gittest/UDPSocket.hpp>

#define GS_CLNT_ONE_TICK_MS 20

struct GsVServClnt
{
	struct GsVServClntCtx *mCtx;
	sp<UDPSocket> mSocket;
	sp<std::thread> mThread;
	struct GsVServClntAddress mAddr;
	std::atomic<uint32_t> mKeys;
	std::mt19937                            mRandGen;
	std::uniform_int_distribution<uint32_t> mRandDis;
};

GsLogList *g_gs_log_list_global = gs_log_list_global_create();

int gs_vserv_clnt_ctx_set(struct GsVServClnt *Clnt, struct GsVServClntCtx *Ctx)
{
	GS_ASSERT(! Clnt->mCtx);
	Clnt->mCtx = Ctx;
	return 0;
}

int gs_vserv_clnt_ctx_get(struct GsVServClnt *Clnt, struct GsVServClntCtx **oCtx)
{
	*oCtx = Clnt->mCtx;
	return 0;
}

int gs_vserv_clnt_receive(
	struct GsVServClnt *Clnt,
	struct GsVServClntAddress *ioAddrFrom,
	uint8_t *ioDataBuf, size_t DataSize, size_t *oLenData)
{
	int r = 0;

	int LenData = 0;

	/* -1 return code aliasing error and lack-of-progress conditions.. nice api minetest */
	if (-1 == (LenData = Clnt->mSocket->Receive(*ioAddrFrom, ioDataBuf, LenData))) {
		/* pretend -1 just means EAGAIN/EWOULDBLOCK/notreadable */
		LenData = 0;
		GS_ERR_NO_CLEAN(0);
	}

noclean:
	if (oLenData)
		*oLenData = LenData;

clean:

	return r;
}

int gs_vserv_clnt_send(struct GsVServClnt *Clnt, const uint8_t *DataBuf, size_t LenData)
{
	int r = 0;

	Clnt->mSocket->Send(Clnt->mAddr, DataBuf, LenData);

clean:

	return r;
}

int gs_vserv_clnt_random_uint(struct GsVServClnt *Clnt, uint32_t *oRand)
{
	*oRand = Clnt->mRandDis(Clnt->mRandGen);
	return 0;
}

int gs_vserv_clnt_setkeys(struct GsVServClnt *Clnt, uint32_t Keys)
{
	Clnt->mKeys.store(Keys);
	return 0;
}

void threadfunc(struct GsVServClnt *Clnt)
{
	int r = 0;

	std::chrono::high_resolution_clock Clock;

	long long TimeStampLastRun = std::chrono::duration_cast<std::chrono::milliseconds>(Clock.now().time_since_epoch()).count();

	while (true) {
		uint32_t Keys = 0;
		long long TimeStampBeforeWait = std::chrono::duration_cast<std::chrono::milliseconds>(Clock.now().time_since_epoch()).count();
		if (TimeStampBeforeWait < TimeStampLastRun) /* backwards clock? wtf? */
			TimeStampBeforeWait = LLONG_MAX;        /* just ensure processing runs immediately */
		long long TimeRemainingToFullTick = GS_CLNT_ONE_TICK_MS - GS_MIN(TimeStampBeforeWait - TimeStampLastRun, GS_CLNT_ONE_TICK_MS);
		if (! Clnt->mSocket->WaitData(TimeRemainingToFullTick))
			continue;
		TimeStampLastRun = std::chrono::duration_cast<std::chrono::milliseconds>(Clock.now().time_since_epoch()).count();
		Keys = Clnt->mKeys.load();
		if (!!(r = gs_vserv_clnt_callback_update_other(Clnt, TimeStampLastRun, Keys)))
			GS_GOTO_CLEAN();
	}

clean:
	if (!!r)
		GS_ASSERT(0);
}

int stuff(struct GsAuxConfigCommonVars *CommonVars)
{
	int r = 0;

	std::random_device RandDev;

	struct GsVServClntAddress Addr = {};
	struct GsVServClnt *Clnt = NULL;

	Addr.mSinFamily = AF_UNIX;
	Addr.mSinPort = CommonVars->VServPort;
	Addr.mSinAddr = 0;

	if (!!(r = UDPSocket::GetHostByName(CommonVars->VServHostNameBuf, &Addr.mSinAddr)))
		GS_GOTO_CLEAN();

	Clnt = new GsVServClnt();
	Clnt->mCtx = NULL;
	Clnt->mSocket = sp<GsVServClnt>(new UDPSocket());
	Clnt->mAddr = Addr;
	Clnt->mKeys.store(0);
	Clnt->mRandGen = std::mt19937(RandDev());
	Clnt->mRandDis = std::uniform_int_distribution<uint32_t>();

	if (!!(r = gs_vserv_clnt_callback_create(Clnt)))
		GS_GOTO_CLEAN();

	Clnt->mSocket->Bind(Clnt->mAddr);

	Clnt->mThread = sp<std::thread>(new std::thread(threadfunc, Clnt));

	Clnt->mThread->join();

clean:

	return r;
}

int main(int argc, char **argv)
{
	int r = 0;

	struct GsConfMap *ConfMap = NULL;
	struct GsAuxConfigCommonVars CommonVars = {};

	if (!!(r = gs_log_crash_handler_setup()))
		GS_GOTO_CLEAN();

	if (!!(r = gs_config_read_default_everything(&ConfMap)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_config_get_common_vars(ConfMap, &CommonVars)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_config_create_common_logs(ConfMap)))
		GS_GOTO_CLEAN();

	{
		log_guard_t Log(GS_LOG_GET("selfup"));
		if (!!(r = stuff(&CommonVars)))
			GS_GOTO_CLEAN();
	}

clean:
	GS_DELETE_F(&ConfMap, gs_conf_map_destroy);

	gs_log_crash_handler_dump_global_log_list_suffix("_log", strlen("_log"));

	if (!!r)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
