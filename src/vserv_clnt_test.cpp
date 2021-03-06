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
#include <gittest/UDPSocket.hpp>

#define GS_CLNT_ONE_TICK_MS 20

struct GsVServClnt
{
	struct GsVServClntCtx *mCtx;
	sp<UDPSocket> mSocket;
	sp<std::thread> mThread;
	uint32_t mThreadExitCode;
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
	if (-1 == (LenData = Clnt->mSocket->Receive(*ioAddrFrom, ioDataBuf, DataSize))) {
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

	log_guard_t Log(GS_LOG_GET("selfup"));

	typedef std::chrono::high_resolution_clock Clock;

	long long TimeStampLastRun = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();

	// FIXME: temporary testing dummy
	uint16_t BlkDummy = 0;
	long long BlkTimeStampDummy = TimeStampLastRun;
	// FIXME: temporary testing dummy
	if (!!(r = gs_vserv_clnt_callback_ident(Clnt, "abcd", 4, "efgh", 4, TimeStampLastRun)))
		GS_GOTO_CLEAN();

	while (true) {
		uint32_t Keys = 0;
		long long TimeStampBeforeWait = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
		bool WaitIndicatesDataArrived = 0;
		if (TimeStampBeforeWait < TimeStampLastRun) /* backwards clock? wtf? */
			TimeStampBeforeWait = LLONG_MAX;        /* just ensure processing runs immediately */
		long long TimeRemainingToFullTick = GS_CLNT_ONE_TICK_MS - GS_MIN(TimeStampBeforeWait - TimeStampLastRun, GS_CLNT_ONE_TICK_MS);
		WaitIndicatesDataArrived = Clnt->mSocket->WaitData(TimeRemainingToFullTick); /* note indication is not actually used */
		TimeStampLastRun = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
		Keys = Clnt->mKeys.load();
		// FIXME: temporary testing dummy
		BlkDummy = (TimeStampLastRun - BlkTimeStampDummy) / 3000; /* increment new block every 3s */
		Keys = ('s' << 0) | (BlkDummy << 8);
		if (!!(r = gs_vserv_clnt_callback_update_other(Clnt, TimeStampLastRun, Keys)))
			GS_GOTO_CLEAN();
	}

clean:
	Clnt->mThreadExitCode = r;
}

int stuff(struct GsAuxConfigCommonVars *CommonVars)
{
	int r = 0;

	ALCdevice *Device = NULL;
	ALCcontext *Context = NULL;

	std::random_device RandDev;

	struct GsVServClntAddress Addr = {};
	struct GsVServClntAddress AddrAny = {};
	struct GsVServClnt *Clnt = NULL;

	if (!(Device = alcOpenDevice(NULL)))
		GS_ERR_CLEAN(1);

	if (!(Context = alcCreateContext(Device, NULL)))
		GS_ERR_CLEAN(1);

	if (! alcMakeContextCurrent(Context))
		GS_ERR_CLEAN(1);

	GS_NOALERR();

	Addr.mSinFamily = AF_INET;
	Addr.mSinPort = CommonVars->VServPort;
	Addr.mSinAddr = 0;

	AddrAny.mSinFamily = AF_INET;
	AddrAny.mSinPort = 0;
	AddrAny.mSinAddr = INADDR_ANY;

	UDPSocket::sockets_init();

	if (!!(r = UDPSocket::GetHostByName(CommonVars->VServHostNameBuf, &Addr.mSinAddr)))
		GS_GOTO_CLEAN();

	Clnt = new GsVServClnt();
	Clnt->mCtx = NULL;
	Clnt->mSocket = sp<UDPSocket>(new UDPSocket());
	Clnt->mThread; /*dummy*/
	Clnt->mThreadExitCode = 0;
	Clnt->mAddr = Addr;
	Clnt->mKeys.store(0);
	Clnt->mRandGen = std::mt19937(RandDev());
	Clnt->mRandDis = std::uniform_int_distribution<uint32_t>();

	if (!!(r = gs_vserv_clnt_callback_create(Clnt)))
		GS_GOTO_CLEAN();

	Clnt->mSocket->Bind(AddrAny);

	Clnt->mThread = sp<std::thread>(new std::thread(threadfunc, Clnt));

	Clnt->mThread->join();

	if (!!(r = Clnt->mThreadExitCode))
		GS_GOTO_CLEAN();

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
