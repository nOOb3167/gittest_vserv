#include <cstdlib>

#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <deque>
#include <random>

#include <AL/al.h>
#include <AL/alc.h>

#include <gittest/misc.h>
#include <gittest/vserv_clnt.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_record.h>

struct GsVServClnt
{
	struct GsVServClntCtx *mCtx;
	sp<UDPSocket> mSocket;
	sp<std::thread> mThread;
	struct GsVServClntAddress mAddr;
	struct GsRecord *mRecord;
	std::atomic<uint32_t> mKeys;
	std::mt19937                            mRandGen;
	std::uniform_int_distribution<uint32_t> mRandDis;
};

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

int gs_vserv_clnt_receive(struct GsVServClnt *Clnt, struct GsVServClntAddress *ioAddrFrom, uint8_t *ioDataBuf, size_t DataSize, size_t *oLenData)
{
	int r = 0;

	int LenData = 0;

	/* -1 return code aliasing error and lack-of-progress conditions.. nice api minetest */
	if (-1 == (LenData = Clnt->mSocket->Receive(*ioAddrFrom, ioDataBuf, LenData)))
		GS_ERR_CLEAN(1);

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

	long long TimeStamp = 0;

	while (true) {
		size_t NumFraProcessed = 0;
		// FIXME: hardcoded timeout (should be prorated wrt worktime)
		if (! Clnt->mSocket->WaitData(20))
			continue;
		TimeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(Clock.now().time_since_epoch()).count();
		while (true) {
			uint8_t FraBuf[GS_OPUS_FRAME_48KHZ_20MS_SAMP_NUM];
			size_t LenFra = 0;
			uint32_t Keys = 0;
			uint8_t Mode = 0;
			uint16_t Blk = 0;
			if (!!(r = gs_record_capture_drain(Clnt->mRecord, sizeof(uint16_t), GS_OPUS_FRAME_48KHZ_20MS_SAMP_NUM, FraBuf, sizeof FraBuf, &LenFra, &NumFraProcessed)))
				GS_GOTO_CLEAN();
			if (NumFraProcessed == 0)
				break;
			Keys = Clnt->mKeys.load();
			Mode = (Keys >> 0) & 0xFF;
			Blk  = (Keys >> 8) & 0xFFFF;
			if (!!(r = gs_vserv_clnt_callback_update_record(Clnt, TimeStamp, Mode, GS_VSERV_USER_ID_SERVFILL_FIXME, Blk, FraBuf, LenFra)))
				GS_GOTO_CLEAN();
		}
		if (!!(r = gs_vserv_clnt_callback_update_other(Clnt, TimeStamp)))
			GS_GOTO_CLEAN();
	}

clean:
	if (!!r)
		GS_ASSERT(0);
}

int stuff(int argc, char **argv)
{
	int r = 0;

	std::random_device RandDev;

	struct GsVServClntAddress Addr = {};
	struct GsVServClnt *Clnt = NULL;

	Addr.mSinFamily = AF_UNIX;
	Addr.mSinPort = 3757;
	Addr.mSinAddr = htons(0x7F000001);

	Clnt = new GsVServClnt();
	Clnt->mCtx = NULL;
	Clnt->mSocket = sp<GsVServClnt>(new UDPSocket());
	Clnt->mAddr = Addr;
	Clnt->mRecord = NULL;
	Clnt->mKeys.store(0);
	Clnt->mRandGen = std::mt19937(RandDev());
	Clnt->mRandDis = std::uniform_int_distribution<uint32_t>();

	if (!!(r = gs_record_create(&Clnt->mRecord)))
		GS_GOTO_CLEAN();

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

	if (!!(r = stuff(argc, argv)))
		GS_GOTO_CLEAN();

clean:
	if (!!r)
		GS_ASSERT(0);

	return r;
}
