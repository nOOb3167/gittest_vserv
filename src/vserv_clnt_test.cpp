#include <cstdlib>

#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <deque>
#include <random>

#ifdef _WIN32
// needed for mingw according to minetest socket.cpp
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0501
#endif
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef SOCKET socket_t;
#endif

#include <AL/al.h>
#include <AL/alc.h>

#include <gittest/misc.h>
#include <gittest/vserv_clnt.h>
#include <gittest/vserv_helpers.h>

// FIXME:
#define GS_VSERV_CMD_IDENT_FIXME 'i'
#define GS_VSERV_CMD_IDENT_ACK_FIXME 'I'
#define GS_VSERV_CMD_GROUP_MODE_MSG_FIXME 'm'
#define GS_VSERV_GROUP_MODE_NONE_FIXME 0
#define GS_VSERV_USER_ID_SERVFILL_FIXME 0xFFFF

#define GS_CLNT_ARBITRARY_PACKET_MAX 4096 /* but mind IP layer fragmentation issues of UDP */
#define GS_CLNT_ARBITRARY_IDENT_RESEND_TIMEOUT 100

#define GS_RECORD_BUFFERS_NUM 8
#define GS_RECORD_ARBITRARY_BUFFER_SAMPLES_NUM 48000

#define GS_OPUS_FRAME_48KHZ_20MS_SAMP_NUM ((48000 / 1000) /*samples/msec*/ * 20 /*20ms (one Opus frame)*/)

#define GS_NOALERR() do { GS_ASSERT(AL_NO_ERROR == alGetError()); } while(0)

class UDPSocket
{
public:
	UDPSocket() {
		init();
	}

	~UDPSocket() {
		if (mHandle != INVALID_SOCKET) {
			closesocket(mHandle);
			mHandle = INVALID_SOCKET;
		}
	}

	void Bind(GsVServClntAddress Addr) {
		int r = 0;

		/* lol this API, bind with void return */

		struct sockaddr_in SockAddr = {};

		SockAddr.sin_family = mSinFamily;
		SockAddr.sin_port = htons(Addr.mSinPort);
		SockAddr.sin_addr.s_addr = htonl(Addr.mSinAddr);

		if (Addr.mSinFamily != mSinFamily)
			GS_ERR_CLEAN(1);

		if (SOCKET_ERROR == bind(mHandle, (struct sockaddr *) &SockAddr, sizeof SockAddr))
			GS_ERR_CLEAN(1);

	clean:
		if (!!r)
			GS_ASSERT(0);
	}

	bool init() {
		int r = 0;

		mHandle = INVALID_SOCKET;
		mSinFamily = AF_INET;
		if (INVALID_SOCKET == (mHandle = socket(mSinFamily, SOCK_DGRAM, 0)))
			GS_ERR_CLEAN(1);
		mTimeoutMs = 0;

	clean:
		if (!!r) {
			if (mHandle != INVALID_SOCKET) {
				closesocket(mHandle);
				mHandle = INVALID_SOCKET;
			}
		}

		return r;
	}

	void Send(const GsVServClntAddress &Dest, const void *Data, int Size) {
		int r = 0;

		struct sockaddr_in SockAddr = {};
		int NSent = 0;

		if (Dest.mSinFamily != mSinFamily)
			GS_ERR_CLEAN(1);
		if (Dest.mSinFamily != AF_INET)
			GS_ERR_CLEAN(1);

		SockAddr.sin_family = Dest.mSinFamily;
		SockAddr.sin_port = htons(Dest.mSinPort);
		SockAddr.sin_addr.s_addr = htonl(Dest.mSinAddr);

		if (SOCKET_ERROR == (NSent = sendto(mHandle, (const char *) Data, Size, 0, (struct sockaddr *) &SockAddr, sizeof SockAddr)))
			GS_ERR_CLEAN(1);
		if (NSent < Size)
			GS_ERR_CLEAN(1);

	clean:
		if (!!r)
			GS_ASSERT(0);
	}

	int Receive(GsVServClntAddress &Sender, void *Data, int Size) {
		int r = 0;

		if (! WaitData(mTimeoutMs))
			return -1;

		struct sockaddr_in SockAddr = {};
		int SockAddrLen = sizeof SockAddr;
		int NRecv = 0;

		if (SOCKET_ERROR == (NRecv = recvfrom(mHandle, (char *) Data, Size, MSG_TRUNC, (struct sockaddr *) &SockAddr, &SockAddrLen)))
			GS_ERR_CLEAN(1);
		if (SockAddrLen != sizeof SockAddr)
			GS_ERR_CLEAN(1);
		if (NRecv > Size)  // MSG_TRUNC effect for too-long datagrams
			GS_ERR_CLEAN(1);

		Sender.mSinFamily = SockAddr.sin_family;
		Sender.mSinPort = ntohs(SockAddr.sin_port);
		Sender.mSinAddr = ntohl(SockAddr.sin_addr.s_addr);

	clean:
		if (!!r)
			NRecv = -1;

		return NRecv;
	}

	bool WaitData(int TimeoutMs) {
		int r = 0;

		fd_set RSet;
		struct timeval TVal = {};

		int NReady = -1;

		FD_ZERO(&RSet);
		FD_SET(mHandle, &RSet);
		TVal.tv_sec = TimeoutMs;
		TVal.tv_usec = 0;

		if (SOCKET_ERROR == (NReady = select(mHandle + 1, &RSet, NULL, NULL, &TVal)))
			GS_ERR_CLEAN(1);
		if (NReady == 0)
			return false;
		if (! FD_ISSET(mHandle, &RSet))
			return false;

		return true;

	clean:
		if (!!r)
			GS_ASSERT(0);
		/* dummy */
		return false;
	}

private:
	SOCKET mHandle;
	unsigned long long mSinFamily;
	unsigned long long mTimeoutMs;
};

struct GsRecord
{
	ALCdevice *mCapDevice;
	ALuint mSource;
	ALuint *mBufferVec; size_t mBufferNum;
	std::deque<ALuint> mBufferAvail;
};

int gs_record_create(struct GsRecord **oRecord)
{
	int r = 0;

	struct GsRecord *Record = NULL;

	ALCdevice *CapDevice = NULL;
	ALuint Source = -1;
	ALuint *BufferVec = NULL;
	ALuint BufferNum = GS_RECORD_BUFFERS_NUM;
	std::deque<ALuint> BufferAvail;

	if (!(BufferVec = new ALuint[BufferNum]))
		GS_ERR_CLEAN(1);

	GS_ASSERT(alcGetCurrentContext() != NULL);

	if (!(CapDevice = alcCaptureOpenDevice(NULL, 48000, AL_FORMAT_MONO16, GS_RECORD_ARBITRARY_BUFFER_SAMPLES_NUM)))
		GS_GOTO_CLEAN();

	GS_NOALERR();

	alGenSources(1, &Source);
	alGenBuffers(BufferNum, BufferVec);

	for (size_t i = 0; i < BufferNum; i++)
		BufferAvail.push_back(BufferVec[i]);

	GS_NOALERR();

	Record = new GsRecord();
	Record->mCapDevice = GS_ARGOWN(&CapDevice);
	Record->mSource = Source;
	Record->mBufferVec = GS_ARGOWN(&BufferVec); Record->mBufferNum = BufferNum;
	Record->mBufferAvail = BufferAvail;

	if (oRecord)
		*oRecord = GS_ARGOWN(&Record);

clean:
	GS_DELETE(&Record, struct GsRecord);
	GS_DELETE_ARRAY(&BufferVec, ALuint);

	return r;
}

int gs_record_destroy(struct GsRecord *Record)
{
	if (Record) {
		GS_DELETE(&Record, struct GsRecord);
	}
	return 0;
}

int gs_record_start(struct GsRecord *Record)
{
	alcCaptureStart(Record->mCapDevice);
	GS_NOALERR();
}

int gs_record_stop(struct GsRecord *Record)
{
	alcCaptureStop(Record->mCapDevice);
	GS_NOALERR();
}

int gs_record_capture_drain(
	struct GsRecord *Record,
	size_t SampSize,
	size_t FraNumSamp,
	uint8_t *ioFraBuf, size_t FraBufSize, size_t *oLenFraBuf,
	size_t *oNumFraProcessed)
{
	int r = 0;

	/*
	* OpenAL alcGetIntegerv exposes the count of new samples arrived, but not yet delivered via alcCaptureSamples.
	*   this count grows during an ongoing capture (ex started via alcCaptureStart).
	* we want samples delivered in blocks of certain size.
	*   (specifically blocks of size of an Opus frame, see calculation of 'OpFraNumSamp'.
	*    Opus supports only specific Opus frame sizes, 20ms hardcoded.
	*    https://wiki.xiph.org/Opus_Recommended_Settings : Quote "Opus can encode frames of 2.5, 5, 10, 20, 40, or 60 ms.")
	* if this function keeps getting called during an ongoing capture, alcGetIntegerv eventually will report enough samples to fill one or more Opus frames.
	*/

	// FIXME: apply fix once opus becomes used
	typedef ALshort should_be_opus_int16_tho;

	/* the values are hardcoded for 1 channel (mono) (ex for 2 channels a 'sample' is actually two individual ALshort or opus_int16 values) */
	const size_t AlSampSize = sizeof(ALshort); /*AL_FORMAT_MONO16*/
	const size_t OpSampSize = sizeof(should_be_opus_int16_tho); /*opus_encode API doc*/
	GS_ASSERT(AlSampSize == OpSampSize);
	const size_t OpFraNumSamp = GS_OPUS_FRAME_48KHZ_20MS_SAMP_NUM;
	const size_t OpFraSize = OpFraNumSamp * OpSampSize;
	GS_ASSERT(OpFraNumSamp == FraNumSamp);

	ALCint NumAvailSamp = 0;
	size_t NumAvailFraAl = 0;
	size_t NumAvailFraBuf = 0;
	size_t NumFraToProcess = 0;

	alcGetIntegerv(Record->mCapDevice, ALC_CAPTURE_SAMPLES, 1, &NumAvailSamp);

	GS_NOALERR();

	NumAvailFraAl = (NumAvailSamp / OpFraNumSamp); /*truncating division*/
	NumAvailFraBuf = (FraBufSize / OpFraSize);     /*truncating division*/
	NumFraToProcess = GS_MIN(NumAvailFraAl, NumAvailFraBuf);

	if (NumFraToProcess == 0)
		GS_ERR_NO_CLEAN(0);

	alcCaptureSamples(Record->mCapDevice, ioFraBuf, NumFraToProcess * OpFraNumSamp);

	GS_NOALERR();

noclean:
	if (oLenFraBuf)
		*oLenFraBuf = NumFraToProcess * OpFraSize;
	if (oNumFraProcessed)
		*oNumFraProcessed = NumFraToProcess;

clean:

	return r;
}

struct GsName
{
	std::string mName;
	std::string mServ;
	uint16_t mId;
};

struct GsRenamer
{
	std::string mNameWant;
	std::string mServWant;
	long long mTimeStampLastRequested;
	uint32_t mRandLastRequested;
};

struct GsVServClntCtx
{
	int16_t mBlk;
	int16_t mSeq;

	struct GsName mName;
	struct GsRenamer mRenamer;
};

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

int gs_vserv_clnt_callback_create(struct GsVServClnt *Clnt)
{
	int r = 0;

	struct GsVServClntCtx *Ctx = new GsVServClntCtx();
	Ctx->mBlk = 0;
	Ctx->mSeq = 0;
	Ctx->mName.mName = std::string();
	Ctx->mName.mServ = std::string();
	Ctx->mName.mId = GS_VSERV_USER_ID_SERVFILL_FIXME;

	if (!!(r = gs_vserv_clnt_ctx_set(Clnt, Ctx)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_clnt_callback_destroy(struct GsVServClnt *Clnt)
{
	int r = 0;

	struct GsVServClntCtx *Ctx = NULL;

	if (!!(r = gs_vserv_clnt_ctx_get(Clnt, &Ctx)))
		GS_GOTO_CLEAN();

	// FIXME: release ctx
	GS_ASSERT(0);

clean:

	return r;
}

int gs_vserv_clnt_callback_ident(struct GsVServClnt *Clnt,
	const char *NameWantedBuf, size_t LenNameWanted,
	const char *ServWantedBuf, size_t LenServWanted,
	long long TimeStamp)
{
	int r = 0;

	struct GsVServClntCtx *Ctx = NULL;

	struct GsRenamer Renamer = {};
	uint32_t FreshRand = 0;

	GS_ALLOCA_VAR(OutBuf, uint8_t, GS_CLNT_ARBITRARY_PACKET_MAX);
	struct GsPacket PacketOut = { OutBuf, GS_CLNT_ARBITRARY_PACKET_MAX };

	if (!!(r = gs_vserv_clnt_ctx_get(Clnt, &Ctx)))
		GS_GOTO_CLEAN();

	/* setup for resends if needed */

	if (!!(r = gs_vserv_clnt_random_uint(Clnt, &FreshRand)))
		GS_GOTO_CLEAN();

	Renamer.mNameWant = std::string(NameWantedBuf, LenNameWanted);
	Renamer.mRandLastRequested = FreshRand;
	Renamer.mTimeStampLastRequested = TimeStamp;

	/* emit ident */

	if (gs_packet_space(&PacketOut, 0, 1 /*cmd*/ + 4 /*rand*/ + 4 /*lenname*/ + 4 /*lenserv*/ + LenNameWanted /*name*/ + LenServWanted /*serv*/))
		GS_ERR_CLEAN(1);

	gs_write_byte(OutBuf + 0, GS_VSERV_CMD_IDENT_FIXME);
	gs_write_uint(OutBuf + 1, Renamer.mRandLastRequested);
	gs_write_uint(OutBuf + 5, LenNameWanted);
	gs_write_uint(OutBuf + 9, LenServWanted);
	memcpy(OutBuf + 13 + 0            , NameWantedBuf, LenNameWanted);
	memcpy(OutBuf + 13 + LenNameWanted, ServWantedBuf, LenServWanted);

	/* update packet with final length */

	PacketOut.dataLength = 13 + LenNameWanted + LenServWanted;

	if (!!(r = gs_vserv_clnt_send(Clnt, PacketOut.data, PacketOut.dataLength)))
		GS_GOTO_CLEAN();

	Ctx->mRenamer = Renamer;

clean:

	return r;
}

int gs_vserv_clnt_callback_update_record(
	struct GsVServClnt *Clnt,
	long long TimeStamp,
	uint8_t Mode,
	uint16_t Id,
	uint16_t Blk,
	uint8_t *FraBuf, size_t LenFra)
{
	int r = 0;

	/* (cmd)[1], (mode)[1], (id)[2], (blk)[2], (seq)[2], (data)[...] */

	struct GsVServClntCtx *Ctx = NULL;

	GS_ALLOCA_VAR(OutBuf, uint8_t, GS_CLNT_ARBITRARY_PACKET_MAX);

	struct GsPacket PacketOut = { OutBuf, GS_CLNT_ARBITRARY_PACKET_MAX };

	if (!!(r = gs_vserv_clnt_ctx_get(Clnt, &Ctx)))
		GS_GOTO_CLEAN();

	/* no mode - no send requested */
	if (Mode == GS_VSERV_GROUP_MODE_NONE_FIXME)
		GS_ERR_NO_CLEAN(0);

	/* fresh blk? use it (also resetting seq) */
	if (Ctx->mBlk != Blk) {
		Ctx->mBlk = Blk;
		Ctx->mSeq = 0;
	}

	if (gs_packet_space(&PacketOut, 0, 1 /*cmd*/ + 1 /*mode*/ + 2 /*id*/ + 2 /*blk*/ + 2 /*seq*/ + LenFra /*data*/))
		GS_ERR_CLEAN(1);

	gs_write_byte(PacketOut.data + 0, GS_VSERV_CMD_GROUP_MODE_MSG_FIXME);
	gs_write_byte(PacketOut.data + 1, Mode);
	gs_write_short(PacketOut.data + 2, Id);
	gs_write_short(PacketOut.data + 4, Ctx->mBlk);
	gs_write_short(PacketOut.data + 6, Ctx->mSeq);
	memcpy(PacketOut.data + 8, FraBuf, LenFra);

	/* update packet with final length */

	PacketOut.dataLength = 8 + LenFra;

	if (!!(r = gs_vserv_clnt_send(Clnt, PacketOut.data, PacketOut.dataLength)))
		GS_GOTO_CLEAN();

noclean:

clean:

	return r;
}

int gs_vserv_clnt_crank0(
	struct GsVServClnt *Clnt,
	struct GsVServClntCtx *Ctx,
	long long TimeStamp,
	struct GsPacket *Packet)
{
	int r = 0;

	if (gs_packet_space(Packet, 0, 1))
		GS_ERR_CLEAN(1);

	switch (Packet->data[0]) {

	case GS_VSERV_CMD_IDENT_ACK_FIXME:
	{
		size_t Offset = 0;

		uint32_t Rand = 0;
		uint32_t Id = GS_VSERV_USER_ID_SERVFILL_FIXME;

		if (gs_packet_space(Packet, (Offset += 1), 4 /*rand*/ + 2 /*id*/))
			GS_ERR_CLEAN_J(ident_ack, 1);

		Rand = gs_read_uint(Packet->data + Offset + 0);
		Id = gs_read_short(Packet->data + Offset + 4);

		/* unsolicited or reliability-codepath (ex re-sent or reordered packet) GS_VSERV_CMD_IDENT_ACK */

		if (! (Ctx->mRenamer.mNameWant.size() && Ctx->mRenamer.mServWant.size()))
			GS_ERR_NO_CLEAN_J(ident_ack, 0);
		if (Rand != Ctx->mRenamer.mRandLastRequested)
			GS_ERR_NO_CLEAN_J(ident_ack, 0);

		/* seems legit, apply */

		Ctx->mName.mName = Ctx->mRenamer.mNameWant;
		Ctx->mName.mServ = Ctx->mRenamer.mServWant;
		Ctx->mName.mId = Id;

	noclean_ident_ack:

	clean_ident_ack:
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	default:
		GS_ASSERT(0);
	}

clean:

	return r;
}

int gs_vserv_clnt_callback_update_other(
	struct GsVServClnt *Clnt,
	long long TimeStamp)
{
	int r = 0;

	struct GsVServClntCtx *Ctx = NULL;

	struct GsPacket PacketOut = {};
	struct GsVServClntAddress Addr = {};

	GS_ALLOCA_VAR(OutBuf, uint8_t, GS_CLNT_ARBITRARY_PACKET_MAX);

	GS_ALLOCA_VAR(DataBuf, uint8_t, GS_CLNT_ARBITRARY_PACKET_MAX);
	size_t DataSize = GS_CLNT_ARBITRARY_PACKET_MAX;
	size_t LenData = 0;

	if (!!(r = gs_vserv_clnt_ctx_get(Clnt, &Ctx)))
		GS_GOTO_CLEAN();

	if (Ctx->mRenamer.mNameWant.size() && Ctx->mRenamer.mServWant.size()) {
		if (Ctx->mRenamer.mTimeStampLastRequested + GS_CLNT_ARBITRARY_IDENT_RESEND_TIMEOUT > TimeStamp) {
			const struct GsRenamer &Renamer = Ctx->mRenamer;

			/* emit ident */

			if (gs_packet_space(&PacketOut, 0, 1 /*cmd*/ + 4 /*rand*/ + 4 /*lenname*/ + 4 /*lenserv*/ + Renamer.mNameWant.size() /*name*/ + Renamer.mServWant.size() /*serv*/))
				GS_ERR_CLEAN(1);

			gs_write_byte(OutBuf + 0, GS_VSERV_CMD_IDENT_FIXME);
			gs_write_uint(OutBuf + 1, Renamer.mRandLastRequested);
			gs_write_uint(OutBuf + 5, Renamer.mNameWant.size());
			gs_write_uint(OutBuf + 9, Renamer.mServWant.size());
			memcpy(OutBuf + 13 + 0, Renamer.mNameWant.data(), Renamer.mNameWant.size());
			memcpy(OutBuf + 13 + Renamer.mNameWant.size(), Renamer.mServWant.data(), Renamer.mServWant.size());

			/* update packet with final length */

			PacketOut.dataLength = 13 + Renamer.mNameWant.size() + Renamer.mServWant.size();

			if (!!(r = gs_vserv_clnt_send(Clnt, PacketOut.data, PacketOut.dataLength)))
				GS_GOTO_CLEAN();

			Ctx->mRenamer.mTimeStampLastRequested = TimeStamp;
		}
	}

	/* -1 return code aliasing error and lack-of-progress conditions.. nice api minetest */
	while (-1 != (LenData = Clnt->mSocket->Receive(Addr, DataBuf, DataSize))) {
		struct GsPacket Packet = { DataBuf, DataSize }; /*notowned*/
		GS_LOG(I, S, "gs_vserv_clnt_callback_update_other receive");
		if (!!(r = gs_vserv_clnt_crank0(Clnt, Ctx, TimeStamp, &Packet)))
			GS_GOTO_CLEAN();
	}

clean:

	return r;
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
