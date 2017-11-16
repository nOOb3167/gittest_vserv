#include <cstdlib>

#include <thread>
#include <chrono>
#include <string>
#include <deque>

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

#define GS_RECORD_BUFFERS_NUM 8
#define GS_RECORD_ARBITRARY_BUFFER_SAMPLES_NUM 48000

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

		if (! WaitData(10))
			return -1;

		struct sockaddr_in SockAddr = {};
		int SockAddrLen = sizeof SockAddr;
		int NRecv = 0;

		if (SOCKET_ERROR == (NRecv = recvfrom(mHandle, (char *) Data, Size, 0, (struct sockaddr *) &SockAddr, &SockAddrLen)))
			GS_ERR_CLEAN(1);
		if (SockAddrLen != sizeof SockAddr)
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
	size_t FraSize,
	size_t BlkNumFra,
	char *ioBlkBuf, size_t BlkBufSize, size_t *oLenBlkBuf,
	size_t *oNumBlkProcessed)
{
	int r = 0;

	/*
	* OpenAL alcGetIntegerv exposes the count of new samples arrived, but not yet delivered via alcCaptureSamples.
	*   this count grows during an ongoing capture (ex started via alcCaptureStart).
	* we want samples delivered in blocks of certain size.
	*   (the size of an Opus frame, see calculation of 'OpBlkNumFra'.
	*    note Opus frame is termed block in this function.
	*    Opus supports only specific Opus frame sizes.
	*    https://wiki.xiph.org/Opus_Recommended_Settings : Quote "Opus can encode frames of 2.5, 5, 10, 20, 40, or 60 ms.")
	* if this function keeps getting called during an ongoing capture, alcGetIntegerv eventually will report enough samples to fill an Opus frame.
	*   those samples are candidate for draining via alcCaptureSamples
	*/

	// FIXME: apply fix once opus becomes used
	typedef ALshort should_be_opus_int16_tho;

	/* Bl(oc)k: [Fra,..]   # one Opus frame worth of blocks
	 * Fra(me): [Samp,..]  # one sample for every channel; 1 channel is hardcoded therefore 1 Sample
	 * Samp(le): [INT16] # MONO16 format is hardcoded therefore sample is an opus_int16 aka ALshort
	 *
	 * property of a 1 channel frame being equivalent to a single sample will be used
	 * (ex passing frame counts into OpenAL functions expecting sample counts) */

	const size_t AlFraSize = sizeof(ALshort) /*AL_FORMAT_MONO16*/ * 1 /*numchannels*/;
	const size_t OpFraSize = sizeof(should_be_opus_int16_tho) /*opus_encode API doc*/ * 1 /*numchannels*/;
	GS_ASSERT(AlFraSize == OpFraSize);
	const size_t OpBlkNumFra = (48000 / 1000) /*samples/msec*/ * 20 /*20ms (one Opus frame)*/;
	const size_t OpBlkSize = OpBlkNumFra * OpFraSize;
	GS_ASSERT(OpFraSize == FraSize);
	GS_ASSERT(OpBlkNumFra == BlkNumFra);

	size_t BlkNum = 0;

	ALCint NumAvailFra = 0;
	size_t NumAvailBlk = 0;
	size_t NumAvailBuf = 0;
	size_t NumBlkToProcess = 0;

	alcGetIntegerv(Record->mCapDevice, ALC_CAPTURE_SAMPLES, 1, &NumAvailFra);

	GS_NOALERR();

	NumAvailBlk = (NumAvailFra / OpBlkNumFra); /*truncating division*/
	NumAvailBuf = (BlkBufSize / OpBlkSize);    /*truncating division*/
	NumBlkToProcess = GS_MIN(NumAvailBuf, NumAvailBlk);

	if (NumBlkToProcess == 0)
		GS_ERR_NO_CLEAN(0);

	alcCaptureSamples(Record->mCapDevice, ioBlkBuf, NumBlkToProcess * OpBlkNumFra);

	GS_NOALERR();

noclean:
	if (oLenBlkBuf)
		*oLenBlkBuf = NumBlkToProcess * OpBlkSize;
	if (oNumBlkProcessed)
		*oNumBlkProcessed = NumBlkToProcess;

clean:

	return r;
}

struct GsVServClnt
{
	struct GsVServClntCtx *mCtx;
	sp<UDPSocket> mSocket;
	sp<std::thread> mThread;
	struct GsVServClntAddress mAddr;
	struct GsRecord *mRecord;
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

void threadfunc(struct GsVServClnt *Clnt)
{
	int r = 0;

	while (true) {
		char DataBuf[65535];
		int LenData = 0;
		struct GsVServClntAddress AddrRecv = {};
		if (! Clnt->mSocket->WaitData(10))
			continue;
		if (!!(r = gs_vserv_clnt_callback_update(Clnt)))
			GS_GOTO_CLEAN();
	}

clean:
	if (!!r)
		GS_ASSERT(0);
}

int stuff(int argc, char **argv)
{
	int r = 0;

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
