#include <cstddef>

#include <deque>

#include <AL/al.h>
#include <AL/alc.h>

#include <gittest/misc.h>
#include <gittest/vserv_record.h>

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
