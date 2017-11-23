#include <cstddef>

#include <AL/al.h>
#include <AL/alc.h>

#include <gittest/misc.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_record.h>

int gs_record_create(struct GsRecord **oRecord)
{
	int r = 0;

	struct GsRecord *Record = NULL;

	ALCdevice *CapDevice = NULL;

	GS_ASSERT(alcGetCurrentContext() != NULL);

	if (!(CapDevice = alcCaptureOpenDevice(NULL, GS_48KHZ, AL_FORMAT_MONO16, GS_RECORD_ARBITRARY_BUFFER_SAMPLES_NUM)))
		GS_GOTO_CLEAN();

	GS_NOALERR();

	Record = new GsRecord();
	Record->mCapDevice = GS_ARGOWN(&CapDevice);

	if (oRecord)
		*oRecord = GS_ARGOWN(&Record);

clean:
	if (CapDevice)
		if (! alcCaptureCloseDevice(CapDevice))
			GS_ASSERT(0);
	GS_DELETE_F(&Record, gs_record_destroy);

	return r;
}

int gs_record_destroy(struct GsRecord *Record)
{
	if (Record) {
		if (Record->mCapDevice)
			if (! alcCaptureCloseDevice(Record->mCapDevice))
				GS_ASSERT(0);
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
