#ifndef _VSERV_RECORD_H_
#define _VSERV_RECORD_H_

#include <stdint.h>

#include <AL/al.h>
#include <AL/alc.h>

#define GS_RECORD_BUFFERS_NUM 8
#define GS_RECORD_ARBITRARY_BUFFER_SAMPLES_NUM 48000

#define GS_OPUS_FRAME_48KHZ_20MS_SAMP_NUM ((48000 / 1000) /*samples/msec*/ * 20 /*20ms (one Opus frame)*/)

struct GsRecord
{
	ALCdevice *mCapDevice;
};

int gs_record_create(struct GsRecord **oRecord);
int gs_record_destroy(struct GsRecord *Record);
int gs_record_start(struct GsRecord *Record);
int gs_record_stop(struct GsRecord *Record);
int gs_record_capture_drain(
	struct GsRecord *Record,
	size_t SampSize,
	size_t FraNumSamp,
	uint8_t *ioFraBuf, size_t FraBufSize, size_t *oLenFraBuf,
	size_t *oNumFraProcessed);

#endif /* _VSERV_RECORD_H_ */
