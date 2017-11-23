#ifndef _VSERV_PLAYBACK_H_
#define _VSERV_PLAYBACK_H_

#define GS_PLAYBACK_FLOW_DELAY_EXPIRY_MS (GS_OPUS_FRAME_DURATION_20MS * 3) /* three opus frames */
#define GS_PLAYBACK_FLOW_DELAY_MS 50
/* https://www.reddit.com/r/Planetside/comments/1e9z36/two_ini_lines_that_gave_me_a_massive_boost_to_fps/
     have not profiled CPU use yet but logically having many simultaneous 'voice' / audio flows must impact performance */
#define GS_PLAYBACK_FLOWS_NUM 4
#define GS_PLAYBACK_FLOW_BUFS_NUM 8
#define GS_OPUS_FRAME_DURATION_20MS 20

struct GsPlayBackFlowKey;
struct GsPlayBackFlow;
struct GsPlayBackId;
struct GsPlayBack;

/* represents buffer from to: mDataPtr + mDataOffset + [0, mLenData]  */
struct GsPlayBackBuf
{
	uint8_t *mDataPtr; size_t mLenData;
	size_t mDataOffset;

	int(*mCbDataDestroy)(uint8_t *DataPtr);
};

int gs_playback_buf_create_copying(
	uint8_t *DataBuf, size_t LenData,
	struct GsPlayBackBuf **oPBBuf);
int gs_playback_buf_destroy(struct GsPlayBackBuf *PBBuf);

int gs_playback_create(
struct GsPlayBack **oPlayBack,
	size_t FlowsNum,
	size_t FlowBufsNum);
int gs_playback_destroy(struct GsPlayBack *PlayBack);
int gs_playback_packet_insert(
	struct GsPlayBack *PlayBack,
	long long TimeStamp,
	uint16_t Id,
	uint16_t Blk,
	uint16_t Seq,
	struct GsPlayBackBuf *PBBuf /*owned*/);
int gs_playback_stacks_check(struct GsPlayBack *PlayBack);
int gs_playback_recycle(struct GsPlayBack *PlayBack);
int gs_playback_harvest(
	struct GsPlayBack *PlayBack,
	long long TimeStamp,
	size_t VecNum, /* length for all three vecs */
	struct GsPlayBackFlowKey *FlowsVec,
	struct GsPlayBackBuf ***ioSlotsVec, /*notowned*/
	size_t                 *ioCountVec /*notowned*/);
int gs_playback_harvest_and_enqueue(
	struct GsPlayBack *PlayBack,
	long long TimeStamp);
int gs_playback_ensure_playing(struct GsPlayBack *PlayBack);
int gs_playback_affinity_process(struct GsPlayBack *PlayBack, long long TimeStamp);
int gs_playback_affinity_flow_liveness(
	struct GsPlayBack *PlayBack,
	long long TimeStamp,
	const struct GsPlayBackFlowKey *Key,
	int *oAlive);

#endif /* _VSERV_PLAYBACK_H_ */
