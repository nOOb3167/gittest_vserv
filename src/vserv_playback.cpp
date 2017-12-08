#ifdef _MSC_VER
#pragma warning(disable : 4267 4102)  // conversion from size_t, unreferenced label
#endif /* _MSC_VER */

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <memory>
#include <utility>
#include <map>
#include <set>

#include <AL/al.h>
#include <AL/alc.h>

#include <gittest/misc.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_playback.h>

#define GS_AL_BUFFER_INVALID 0xFFFFFFFF

// FIXME: temp global data
uint8_t BufSilenceDummy[2 * (GS_48KHZ / 1000 * GS_OPUS_FRAME_DURATION_20MS)] = {};
struct GsPlayBackBuf PBBufSilenceDummy = { BufSilenceDummy, 2 * (GS_48KHZ / 1000 * GS_OPUS_FRAME_DURATION_20MS), 0, NULL };

struct GsPlayBackFlowKey
{
	uint16_t mId;
	uint16_t mBlk;
};

struct gs_playback_flow_key_less_t
{
	bool operator()(const GsPlayBackFlowKey &a, const GsPlayBackFlowKey &b) const
		{ return a.mId != b.mId ? (a.mId < b.mId) : (a.mBlk < b.mBlk); }
};

typedef std::set<struct GsPlayBackFlowKey, gs_playback_flow_key_less_t> gs_playback_affinity_t;

struct GsPlayBackFlow
{
	/* Seq -> Buf */
	std::map<uint16_t, sp<GsPlayBackBuf> > mMapBuf;
	long long mTimeStampFirstReceipt;
	size_t mNextSeq;
};

struct GsPlayBackId
{
	uint16_t mBlkFloor;
};

struct GsPlayBack
{
	size_t mFlowsNum; /* length for Source, StackCnt, BufferStack vecs */
	size_t mFlowBufsNum;

	std::map<GsPlayBackFlowKey, GsPlayBackFlow, gs_playback_flow_key_less_t> mMapFlow;
	std::map<uint16_t, GsPlayBackId> mMapId;

	ALuint *mSourceVec;
	size_t  *mStackCntVec;
	ALuint **mBufferStackVec;

	gs_playback_affinity_t mAffinity;
};

static int gs_playback_buf_data_destroy_free(uint8_t *DataPtr);

int gs_playback_buf_data_destroy_free(uint8_t *DataPtr)
{
	free(DataPtr);
	return 0;
}

int gs_playback_buf_create_copying(
	uint8_t *DataBuf, size_t LenData,
	struct GsPlayBackBuf **oPBBuf)
{
	int r = 0;

	struct GsPlayBackBuf *PBBuf = NULL;

	uint8_t *CpyBuf = NULL;
	
	if (!(CpyBuf = (uint8_t *)malloc(LenData)))
		GS_ERR_CLEAN(1);
	memcpy(CpyBuf, DataBuf, LenData);

	PBBuf = new GsPlayBackBuf();
	PBBuf->mDataPtr = GS_ARGOWN(&CpyBuf);
	PBBuf->mLenData = LenData;
	PBBuf->mDataOffset = 0;
	PBBuf->mCbDataDestroy = gs_playback_buf_data_destroy_free;

	if (oPBBuf)
		*oPBBuf = GS_ARGOWN(&PBBuf);

clean:
	free(CpyBuf);
	GS_DELETE_F(&PBBuf, gs_playback_buf_destroy);

	return r;
}

int gs_playback_buf_destroy(struct GsPlayBackBuf *PBBuf)
{
	if (PBBuf) {
		if (!! PBBuf->mCbDataDestroy(PBBuf->mDataPtr))
			GS_ASSERT(0);
		GS_DELETE(&PBBuf, struct GsPlayBackBuf);
	}
	return 0;
}

int gs_playback_create(
	struct GsPlayBack **oPlayBack,
	size_t FlowsNum,
	size_t FlowBufsNum)
{
	int r = 0;

	struct GsPlayBack *PlayBack = NULL;

	ALuint  *SourceVec = NULL;
	size_t  *StackCntVec = NULL;
	ALuint **BufferStackVec = NULL;

	SourceVec = new ALuint[FlowsNum];
	StackCntVec = new (size_t[FlowsNum]);
	BufferStackVec = new ALuint*[FlowsNum];

	for (size_t i = 0; i < FlowsNum; i++)
		StackCntVec[i] = FlowBufsNum;

	for (size_t i = 0; i < FlowsNum; i++) {
		BufferStackVec[i] = new ALuint[FlowBufsNum];
		for (size_t j = 0; j < FlowBufsNum; j++)
			BufferStackVec[i][j] = GS_AL_BUFFER_INVALID;
	}

	PlayBack = new GsPlayBack();
	PlayBack->mFlowsNum = FlowsNum;
	PlayBack->mFlowBufsNum = FlowBufsNum;
	PlayBack->mMapFlow; /*dummy*/
	PlayBack->mMapId; /*dummy*/
	PlayBack->mSourceVec = GS_ARGOWN(&SourceVec);
	PlayBack->mStackCntVec = GS_ARGOWN(&StackCntVec);
	PlayBack->mBufferStackVec = GS_ARGOWN(&BufferStackVec);
	PlayBack->mAffinity; /*dummy*/

	GS_ASSERT(alcGetCurrentContext() != NULL);

	alGenSources(PlayBack->mFlowsNum, PlayBack->mSourceVec);
	GS_NOALERR();
	for (size_t i = 0; i < FlowsNum; i++)
		alGenBuffers(PlayBack->mFlowBufsNum, PlayBack->mBufferStackVec[i]);
	GS_NOALERR();

	if (oPlayBack)
		*oPlayBack = GS_ARGOWN(&PlayBack);

clean:
	GS_DELETE_ARRAY(&SourceVec, ALuint);
	GS_DELETE_ARRAY(&StackCntVec, size_t);
	if (BufferStackVec)
		for (size_t i = 0; i < FlowsNum; i++)
			GS_DELETE_ARRAY(&BufferStackVec[i], ALuint);
	GS_DELETE_ARRAY(&BufferStackVec, ALuint *);

	GS_DELETE_F(&PlayBack, gs_playback_destroy);

	return r;
}

int gs_playback_destroy(struct GsPlayBack *PlayBack)
{
	// FIXME: destroying sources and buffers is trickier, right? undefined behaviour if any buffers queued?
	if (PlayBack) {
		GS_DELETE_ARRAY(&PlayBack->mSourceVec, ALuint);
		GS_DELETE_ARRAY(&PlayBack->mStackCntVec, size_t);
		if (PlayBack->mBufferStackVec)
			for (size_t i = 0; i < PlayBack->mFlowsNum; i++)
				GS_DELETE_ARRAY(&PlayBack->mBufferStackVec[i], ALuint);
		GS_DELETE_ARRAY(&PlayBack->mBufferStackVec, ALuint *);
		GS_DELETE(&PlayBack, struct GsPlayBack);
	}

	return 0;
}

int gs_playback_packet_insert(
	struct GsPlayBack *PlayBack,
	long long TimeStamp,
	uint16_t Id,
	uint16_t Blk,
	uint16_t Seq,
	struct GsPlayBackBuf *PBBuf /*owned*/)
{
	int r = 0;

	const struct GsPlayBackFlowKey Key = { Id, Blk };

	auto itId = PlayBack->mMapId.find(Id);

	if (itId == PlayBack->mMapId.end()) {
		struct GsPlayBackId PBId;
		PBId.mBlkFloor = 0;
		itId = (PlayBack->mMapId.insert(std::make_pair(Id, std::move(PBId)))).first;
	}

	if (Blk < itId->second.mBlkFloor)
		GS_ERR_NO_CLEAN(0);

	{
		auto it1 = PlayBack->mMapFlow.find(Key);

		if (it1 == PlayBack->mMapFlow.end()) {
			/* this is the first packet seen from this flow */
			if (Seq > GS_PLAYBACK_FLOW_LEADING_SEQUENCE_LOSS_THRESHOLD) {
				/* if such a first packet arrives with a high Seq number
				   we can assume the earlier Seq got lost, somehow otherwise will not be arriving,
				   or at the very least be severely outdated the moment they would of been received.
				   ATM the known non-failure path known to cause such high Seq number is
				   a client connecting to the voice server during an ongoing long-running
				   flow. The client, having just connected, is guaranteed to miss the
				   earlier Seq. First packet received of the long-running flow will have high Seq.
				   Two ways of handling such high Seq scenarios were considered:
				     - play the flow as usual (low Seq considered packet-loss)
					   leads to a severe time lag between recording and eventual playback of the affected flow.
					 - drop the flow
					   ''cant have time lag if you aint ever playing the flow :>''
					   potentially discards perfectly usable data (rest of the long-running flow)
					Current handling implemented as drop the flow.
				   */
				GS_ERR_NO_CLEAN(0);
			}
			else {
				struct GsPlayBackFlow PBFlow;
				PBFlow.mMapBuf; /*dummy*/
				PBFlow.mTimeStampFirstReceipt = TimeStamp;
				PBFlow.mNextSeq = 0;
				it1 = (PlayBack->mMapFlow.insert(std::make_pair(Key, std::move(PBFlow)))).first;
			}
		}

		auto it2 = it1->second.mMapBuf.find(Seq);

		if (it2 == it1->second.mMapBuf.end()) {
			sp<GsPlayBackBuf> PBBuf(GS_ARGOWN(&PBBuf), gs_playback_buf_destroy);
			it2 = (it1->second.mMapBuf.insert(std::make_pair(Seq, std::move(PBBuf)))).first;
		}
	}

noclean:

clean:
	GS_DELETE_F(&PBBuf, gs_playback_buf_destroy);

	return r;
}

int gs_playback_stacks_check(struct GsPlayBack *PlayBack)
{
	int r = 0;

	for (size_t i = 0; i < PlayBack->mFlowsNum; i++) {
		std::set<ALuint> UniqSet;
		if (PlayBack->mStackCntVec[i] > PlayBack->mFlowBufsNum)
			GS_ERR_CLEAN(1);
		for (size_t j = 0; j < PlayBack->mStackCntVec[i]; j++)
			UniqSet.insert(PlayBack->mBufferStackVec[i][j]);
		if (UniqSet.size() != PlayBack->mStackCntVec[i])
			GS_ERR_CLEAN(1);
		for (size_t j = PlayBack->mStackCntVec[i]; j < PlayBack->mFlowBufsNum; j++)
			if (PlayBack->mBufferStackVec[i][j] != GS_AL_BUFFER_INVALID)
				GS_ERR_CLEAN(1);
	}

clean:

	return r;
}

int gs_playback_recycle(struct GsPlayBack *PlayBack)
{
	int r = 0;

	for (size_t i = 0; i < PlayBack->mFlowsNum; i++) {
		ALint NumProcessed = 0;
		alGetSourcei(PlayBack->mSourceVec[i], AL_BUFFERS_PROCESSED, &NumProcessed);
		GS_NOALERR();
		/* can accept NumProcessed buffers? */
		GS_ASSERT(PlayBack->mStackCntVec[i] + NumProcessed <= PlayBack->mFlowBufsNum);
		/* transfer NumProcessed buffers from OpenAL source to BufferStackVec */
		alSourceUnqueueBuffers(PlayBack->mSourceVec[i], NumProcessed, &PlayBack->mBufferStackVec[i][PlayBack->mStackCntVec[i]]);
		GS_NOALERR();
		PlayBack->mStackCntVec[i] += NumProcessed;
	}

	GS_ASSERT(! gs_playback_stacks_check(PlayBack));

clean:

	return r;
}

int gs_playback_harvest(
	struct GsPlayBack *PlayBack,
	long long TimeStamp,
	size_t VecNum, /* length for all three vecs */
	struct GsPlayBackFlowKey *FlowsVec, /*notowned*/
	struct GsPlayBackBuf ***ioSlotsVec, /*notowned*/
	size_t                 *ioCountVec /*notowned*/)
{
	int r = 0;

	for (size_t i = 0; i < VecNum; i++)
		for (size_t j = 0; j < PlayBack->mFlowBufsNum; j++)
			ioSlotsVec[i][j] = NULL;

	for (size_t i = 0; i < VecNum; i++) {
		const size_t InCount = ioCountVec[i];
		ioCountVec[i] = 0;
		auto itFlow = PlayBack->mMapFlow.find(FlowsVec[i]);
		auto itId = PlayBack->mMapId.find(FlowsVec[i].mId);
		// FIXME: have a way to signal inexistent flow? or different func which caller checks with
		if (itFlow == PlayBack->mMapFlow.end() || itId == PlayBack->mMapId.end())
			continue;
		const long long FlowPlayBackStartTime = itFlow->second.mTimeStampFirstReceipt + GS_PLAYBACK_FLOW_DELAY_MS;
		if (TimeStamp < FlowPlayBackStartTime)
			continue;
		const uint16_t SeqCurrentTime = (TimeStamp - FlowPlayBackStartTime) / GS_OPUS_FRAME_DURATION_20MS;
		GS_ASSERT(itFlow->second.mNextSeq <= SeqCurrentTime);
		const size_t Count = GS_MIN(InCount, SeqCurrentTime - itFlow->second.mNextSeq);
		for (size_t j = 0; j < Count; j++) {
			struct GsPlayBackBuf * PBBuf = NULL;
			auto itBuf = itFlow->second.mMapBuf.find(itFlow->second.mNextSeq + j);
			if (itBuf != itFlow->second.mMapBuf.end())
				PBBuf = itBuf->second.get();
			ioSlotsVec[i][j] = PBBuf;
			ioCountVec[i]++;
		}
		itFlow->second.mNextSeq += Count;
	}

clean:
	
	return r;
}

int gs_playback_harvest_and_enqueue(
	struct GsPlayBack *PlayBack,
	long long TimeStamp)
{
	int r = 0;

	GS_ALLOCA_VAR(SlotsPtrVec, GsPlayBackBuf **, PlayBack->mFlowsNum);
	GS_ALLOCA_VAR(SlotsVec, GsPlayBackBuf *, PlayBack->mFlowsNum * PlayBack->mFlowBufsNum);
	GS_ALLOCA_VAR(CountVec, size_t, PlayBack->mFlowsNum);

	GS_ALLOCA_VAR(FlowKeysVec, GsPlayBackFlowKey, PlayBack->mFlowsNum);

	size_t FlowsToHarvestNum = 0;

	for (auto it = PlayBack->mAffinity.begin(); it != PlayBack->mAffinity.end(); ++it)
		FlowKeysVec[FlowsToHarvestNum++] = *it;
	GS_ASSERT(FlowsToHarvestNum <= PlayBack->mFlowsNum);

	for (size_t i = 0; i < FlowsToHarvestNum; i++)
		SlotsPtrVec[i] = SlotsVec + (PlayBack->mFlowBufsNum * i);

	for (size_t i = 0; i < FlowsToHarvestNum; i++)
		CountVec[i] = PlayBack->mStackCntVec[i];

	// FIXME: somehow need to make sure that buffers received through gs_playback_harvest are not destroyed while in use
	//        currently this is done by just not modifying the mMapBuf inside the GsPlayBackFlow structures

	if (!!(r = gs_playback_harvest(PlayBack, TimeStamp, FlowsToHarvestNum, FlowKeysVec, SlotsPtrVec, CountVec)))
		GS_GOTO_CLEAN();

	for (size_t i = 0; i < FlowsToHarvestNum; i++) {
		GS_ASSERT(CountVec[i] <= PlayBack->mStackCntVec[i]);
		/* transfer CountVec[i] GsPlayBackBufs into OpenAL buffers and queue them */
		for (size_t j = 0; j < CountVec[i]; j++) {
			struct GsPlayBackBuf *PBBuf = SlotsPtrVec[i][j];
			if (PBBuf == NULL)
				PBBuf = &PBBufSilenceDummy;
			ALuint BufferForPlayBack = PlayBack->mBufferStackVec[i][(PlayBack->mStackCntVec[i] - 1) - j];
			alBufferData(BufferForPlayBack, AL_FORMAT_MONO16, PBBuf->mDataPtr + PBBuf->mDataOffset, PBBuf->mLenData, GS_48KHZ);
			GS_NOALERR();
			alSourceQueueBuffers(PlayBack->mSourceVec[i], 1, &BufferForPlayBack);
			GS_NOALERR();
		}
		/* sentinel-ize the transferred BufferStackVec entries */
		for (size_t j = 0; j < CountVec[i]; j++)
			PlayBack->mBufferStackVec[i][(PlayBack->mStackCntVec[i] - 1) - j] = GS_AL_BUFFER_INVALID;
		PlayBack->mStackCntVec[i] -= CountVec[i];
	}

clean:

	return r;
}

int gs_playback_ensure_playing(struct GsPlayBack *PlayBack)
{
	int r = 0;

	// FIXME: be smarter and only try to play sources which had any buffers queued
	//   higher level code would be the place to have this information presumably

	for (size_t i = 0; i < PlayBack->mFlowsNum; i++) {
		ALint State = 0;

		alGetSourcei(PlayBack->mSourceVec[i], AL_SOURCE_STATE, &State);
		GS_NOALERR();

		if (State != AL_PLAYING) {
			alSourcePlay(PlayBack->mSourceVec[i]);
			GS_NOALERR();
		}
	}

clean:

	return r;
}

int gs_playback_affinity_process(struct GsPlayBack *PlayBack, long long TimeStamp)
{
	int r = 0;

	/* drop expired flows */

	for (auto it = PlayBack->mAffinity.begin(); it != PlayBack->mAffinity.end();) {
		int Alive = 0;
		if (!!(r = gs_playback_affinity_flow_liveness(PlayBack, TimeStamp, &*it, &Alive)))
			GS_GOTO_CLEAN();
		if (Alive) {
			/*keep*/
			++it;
		}
		else {
			/*drop*/
			struct GsPlayBackFlowKey Key = { it->mId, it->mBlk };
			auto itFlow = PlayBack->mMapFlow.find(Key);
			auto itId = PlayBack->mMapId.find(it->mId);
			GS_ASSERT(itFlow != PlayBack->mMapFlow.end());
			GS_ASSERT(itId != PlayBack->mMapId.end());
			PlayBack->mMapFlow.erase(Key);
			// FIXME: the correct time for removal of mMapId[Id] is after disconnection of user Id,
			//        and before Id gets recycled for a new connection.
			//        ex even if all flows with keys mId=Id are gone from mMapFlow are gone
			//          more such flows could arrive in the future. if mMapId[Id] were removed,
			//          its former state would be lost.
			//// PlayBack->mMapId.erase(it->mId);
			it = PlayBack->mAffinity.erase(it);
		}
	}

	/* fill for up to max flows */

	for (auto it = PlayBack->mMapFlow.begin(); it != PlayBack->mMapFlow.end() && PlayBack->mAffinity.size() < PlayBack->mFlowsNum; ++it) {
		if (PlayBack->mAffinity.find(it->first) != PlayBack->mAffinity.end())
			continue;
		PlayBack->mAffinity.insert(it->first);
	}

clean:

	return r;
}

int gs_playback_affinity_flow_liveness(
	struct GsPlayBack *PlayBack,
	long long TimeStamp,
	const struct GsPlayBackFlowKey *Key,
	int *oAlive)
{
	int r = 0;

	int Alive = 0;

	auto itFlow = PlayBack->mMapFlow.find(*Key);

	do {
		/* cant be alive if it aint there */
		if (itFlow == PlayBack->mMapFlow.end())
			{ Alive = 0; break; }
		const long long FlowPlayBackStartTime = itFlow->second.mTimeStampFirstReceipt + GS_PLAYBACK_FLOW_DELAY_MS;
		/* cant be dead it if it aint ever even given a chance to get goin */
		if (TimeStamp < FlowPlayBackStartTime)
			{ Alive = 1; break; }
		const uint16_t SeqCurrentTime = (TimeStamp - FlowPlayBackStartTime) / GS_OPUS_FRAME_DURATION_20MS;
		const auto itLastReceived = itFlow->second.mMapBuf.rbegin();
		/* check if the flow expired (ie we postulate further packets will either not arrive,
		   or arrive and be too late (ex if we're past 5s into playing a flow and receive a packet
		   carrying data from 1 to 1.050s it is too late to play).
		   
		   currently the code count a flow as expired if:
		     - we are (time-wise) sufficiently past the last arrived/received packet in the flow
			 - or, should none have arrived, we are sufficiently past the playback start time of that flow
		   sufficiently behind meaning GS_PLAYBACK_FLOW_DELAY_EXPIRY_MS or more msec of delay */
		long long ExpiryComparisonStartTime = FlowPlayBackStartTime;
		if (itLastReceived != itFlow->second.mMapBuf.rend()) {
			const uint16_t  SeqLastReceived  = itLastReceived->first;
			const long long SeqLastReceivedStartTimeOffset = SeqLastReceived * GS_OPUS_FRAME_DURATION_20MS;
			ExpiryComparisonStartTime += SeqLastReceivedStartTimeOffset;
		}
		ExpiryComparisonStartTime += GS_PLAYBACK_FLOW_DELAY_EXPIRY_MS;
		if (ExpiryComparisonStartTime < TimeStamp)
			{ Alive = 0; break; }
		/* all liveness checks passed, the flow is alive */
		Alive = 1;
	} while (0);

noclean:

	if (oAlive)
		*oAlive = Alive;

clean:

	return r;
}
