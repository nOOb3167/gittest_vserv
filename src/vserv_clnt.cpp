#include <cstddef>
#include <cstdint>
#include <cstring>

#include <string>
#include <set>
#include <random>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_record.h>
#include <gittest/vserv_playback.h>
#include <gittest/vserv_clnt.h>

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
	struct GsRecord   *mRecord;
	struct GsPlayBack *mPlayBack;
};

static bool gs_renamer_is_wanted(struct GsRenamer *Renamer);
static int gs_renamer_ident_emit(struct GsRenamer *Renamer, struct GsPacket *ioPacket);
int gs_renamer_update(struct GsRenamer *Renamer, struct GsVServClnt *Clnt, long long TimeStamp);
static int gs_vserv_clnt_crank0(
	struct GsVServClnt *Clnt,
	struct GsVServClntCtx *Ctx,
	long long TimeStamp,
	struct GsPacket *Packet);

bool gs_renamer_is_wanted(struct GsRenamer *Renamer)
{
	GS_ASSERT(Renamer->mNameWant.empty() == Renamer->mServWant.empty());
	return ! Renamer->mNameWant.empty() && ! Renamer->mServWant.empty();
}

int gs_renamer_ident_emit(struct GsRenamer *Renamer, struct GsPacket *ioPacket)
{
	int r = 0;

	GS_ASSERT(gs_renamer_is_wanted(Renamer));

	if (gs_packet_space(ioPacket, 0, 1 /*cmd*/ + 4 /*rand*/ + 4 /*lenname*/ + 4 /*lenserv*/ + Renamer->mNameWant.size() /*name*/ + Renamer->mServWant.size() /*serv*/))
		GS_ERR_CLEAN(1);

	gs_write_byte(ioPacket->data + 0, GS_VSERV_CMD_IDENT_FIXME);
	gs_write_uint(ioPacket->data + 1, Renamer->mRandLastRequested);
	gs_write_uint(ioPacket->data + 5, Renamer->mNameWant.size());
	gs_write_uint(ioPacket->data + 9, Renamer->mServWant.size());
	memcpy(ioPacket->data + 13 + 0                        , Renamer->mNameWant.data(), Renamer->mNameWant.size());
	memcpy(ioPacket->data + 13 + Renamer->mNameWant.size(), Renamer->mServWant.data(), Renamer->mServWant.size());

	/* update packet with final length */

	ioPacket->dataLength = 13 + Renamer->mNameWant.size() + Renamer->mServWant.size();

clean:

	return r;
}

int gs_renamer_update(struct GsRenamer *Renamer, struct GsVServClnt *Clnt, long long TimeStamp)
{
	int r = 0;

	GS_ALLOCA_VAR(OutBuf, uint8_t, GS_CLNT_ARBITRARY_PACKET_MAX);
	struct GsPacket Packet = { OutBuf, GS_CLNT_ARBITRARY_PACKET_MAX };

	/* no update work needed at all */

	if (! gs_renamer_is_wanted(Renamer))
		GS_ERR_NO_CLEAN(0);

	/* update work needed - but not yet */

	if (TimeStamp < Renamer->mTimeStampLastRequested + GS_CLNT_ARBITRARY_IDENT_RESEND_TIMEOUT)
		GS_ERR_NO_CLEAN(0);

	/* update work - send / resent the ident message */

	if (!!(r = gs_renamer_ident_emit(Renamer, &Packet)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_clnt_send(Clnt, Packet.data, Packet.dataLength)))
		GS_GOTO_CLEAN();

	Renamer->mTimeStampLastRequested = TimeStamp;

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

	GS_LOG(I, PF, "pkt [cmd=%c]", (int)Packet->data[0]);

	switch (Packet->data[0]) {

	case GS_VSERV_CMD_IDENT_ACK_FIXME:
	{
		/* (cmd)[1], (rand)[4], (id)[2] */

		size_t Offset = 0;

		uint32_t Rand = 0;
		uint32_t Id = GS_VSERV_USER_ID_SERVFILL_FIXME;

		if (gs_packet_space(Packet, (Offset += 1), 4 /*rand*/ + 2 /*id*/))
			GS_ERR_CLEAN_J(ident_ack, 1);

		Rand = gs_read_uint(Packet->data + Offset + 0);
		Id = gs_read_short(Packet->data + Offset + 4);

		/* unsolicited or reliability-codepath (ex re-sent or reordered packet) GS_VSERV_CMD_IDENT_ACK */

		if (! gs_renamer_is_wanted(&Ctx->mRenamer))
			GS_ERR_NO_CLEAN_J(ident_ack, 0);
		if (Rand != Ctx->mRenamer.mRandLastRequested)
			GS_ERR_NO_CLEAN_J(ident_ack, 0);

		/* seems legit, apply */

		Ctx->mName.mName = Ctx->mRenamer.mNameWant;
		Ctx->mName.mServ = Ctx->mRenamer.mServWant;
		Ctx->mName.mId = Id;

		/* reset renamer */

		Ctx->mRenamer.mNameWant.clear();
		Ctx->mRenamer.mServWant.clear();

	noclean_ident_ack:

	clean_ident_ack:
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	case GS_VSERV_CMD_GROUP_MODE_MSG_FIXME:
	{
		/* (cmd)[1], (mode)[1], (id)[2], (blk)[2], (seq)[2], (data)[...] */

		size_t Offset = 0;

		uint8_t Mode = 0;
		uint16_t Id = 0;
		uint16_t Blk = 0;
		uint16_t Seq = 0;

		struct GsPlayBackBuf *PBBuf = NULL;

		if (gs_packet_space(Packet, (Offset += 1), 1 /*mode*/ + 2 /*id*/ + 2 /*blk*/ + 2 /*seq*/))
			GS_ERR_CLEAN_J(groupmodemsg, 1);

		Mode = gs_read_byte(Packet->data + Offset);
		Id = gs_read_short(Packet->data + Offset + 1);
		Blk = gs_read_short(Packet->data + Offset + 3);
		Seq = gs_read_short(Packet->data + Offset + 5);

		// FIXME: hmmm but SERVFILL_FIXME is actually a valid uint16_t value / id ?
		//   prevent generating those (fix ex gs_vserv_user_genid)
		GS_ASSERT(Id != GS_VSERV_USER_ID_SERVFILL_FIXME);

		Offset += 7; /* rest is data */

		GS_ASSERT(Offset <= Packet->dataLength);

		if (!!(r = gs_playback_buf_create_copying(Packet->data + Offset, Packet->dataLength - Offset, &PBBuf)))
			GS_GOTO_CLEAN();

		if (!!(r = gs_playback_packet_insert(Ctx->mPlayBack, TimeStamp, Id, Blk, Seq, GS_ARGOWN(&PBBuf))))
			GS_GOTO_CLEAN();

	clean_groupmodemsg:
		GS_DELETE_F(&PBBuf, gs_playback_buf_destroy);

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

int gs_vserv_clnt_callback_create(struct GsVServClnt *Clnt)
{
	int r = 0;

	struct GsVServClntCtx *Ctx = NULL;

	struct GsRecord   *Record = NULL;
	struct GsPlayBack *PlayBack = NULL;

	if (!!(r = gs_record_create(&Record)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_playback_create(&PlayBack, GS_PLAYBACK_FLOWS_NUM, GS_PLAYBACK_FLOW_BUFS_NUM)))
		GS_GOTO_CLEAN();

	Ctx = new GsVServClntCtx();
	Ctx->mBlk = 0;
	Ctx->mSeq = 0;
	Ctx->mName.mName = std::string();
	Ctx->mName.mServ = std::string();
	Ctx->mName.mId = GS_VSERV_USER_ID_SERVFILL_FIXME;
	Ctx->mRecord = GS_ARGOWN(&Record);
	Ctx->mPlayBack = GS_ARGOWN(&PlayBack);

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

int gs_vserv_clnt_callback_ident(
	struct GsVServClnt *Clnt,
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

	if (!!(r = gs_vserv_clnt_random_uint(Clnt, &FreshRand)))
		GS_GOTO_CLEAN();

	Renamer.mNameWant = std::string(NameWantedBuf, LenNameWanted);
	Renamer.mServWant = std::string(ServWantedBuf, LenServWanted);
	Renamer.mRandLastRequested = FreshRand;
	Renamer.mTimeStampLastRequested = TimeStamp;

	if (!!(r = gs_renamer_ident_emit(&Renamer, &PacketOut)))
		GS_GOTO_CLEAN();

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

	/* commit mSeq */
	// FIXME: overflow handling (maybe advance blk)
	Ctx->mSeq += 1;

	if (!!(r = gs_vserv_clnt_send(Clnt, PacketOut.data, PacketOut.dataLength)))
		GS_GOTO_CLEAN();

noclean:

clean:

	return r;
}

int gs_vserv_clnt_callback_update_other(
	struct GsVServClnt *Clnt,
	long long TimeStamp,
	uint32_t Keys /*hmmm*/)
{
	int r = 0;

	struct GsVServClntCtx *Ctx = NULL;

	struct GsVServClntAddress Addr = {};

	GS_ALLOCA_VAR(DataBuf, uint8_t, GS_CLNT_ARBITRARY_PACKET_MAX);
	size_t DataSize = GS_CLNT_ARBITRARY_PACKET_MAX;

	if (!!(r = gs_vserv_clnt_ctx_get(Clnt, &Ctx)))
		GS_GOTO_CLEAN();

	/* recording and network sending of recorded sound data */

	// FIXME: temporary testing dummy
	if (!!(r = gs_record_start(Ctx->mRecord)))
		GS_GOTO_CLEAN();

	while (true) {
		size_t  NumFraProcessed = 0;
		uint8_t FraBuf[2 * GS_OPUS_FRAME_48KHZ_20MS_SAMP_NUM];
		size_t  LenFra = 0;
		uint8_t  Mode = 0;
		uint16_t Blk  = 0;
		if (!!(r = gs_record_capture_drain(Ctx->mRecord, sizeof(uint16_t), GS_OPUS_FRAME_48KHZ_20MS_SAMP_NUM, FraBuf, sizeof FraBuf, &LenFra, &NumFraProcessed)))
			GS_GOTO_CLEAN();
		if (NumFraProcessed == 0)
			break;
		Mode = (Keys >> 0) & 0xFF;
		Blk  = (Keys >> 8) & 0xFFFF;
		if (!!(r = gs_vserv_clnt_callback_update_record(Clnt, TimeStamp, Mode, Ctx->mName.mId, Blk, FraBuf, LenFra)))
			GS_GOTO_CLEAN();
	}

	/* network receiving and general network processing
	     receives sound data (ex accumulates playback with gs_playback_packet_insert) */

	if (!!(r = gs_renamer_update(&Ctx->mRenamer, Clnt, TimeStamp)))
		GS_GOTO_CLEAN();

	while (true) {
		struct GsPacket Packet = { DataBuf, DataSize }; /*notowned*/

		if (!!(r = gs_vserv_clnt_receive(Clnt, &Addr, Packet.data, Packet.dataLength, &Packet.dataLength)))
			GS_GOTO_CLEAN();

		if (Packet.dataLength == 0)
			break;

		GS_LOG(I, S, "gs_vserv_clnt_callback_update_other receive");

		if (!!(r = gs_vserv_clnt_crank0(Clnt, Ctx, TimeStamp, &Packet)))
			GS_GOTO_CLEAN();
	}

	/* processing of received and accumulated playback */

	if (!!(r = gs_playback_recycle(Ctx->mPlayBack)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_playback_affinity_process(Ctx->mPlayBack, TimeStamp)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_playback_harvest_and_enqueue(Ctx->mPlayBack, TimeStamp)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_playback_ensure_playing(Ctx->mPlayBack)))
		GS_GOTO_CLEAN();

clean:

	return r;
}
