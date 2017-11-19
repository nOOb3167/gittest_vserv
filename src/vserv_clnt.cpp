#include <cstddef>
#include <cstdint>
#include <cstring>

#include <string>
#include <random>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>
#include <gittest/vserv_clnt.h>
#include <gittest/vserv_helpers.h>

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

static int gs_vserv_clnt_crank0(
	struct GsVServClnt *Clnt,
	struct GsVServClntCtx *Ctx,
	long long TimeStamp,
	struct GsPacket *Packet);

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

	while (true) {
		struct GsPacket Packet = { DataBuf, DataSize }; /*notowned*/

		if (!!(r = gs_vserv_clnt_receive(Clnt, &Addr, Packet.data, Packet.dataLength, &Packet.dataLength)))
			GS_GOTO_CLEAN();

		GS_LOG(I, S, "gs_vserv_clnt_callback_update_other receive");

		if (!!(r = gs_vserv_clnt_crank0(Clnt, Ctx, TimeStamp, &Packet)))
			GS_GOTO_CLEAN();
	}

clean:

	return r;
}
