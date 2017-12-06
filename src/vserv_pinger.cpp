#include <gittest/misc.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_clnt_helpers.h>
#include <gittest/vserv_pinger.h>

struct GsPinger
{
	long long mTimeStampLastPing;
};

int gs_pinger_create(struct GsPinger **oPinger)
{
	int r = 0;

	struct GsPinger *Pinger = NULL;

	Pinger = new GsPinger();
	Pinger->mTimeStampLastPing = 0;

	if (oPinger)
		*oPinger = GS_ARGOWN(&Pinger);

clean:
	GS_DELETE_F(&Pinger, gs_pinger_destroy);

	return r;
}

int gs_pinger_destroy(struct GsPinger *Pinger)
{
	if (Pinger) {
		GS_DELETE(&Pinger, struct GsPinger);
	}
	return 0;
}

int gs_pinger_emit_prepare_cond(
	struct GsPinger *Pinger,
	long long TimeStamp,
	struct GsPacket *ioPacketOut,
	int *ioWantEmitPacket)
{
	int r = 0;

	size_t WantEmitPacket = 0;
	size_t OffsetOut = 0;

	if (TimeStamp < Pinger->mTimeStampLastPing + GS_PINGER_REQUEST_INTERVAL_MS)
		GS_ERR_NO_CLEAN(0);

	/* (cmd)[1] */

	if (gs_packet_space(ioPacketOut, (OffsetOut), 1 /*cmd*/))
		GS_ERR_CLEAN(1);

	gs_write_byte(ioPacketOut->data + OffsetOut, GS_VSERV_CMD_PING);

	OffsetOut += 1;

	/* adjust packet to real length (vs maximum allowed) */

	ioPacketOut->dataLength = OffsetOut;

	WantEmitPacket = 1;

noclean:
	if (ioWantEmitPacket)
		*ioWantEmitPacket = WantEmitPacket;

clean:

	return r;
}

int gs_pinger_emit_success(
	struct GsPinger *Pinger,
	long long TimeStamp)
{
	int r = 0;

	Pinger->mTimeStampLastPing = TimeStamp;

clean:

	return r;
}
