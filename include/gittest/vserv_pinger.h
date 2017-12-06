#ifndef _GS_VSERV_PINGER_H_
#define _GS_VSERV_PINGER_H_

#define GS_PINGER_REQUEST_INTERVAL_MS 1000

struct GsPinger;

int gs_pinger_create(struct GsPinger **oPinger);
int gs_pinger_destroy(struct GsPinger *Pinger);
int gs_pinger_emit_prepare_cond(
	struct GsPinger *Pinger,
	long long TimeStamp,
	struct GsPacket *ioPacketOut,
	int *ioWantEmitPacket);
int gs_pinger_emit_success(
	struct GsPinger *Pinger,
	long long TimeStamp);

#endif /* _GS_VSERV_PINGER_H_ */
