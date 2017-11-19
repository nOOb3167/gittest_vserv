#ifndef _VSERV_CLNT_H_
#define _VSERV_CLNT_H_

#include <stddef.h>
#include <stdint.h>

#include <gittest/UDPSocket.hpp>

// FIXME:
#define GS_VSERV_CMD_IDENT_FIXME 'i'
#define GS_VSERV_CMD_IDENT_ACK_FIXME 'I'
#define GS_VSERV_CMD_GROUP_MODE_MSG_FIXME 'm'
#define GS_VSERV_GROUP_MODE_NONE_FIXME 0
#define GS_VSERV_USER_ID_SERVFILL_FIXME 0xFFFF

#define GS_CLNT_ARBITRARY_PACKET_MAX 4096 /* but mind IP layer fragmentation issues of UDP */
#define GS_CLNT_ARBITRARY_IDENT_RESEND_TIMEOUT 100

struct GsVServClnt;
struct GsVServClntCtx;

int gs_vserv_clnt_ctx_set(struct GsVServClnt *Clnt, struct GsVServClntCtx *Ctx);
int gs_vserv_clnt_ctx_get(struct GsVServClnt *Clnt, struct GsVServClntCtx **oCtx);
int gs_vserv_clnt_receive(struct GsVServClnt *Clnt, struct GsVServClntAddress *ioAddrFrom, uint8_t *ioDataBuf, size_t DataSize, size_t *oLenData);
int gs_vserv_clnt_send(struct GsVServClnt *Clnt, const uint8_t *DataBuf, size_t LenData);
int gs_vserv_clnt_random_uint(struct GsVServClnt *Clnt, uint32_t *oRand);

int gs_vserv_clnt_setkeys(struct GsVServClnt *Clnt, uint32_t Keys);

int gs_vserv_clnt_callback_create(struct GsVServClnt *Clnt);
int gs_vserv_clnt_callback_destroy(struct GsVServClnt *Clnt);
int gs_vserv_clnt_callback_ident(struct GsVServClnt *Clnt,
	const char *NameWantedBuf, size_t LenNameWanted,
	const char *ServWantedBuf, size_t LenServWanted,
	long long TimeStamp);
int gs_vserv_clnt_callback_update_record(
	struct GsVServClnt *Clnt,
	long long TimeStamp,
	uint8_t Mode,
	uint16_t Id,
	uint16_t Blk,
	uint8_t *FraBuf, size_t LenFra);
int gs_vserv_clnt_callback_update_other(
	struct GsVServClnt *Clnt,
	long long TimeStamp);

// pedantically version-define the header so it may be bundled into foreign source trees?
//   version passed to create?

// consider separate start_shutdown and destroy callbacks (start_shutdown keeps sending disconnect messages)

#endif /* _VSERV_CLNT_H_ */
