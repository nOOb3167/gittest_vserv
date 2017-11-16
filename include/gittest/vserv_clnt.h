#ifndef _VSERV_CLNT_H_
#define _VSERV_CLNT_H_

#include <stddef.h>
#include <stdint.h>

struct GsVServClntAddress
{
	unsigned long long mSinFamily;
	unsigned long long mSinPort; /* host byte order */
	unsigned long long mSinAddr; /* host byte order */
};

struct GsVServClnt;
struct GsVServClntCtx;

int gs_vserv_clnt_ctx_set(struct GsVServClnt *Clnt, struct GsVServClntCtx *Ctx);
int gs_vserv_clnt_ctx_get(struct GsVServClnt *Clnt, struct GsVServClntCtx **oCtx);
int gs_vserv_clnt_receive(struct GsVServClnt *Clnt, struct GsVServClntAddress *ioAddrFrom, uint8_t *ioDataBuf, size_t DataSize, size_t *oLenData);
int gs_vserv_clnt_send(struct GsVServClnt *Clnt, uint8_t *DataBuf, size_t LenData);

int gs_vserv_clnt_callback_create(struct GsVServClnt *Clnt);
int gs_vserv_clnt_callback_destroy(struct GsVServClnt *Clnt);
// some kind of timing argument? abstime or deltatime?
// some kind of received-sound-frames-with-mode argument?
int gs_vserv_clnt_callback_update(struct GsVServClnt *Clnt);

// pedantically version-define the header so it may be bundled into foreign source trees?
//   version passed to create?

// consider separate start_shutdown and destroy callbacks (start_shutdown keeps sending disconnect messages)

#endif /* _VSERV_CLNT_H_ */
