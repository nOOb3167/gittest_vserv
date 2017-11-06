#ifndef _VSERV_NET_H_
#define _VSERV_NET_H_

#include <stddef.h>

#include <gittest/config.h>

/* intended to be forward-declared in header (API use pointer only) */
struct GsVServCtl;

enum GsSockType
{
	GS_SOCK_TYPE_NORMAL = 2,
	GS_SOCK_TYPE_EVENT = 3,
};

struct GsVServConExt
{
	struct GsAuxConfigCommonVars mCommonVars; /*notowned*/
};

struct GsVServConCtx
{
	int mFd;
	struct GsVServConExt *mExt; /*notowned*/
	/* must set the callbacks - caller inits other members
	likely want an extra context parameter for communication */
	int(*CbCtxCreate)(struct GsVServConCtx **oCtxBase, enum XsSockType Type, struct XsConExt *Ext);
	int(*CbCtxDestroy)(struct GsVServConCtx *CtxBase);
	int(*CbCrank)(struct GsVServConCtx *CtxBase, struct GsPacket *Packet);
};

typedef int(*gs_cb_vserv_con_ctx_create_t)(struct GsVServConCtx **oCtxBase, enum GsSockType Type, struct GsVServConExt *Ext);

int gs_vserv_ctl_create_part(
	size_t ThreadNum,
	struct GsVServCtl **oServCtl);
int gs_vserv_ctl_destroy(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_request(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_wait(struct GsVServCtl *ServCtl);

int gs_vserv_sockets_create(
	const char *Port,
	int *ioSockFdVec, size_t SockFdNum);

int gs_vserv_start(struct GsAuxConfigCommonVars *CommonVars);

#endif /* _VSERV_NET_H_ */
