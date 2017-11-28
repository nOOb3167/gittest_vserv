#ifndef _VSERV_NET_H_
#define _VSERV_NET_H_

#include <stddef.h>
#include <cstdint>

#include <gittest/config.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_helpers_plat.h>
#include <gittest/vserv_work.h>

struct GsVServCtl;
struct GsVServMgmt;
struct GsVServRespondM;

struct GsVServCon
{
	struct GsVServMgmt * (*CbGetMgmt)(struct GsVServCon *Base);
};

struct GsVServWorkCb
{
	/* ServCtl->mThreadVec threads are made call this on start */
	int(*CbThreadFunc)(struct GsVServCtl *ServCtl, size_t SockIdx);
	/* called per-request */
	int(*CbCrank)(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond);
};

struct GsVServMgmtCb
{
	/* ServCtl->mThreadMgmt thread is made call this on start */
	int(*CbThreadFuncM)(struct GsVServCtl *ServCtl);
	/* called per-request */
	int(*CbCrankM)(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespondM *Respond);
};

int gs_vserv_ctl_create_part(
	size_t ThreadNum,
	struct GsVServCon *Con, /*owned*/
	struct GsVServWorkCb WorkCb,
	struct GsVServMgmtCb MgmtCb,
	struct GsVServCtl **oServCtl);
int gs_vserv_ctl_create_finish(
	struct GsVServCtl *ServCtl,
	struct GsVServQuitCtl *QuitCtl, /*owned*/
	struct GsVServWork *Work /*owned*/);
int gs_vserv_ctl_destroy(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_request(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_wait(struct GsVServCtl *ServCtl);
struct GsVServWork *   gs_vserv_ctl_get_work(struct GsVServCtl *ServCtl);
struct GsVServMgmt *   gs_vserv_ctl_get_mgmt(struct GsVServCtl *ServCtl);
struct GsVServCon *    gs_vserv_ctl_get_con(struct GsVServCtl *ServCtl);
struct GsVServWorkCb * gs_vserv_ctl_get_workcb(struct GsVServCtl *ServCtl);
struct GsVServMgmtCb * gs_vserv_ctl_get_mgmtcb(struct GsVServCtl *ServCtl);

/**/

int gs_vserv_start_crank0(struct GsAuxConfigCommonVars *CommonVars);

#endif /* _VSERV_NET_H_ */
