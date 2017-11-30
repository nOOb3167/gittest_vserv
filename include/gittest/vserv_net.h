#ifndef _VSERV_NET_H_
#define _VSERV_NET_H_

#include <stddef.h>
#include <cstdint>

#include <gittest/config.h>
#include <gittest/vserv_helpers.h>
#include <gittest/vserv_helpers_plat.h>
#include <gittest/vserv_work.h>

struct GsVServCtl;
struct GsVServMgmt;  // FIXME: create public mgmt header

struct GsVServCon
{
};

/** @sa
		::gs_vserv_respond_enqueue_idvec_free
*/
struct GsVServRespond
{
	/* DataBuf is owned - is to be released by free(2) */
	int(*CbRespond)(
		struct GsVServRespond *RespondBase,
		uint8_t *DataBuf, size_t LenData, /*owned*/
		const struct GsAddr **AddrVec, size_t LenAddrVec);
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
	int(*CbCrankM)(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond);
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
	struct GsVServWork *Work /*owned*/,
	struct GsVServMgmt *Mgmt /*owned*/);
int gs_vserv_ctl_destroy(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_request(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_wait(struct GsVServCtl *ServCtl);
struct GsVServWork *   gs_vserv_ctl_get_work(struct GsVServCtl *ServCtl);
struct GsVServMgmt *   gs_vserv_ctl_get_mgmt(struct GsVServCtl *ServCtl);
struct GsVServCon *    gs_vserv_ctl_get_con(struct GsVServCtl *ServCtl);
struct GsVServWorkCb * gs_vserv_ctl_get_workcb(struct GsVServCtl *ServCtl);
struct GsVServMgmtCb * gs_vserv_ctl_get_mgmtcb(struct GsVServCtl *ServCtl);

int gs_vserv_respond_enqueue_idvec_free(
	struct GsVServRespond *RespondBase,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);

/**/

int gs_vserv_start_crank0(struct GsAuxConfigCommonVars *CommonVars);

#endif /* _VSERV_NET_H_ */
