#ifndef _VSERV_ENET_PRIV_H_
#define _VSERV_ENET_PRIV_H_

#include <map>

#include <enet/enet.h>

#include <gittest/config.h>
#include <gittest/vserv_net.h>

/** @sa
		::gs_vserv_mgmt_init
		::gs_vserv_mgmt_create
		::gs_vserv_mgmt_destroy
		::gs_vserv_mgmt_receive_func
*/
struct GsVServMgmt
{
	struct GsAuxConfigCommonVars CommonVars;
	struct GsVServQuitCtl *mQuitCtl;
	ENetAddress mAddr;
	ENetHost *mHost;
	std::map<GsAddr, ENetPeer *, gs_addr_less_t> mAddrPeerMap;
};

/** @sa
		::gs_vserv_respond_mgmt_cb_respond
		::gs_vserv_respond_mgmt_enqueue_reliable_free
*/
struct GsVServRespondMgmt
{
	struct GsVServRespond base;
	struct GsVServMgmt *mMgmt;
	ENetPeer *mPeer;
};

int gs_vserv_mgmt_init();
int gs_vserv_mgmt_create(
	struct GsAuxConfigCommonVars *CommonVars,
	struct GsVServQuitCtl *QuitCtl, /*notowned*/
	struct GsVServMgmt **oMgmt);
int gs_vserv_mgmt_destroy(struct GsVServMgmt *Mgmt);
/*interface*/
int gs_vserv_mgmt_receive_func(
	struct GsVServCtl *ServCtl);

#endif /* _VSERV_ENET_PRIV_H_ */
