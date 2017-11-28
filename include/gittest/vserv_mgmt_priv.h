#ifndef _VSERV_ENET_PRIV_H_
#define _VSERV_ENET_PRIV_H_

#include <enet/enet.h>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>

struct GsVServMgmt
{
	struct GsAuxConfigCommonVars CommonVars;
	ENetAddress mAddr;
	ENetHost *mHost;
};

struct GsVServRespondM
{
	struct GsVServMgmt *mMgmt;
	ENetPeer *mPeer;
};

int gs_vserv_mgmt_init();
int gs_vserv_mgmt_create(
	struct GsAuxConfigCommonVars *CommonVars,
	struct GsVServMgmt **oMgmt);
int gs_vserv_mgmt_destroy(struct GsVServMgmt *Mgmt);
/*interface*/
int gs_vserv_mgmt_receive_func(
	struct GsVServCtl *ServCtl);

#endif /* _VSERV_ENET_PRIV_H_ */
