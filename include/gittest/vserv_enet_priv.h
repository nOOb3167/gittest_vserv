#ifndef _VSERV_ENET_PRIV_H_
#define _VSERV_ENET_PRIV_H_

#include <enet/enet.h>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>

struct GsVServEnet
{
	struct GsAuxConfigCommonVars CommonVars;
	struct GsVServCtlCb *mCb; /*notowned*/
	ENetAddress mAddr;
	ENetHost *mHost;
};

struct GsVServRespondM
{
	struct GsVServEnet *mEnet;
	ENetPeer *mPeer;
};

int gs_vserv_enet_init();
int gs_vserv_enet_create(
	struct GsAuxConfigCommonVars *CommonVars,
	struct GsVServCtlCb *Cb,
	struct GsVServEnet **oEnet);
int gs_vserv_enet_destroy(struct GsVServEnet *Enet);
/*interface*/
int gs_vserv_enet_receive_func(
	struct GsVServCtl *ServCtl);

#endif /* _VSERV_ENET_PRIV_H_ */
