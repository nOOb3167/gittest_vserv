#include <cstdint>

#include <enet/enet.h>

#include <gittest/misc.h>
#include <gittest/config.h>
#include <gittest/vserv_net.h>
#include <gittest/vserv_crank0_priv.h>
#include <gittest/vserv_mgmt_priv.h>

#define GS_VSERV_ENET_ARBITRARY_CLIENT_MAX 128

static unsigned long long gs_vserv_enet_addr_host_to_gs_addr_host(uint32_t EnetAddrHost);

unsigned long long gs_vserv_enet_addr_host_to_gs_addr_host(uint32_t EnetAddrHost)
{
	return ENET_NET_TO_HOST_32(EnetAddrHost);
}

// FIXME: should be in the public header really
int gs_vserv_mgmt_init()
{
	return !! enet_initialize();
}

int gs_vserv_mgmt_create(
	struct GsAuxConfigCommonVars *CommonVars,
	struct GsVServMgmt **oMgmt)
{
	int r = 0;

	struct GsVServMgmt *Mgmt = NULL;

	ENetAddress Addr = {};
	ENetHost *Host = NULL;

	if (!!(r = gs_buf_ensure_haszero(CommonVars->VServHostNameBuf, CommonVars->LenVServHostName + 1)))
		GS_GOTO_CLEAN();

	if (!!(r = enet_address_set_host(&Addr, CommonVars->VServHostNameBuf)))
		GS_GOTO_CLEAN();
	Addr.port = CommonVars->VServPortEnet;

	if (!(Host = enet_host_create(&Addr, GS_VSERV_ENET_ARBITRARY_CLIENT_MAX, 1, 0, 0)))
		GS_ERR_CLEAN(1);

	Mgmt = new GsVServMgmt();
	Mgmt->mAddr = Addr;
	Mgmt->mHost = GS_ARGOWN(&Host);

	if (oMgmt)
		*oMgmt = GS_ARGOWN(&Mgmt);

clean:
	enet_host_destroy(Host);
	GS_DELETE(&Mgmt, struct GsVServMgmt);

	return r;
}

int gs_vserv_mgmt_destroy(struct GsVServMgmt *Mgmt)
{
	GS_DELETE(&Mgmt, struct GsVServMgmt);
	return 0;
}

/** designed to be called on separate thread after GsVServEnet creation */
int gs_vserv_mgmt_receive_func(
	struct GsVServCtl *ServCtl)
{
	int r = 0;

	struct GsVServConExt *Ext = (struct GsVServConExt *) gs_vserv_ctl_get_con(ServCtl);
	struct GsVServMgmtCb *MgmtCb = (struct GsVServMgmtCb *) gs_vserv_ctl_get_mgmtcb(ServCtl);
	struct GsVServMgmt *Mgmt = gs_vserv_con_ext_getmgmt(&Ext->base);

	const size_t TimeoutGenerationMax = 4; /* [0,4] interval */
	uint32_t TimeoutGenerationVec[]    = { 1,  5,  10, 20,  500 };
	uint32_t TimeoutGenerationCntVec[] = { 10, 10, 10, 100, 0xFFFFFFFF };

	size_t TimeoutGeneration    = 0;
	size_t TimeoutGenerationCnt = 0;

	int HostServiceRet = 0;

	while (true) {
		ENetEvent Evt = {};

		if (0 > (HostServiceRet = enet_host_service(Mgmt->mHost, &Evt, TimeoutGenerationVec[TimeoutGeneration])))
			GS_ERR_CLEAN(1);

		/* timeout - if too many, switch to next timeout generation */
		if (HostServiceRet == 0)
			if ((++TimeoutGenerationCnt % TimeoutGenerationCntVec[TimeoutGeneration]) == 0)
				TimeoutGeneration = GS_MIN(TimeoutGeneration + 1, TimeoutGenerationMax);

		switch (Evt.type)
		{

		case ENET_EVENT_TYPE_CONNECT:
		{
			GS_LOG(I, PF, "enet newcon [port=%d]", (int)Evt.peer->address.port);
			Evt.peer->data = NULL;
		}
		break;

		case ENET_EVENT_TYPE_DISCONNECT:
		{
			GS_LOG(I, PF, "enet delcon [port=%d]", (int)Evt.peer->address.port);
			GS_ASSERT(Evt.peer->data == NULL);
		}
		break;

		case ENET_EVENT_TYPE_RECEIVE:
		{
			struct GsAddr Addr = {};
			struct GsPacket Packet = {};
			struct GsVServRespondM Respond = {};
			Addr.mSinFamily = AF_INET;
			Addr.mSinPort = Evt.peer->address.port;
			Addr.mSinAddr = gs_vserv_enet_addr_host_to_gs_addr_host(Evt.peer->address.host);
			Packet.data = Evt.packet->data;
			Packet.dataLength = Evt.packet->dataLength;
			Respond.mMgmt = Mgmt;
			Respond.mPeer = Evt.peer;
			if (!!(r = MgmtCb->CbCrankM(ServCtl, &Packet, &Addr, &Respond)))
				GS_GOTO_CLEAN_J(receive);

		clean_receive:
			enet_packet_destroy(Evt.packet);
			if (!!r)
				GS_GOTO_CLEAN();
		}
		break;

		default:
			GS_ASSERT(0);

		}
	}

clean:

	return r;
}
