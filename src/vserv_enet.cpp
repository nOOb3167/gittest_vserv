#include <cstdint>

#include <enet/enet.h>

#include <gittest/misc.h>
#include <gittest/config.h>
#include <gittest/vserv_net.h>
#include <gittest/vserv_enet_priv.h>

#define GS_VSERV_ENET_ARBITRARY_CLIENT_MAX 128

static unsigned long long gs_vserv_enet_addr_host_to_gs_addr_host(uint32_t EnetAddrHost);

unsigned long long gs_vserv_enet_addr_host_to_gs_addr_host(uint32_t EnetAddrHost)
{
	return ENET_NET_TO_HOST_32(EnetAddrHost);
}

// FIXME: should be in the public header really
int gs_vserv_enet_init()
{
	return !! enet_initialize();
}

int gs_vserv_enet_create(
	struct GsAuxConfigCommonVars *CommonVars,
	struct GsVServCtlCb *Cb,
	struct GsVServEnet **oEnet)
{
	int r = 0;

	struct GsVServEnet *Enet = NULL;

	ENetAddress Addr = {};
	ENetHost *Host = NULL;

	if (!!(r = gs_buf_ensure_haszero(CommonVars->VServHostNameBuf, CommonVars->LenVServHostName + 1)))
		GS_GOTO_CLEAN();

	if (!!(r = enet_address_set_host(&Addr, CommonVars->VServHostNameBuf)))
		GS_GOTO_CLEAN();
	Addr.port = CommonVars->VServPortEnet;

	if (!(Host = enet_host_create(&Addr, GS_VSERV_ENET_ARBITRARY_CLIENT_MAX, 1, 0, 0)))
		GS_ERR_CLEAN(1);

	Enet = new GsVServEnet();
	Enet->mCb = Cb;
	Enet->mAddr = Addr;
	Enet->mHost = GS_ARGOWN(&Host);

clean:
	enet_host_destroy(Host);
	GS_DELETE(&Enet, struct GsVServEnet);

	return r;
}

int gs_vserv_enet_destroy(struct GsVServEnet *Enet)
{
	GS_DELETE(&Enet, struct GsVServEnet);
	return 0;
}

/** designed to be called on separate thread after GsVServEnet creation */
int gs_vserv_enet_receive_func(
	struct GsVServCtl *ServCtl)
{
	int r = 0;

	struct GsVServCtlCb *XCb = gs_vserv_ctl_get_cb(ServCtl);
	struct GsVServCtlCb0 *XCb0 = (struct GsVServCtlCb0 *) XCb;
	struct GsVServEnet *Enet = XCb0->mEnet;

	const size_t TimeoutGenerationMax = 4; /* [0,4] interval */
	uint32_t TimeoutGenerationVec[]    = { 1,  5,  10, 20,  500 };
	uint32_t TimeoutGenerationCntVec[] = { 10, 10, 10, 100, 0xFFFFFFFF };

	size_t TimeoutGeneration    = 0;
	size_t TimeoutGenerationCnt = 0;

	int HostServiceRet = 0;

	while (true) {
		ENetEvent Evt = {};

		if (0 > (HostServiceRet = enet_host_service(Enet->mHost, &Evt, TimeoutGenerationVec[TimeoutGeneration])))
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
			Respond.mEnet = Enet;
			Respond.mPeer = Evt.peer;
			if (!!(r = Enet->mCb->CbCrankM(Enet->mCb, &Packet, &Addr, &Respond)))
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
