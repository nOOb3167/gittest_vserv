#include <cstdint>

#include <utility>

#include <enet/enet.h>

#include <gittest/misc.h>
#include <gittest/config.h>
#include <gittest/vserv_net.h>
#include <gittest/vserv_crank0_priv.h>
#include <gittest/vserv_mgmt_priv.h>

#define GS_VSERV_ENET_ARBITRARY_CLIENT_MAX 128

static unsigned long long gs_vserv_enet_addr_host_to_gs_addr_host(uint32_t EnetAddrHost);
static uint32_t           gs_vserv_gs_addr_host_to_enet_addr_host(unsigned long long AddrHost);
static struct GsAddr      gs_vserv_enet_addr_to_gs_addr(ENetAddress EnetAddr);

static int gs_vserv_respond_mgmt_cb_respond(
	struct GsVServRespond *RespondBase,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);
static int gs_vserv_respond_mgmt_enqueue_reliable_free(
	struct GsVServRespondMgmt *Respond,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);

unsigned long long gs_vserv_enet_addr_host_to_gs_addr_host(uint32_t EnetAddrHost)
{
	return ENET_NET_TO_HOST_32(EnetAddrHost);
}

uint32_t gs_vserv_gs_addr_host_to_enet_addr_host(unsigned long long AddrHost)
{
	return ENET_HOST_TO_NET_32(AddrHost);
}

struct GsAddr gs_vserv_enet_addr_to_gs_addr(ENetAddress EnetAddr)
{
	struct GsAddr Addr = {};
	Addr.mSinFamily = AF_UNIX;  // FIXME: constant exposed by ENet header but find cleaner approach
	Addr.mSinPort = EnetAddr.port;
	Addr.mSinAddr = gs_vserv_enet_addr_host_to_gs_addr_host(EnetAddr.host);
	return Addr;
}

void ENET_CALLBACK gs_vserv_write_elt_del_sp_free__enet_packet_freecallback(struct _ENetPacket *Packet)
{
	GS_DELETE_F(&Packet->data, gs_vserv_write_elt_del_sp_free);
}

int gs_vserv_respond_mgmt_cb_respond(
	struct GsVServRespond *RespondBase,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec)
{
	struct GsVServRespondMgmt *Respond = (struct GsVServRespondMgmt *) RespondBase;

	return gs_vserv_respond_mgmt_enqueue_reliable_free(Respond, DataBuf, LenData, AddrVec, LenAddrVec);
}

int gs_vserv_respond_mgmt_enqueue_reliable_free(
	struct GsVServRespondMgmt *Respond,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec)
{
	int r = 0;

	struct GsVServMgmt *Mgmt = Respond->mMgmt;

	ENetPacket *Pkt = NULL;
	bool OwnershipPassedToPeerSend = false;

	/* we will be using ENET_PACKET_FLAG_NO_ALLOCATE together with freeCallback.
	   DataBuf is not copied by enet_packet_create - but we can still release ownership
	   of DataBuf as the freeCallback will eventually be invoked. */
	/* enet_peer_send takes ownership of the packet on success (enet_packet_destroy MUST NOT be called).
	   enet_peer_send does not take ownership of the packet on failure (enet_packet_destroy MUST be called).
	   in the case multiple enet_peer_send (completing with succeess) calls are issued for the same packet
	   the first call will take ownership.
	     due to above behaviour of enet_packet_send, a flag is used to track
		 whether enet_peer_send has ownership, and avoid enet_packet_destroy.
	*/

	if (!(Pkt = enet_packet_create(DataBuf, LenData, ENET_PACKET_FLAG_NO_ALLOCATE | ENET_PACKET_FLAG_RELIABLE)))
		GS_ERR_CLEAN(1);
	Pkt->freeCallback = gs_vserv_write_elt_del_sp_free__enet_packet_freecallback;
	DataBuf = NULL;	

	for (size_t NumWrite = 0; NumWrite < LenAddrVec; NumWrite++) {
		if (Mgmt->mAddrPeerMap.find(*AddrVec[NumWrite]) == Mgmt->mAddrPeerMap.end)
			GS_ERR_CLEAN(1);
		if (!!(r = enet_peer_send(Mgmt->mAddrPeerMap[*AddrVec[NumWrite]], 0, Pkt)))
			GS_GOTO_CLEAN();
		if (! OwnershipPassedToPeerSend)
			OwnershipPassedToPeerSend = true;
	}

clean:
	if (! OwnershipPassedToPeerSend)
		enet_packet_destroy(Pkt);
	GS_DELETE_F(&DataBuf, gs_vserv_write_elt_del_sp_free);

	return r;
}

// FIXME: should be in the public header really
int gs_vserv_mgmt_init()
{
	return !! enet_initialize();
}

int gs_vserv_mgmt_create(
	struct GsAuxConfigCommonVars *CommonVars,
	struct GsVServQuitCtl *QuitCtl, /*notowned*/
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
	Mgmt->mQuitCtl = GS_ARGOWN(&QuitCtl);
	Mgmt->mAddr = Addr;
	Mgmt->mHost = GS_ARGOWN(&Host);

	if (oMgmt)
		*oMgmt = GS_ARGOWN(&Mgmt);

clean:
	enet_host_destroy(Host);
	GS_DELETE_F(&Mgmt, gs_vserv_mgmt_destroy);

	return r;
}

int gs_vserv_mgmt_destroy(struct GsVServMgmt *Mgmt)
{
	if (Mgmt) {
		enet_host_destroy(Mgmt->mHost);
		GS_DELETE(&Mgmt, struct GsVServMgmt);
	}
	return 0;
}

/** designed to be called on separate thread after GsVServEnet creation */
int gs_vserv_mgmt_receive_func(
	struct GsVServCtl *ServCtl)
{
	int r = 0;

	struct GsVServConExt *Ext = (struct GsVServConExt *) gs_vserv_ctl_get_con(ServCtl);
	struct GsVServMgmtCb *MgmtCb = (struct GsVServMgmtCb *) gs_vserv_ctl_get_mgmtcb(ServCtl);
	struct GsVServMgmt *Mgmt = gs_vserv_ctl_get_mgmt(ServCtl);

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
			struct GsAddr Addr = gs_vserv_enet_addr_to_gs_addr(Evt.peer->address);
			if (! (Mgmt->mAddrPeerMap.insert(std::make_pair(Addr, Evt.peer))).second)
				GS_ERR_CLEAN(1);
			GS_LOG(I, PF, "enet newcon [addr=%X, port=%d]", (unsigned int) Addr.mSinAddr, (int) Addr.mSinPort);
		}
		break;

		case ENET_EVENT_TYPE_DISCONNECT:
		{
			struct GsAddr Addr = gs_vserv_enet_addr_to_gs_addr(Evt.peer->address);
			auto it = Mgmt->mAddrPeerMap.find(Addr);
			GS_ASSERT(it != Mgmt->mAddrPeerMap.end());
			Mgmt->mAddrPeerMap.erase(it);
			GS_LOG(I, PF, "enet delcon [addr=%X, port=%d]", (unsigned int) Addr.mSinAddr, (int) Addr.mSinPort);
		}
		break;

		case ENET_EVENT_TYPE_RECEIVE:
		{
			struct GsAddr Addr = gs_vserv_enet_addr_to_gs_addr(Evt.peer->address);
			struct GsPacket Packet = {};
			struct GsVServRespondMgmt Respond = {};
			Packet.data = Evt.packet->data;
			Packet.dataLength = Evt.packet->dataLength;
			Respond.base.CbRespond = gs_vserv_respond_mgmt_cb_respond;
			Respond.mMgmt = Mgmt;
			Respond.mPeer = Evt.peer;
			if (!!(r = MgmtCb->CbCrankM(ServCtl, &Packet, &Addr, &Respond.base)))
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
