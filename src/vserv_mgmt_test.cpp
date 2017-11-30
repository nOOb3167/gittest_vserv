#include <cstdlib>
#include <cstddef>

#include <memory>
#include <thread>
#include <chrono>
#include <random>

#include <enet/enet.h>

#include <gittest/misc.h>
#include <gittest/config.h>
#include <gittest/log.h>
#include <gittest/vserv_net.h>

#define GS_VSERV_CMD_NAMES_FIXME 'N'
#define GS_VSERV_M_CMD_GROUPSET_FIXME 's'

#define GS_MGMT_ARBITRARY_PACKET_MAX 4096 /* but mind IP layer fragmentation issues of UDP */
#define GS_MGMT_ARBITRARY_EVT_MAX 64 /* how many dequeued at most per-iteration */
#define GS_MGMT_ONE_TICK_MS 20

struct GsVServMgmt
{
	ENetAddress mAddr;
	ENetHost *mHost;
	ENetPeer *mPeer;

	sp<std::thread> mThread;

	std::mt19937                            mRandGen;
	std::uniform_int_distribution<uint32_t> mRandDis;
};

static int gs_vserv_enet_init();

int gs_vserv_enet_init()
{
	return !! enet_initialize();
}

int gs_vserv_enet_send_reliable(ENetPeer *Peer, struct GsPacket *Packet)
{
	int r = 0;

	ENetPacket *Pkt = NULL;

	if (!(Pkt = enet_packet_create(Packet->data, Packet->dataLength, ENET_PACKET_FLAG_RELIABLE)))
		GS_ERR_CLEAN(1);

	/* FIXME: according to the ENet Tutorial:
		"""Once the packet is handed over to ENet with enet_peer_send(),
		   ENet will handle its deallocation and enet_packet_destroy()
		   should not be used upon it."""
	   but of course expecting the ENet author to have sufficient foresight
	   to 'handle its deallocation' in every case (specifically early exit due to error)
	   proves to be overly optimistic.
	   reading the source code reveals the following enet_peer_send behaviours:
		- succeed and take ownership     -> caller MUST NOT destroy
		- fail and take ownership        -> caller MUST NOT destroy
		- fail and do not take ownership -> caller MUST destroy
	   the two fail cases impose contradictory requirements wrt destruction.
	   for now just assume enet_peer_send always takes ownership, leaking the packet in some cases.
	   FIXME: UPON FURTHER INSPECTION THE ABOVE IS INACCURATE
	     enet_peer_send fucks with the packet reference count.
		 BUT enet_packet_destroy _does_ _not_ _even_ _check_ _it_ .
		 further, critically, enet_peer_send codepaths seem to take care
		 to always succeed after incrementing the packet reference count.
		 therefore the revised enet_peer_send behaviours:
		  - succeed and take ownership     -> caller MUST NOT destroy
		  - fail and do not take ownership -> caller MUST destroy
	*/

	if (!!(r = enet_peer_send(Peer, 0, Pkt)))
		GS_GOTO_CLEAN();
	Pkt = NULL;

clean:
	if (Pkt)
		enet_packet_destroy(Pkt);

	return r;
}

int gs_vserv_mgmt_crank0(
	struct GsVServMgmt *Mgmt,
	long long TimeStamp,
	struct GsPacket *Packet)
{
	int r = 0;

	if (gs_packet_space(Packet, 0, 1))
		GS_ERR_CLEAN(1);

	GS_LOG(I, PF, "pkt [cmd=%c]", (int)Packet->data[0]);

	switch (Packet->data[0])
	{

	case GS_VSERV_CMD_NAMES_FIXME:
	{
		/* (cmd)[1], ((id)[2], (namenum)[4] (namevec)[namenum])[..] */

		size_t Offset = 1; /* past 'cmd' */

		std::vector<uint16_t> Ids;
		std::vector<std::string> Names;

		struct GsPacket PacketOut = {};
		GS_ALLOCA_ASSIGN(PacketOut.data, uint8_t, GS_MGMT_ARBITRARY_PACKET_MAX);
		PacketOut.dataLength = GS_MGMT_ARBITRARY_PACKET_MAX;

		size_t OffsetOut = 0;

		while (Offset < Packet->dataLength) {
			uint16_t Id = 0;
			size_t NameNum = 0;
			if (gs_packet_space(Packet, (Offset), 2 /*id*/ + 4 /*namenum*/))
				GS_ERR_CLEAN_J(names, 1);
			Id = gs_read_short(Packet->data + Offset + 0);
			NameNum = gs_read_uint(Packet->data + Offset + 2);
			if (gs_packet_space(Packet, (Offset += 6), NameNum))
				GS_ERR_CLEAN_J(names, 1);
			Ids.push_back(Id);
			Names.push_back(std::string((const char *) (Packet->data + Offset), NameNum));
		}

		/* (cmd)[1], (idnum)[4], (sznum)[4], (idvec[idnum])[2*idnum], (szvec[sznum])(2*sznum) */

		if (gs_packet_space(&PacketOut, (OffsetOut), 1 /*cmd*/ + 4 /*idnum*/ + 4 /*sznum*/ + 2 * Ids.size() /*idvec*/ + 2 /*szvec*/))
			GS_ERR_CLEAN_J(names, 1);

		gs_write_byte(PacketOut.data + 0, GS_VSERV_M_CMD_GROUPSET_FIXME);
		gs_write_uint(PacketOut.data + 1, Ids.size());
		gs_write_uint(PacketOut.data + 5, 1);

		OffsetOut += 9;
		
		for (size_t i = 0; i < Ids.size(); i++, (OffsetOut+=2))
			gs_write_short(PacketOut.data + OffsetOut, Ids[i]);
		
		gs_write_short(PacketOut.data + OffsetOut, Ids.size());

		OffsetOut += 2;

		/* adjust packet to real length (vs maximum allowed) */

		PacketOut.dataLength = OffsetOut;

		/* respond */

		if (!!(r = gs_vserv_enet_send_reliable(Mgmt->mPeer, &PacketOut)))
			GS_GOTO_CLEAN();

	clean_names:
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	default:
		GS_ASSERT(0);
	}

clean:

	return r;
}

int gs_vserv_mgmt_update(
	struct GsVServMgmt *Mgmt,
	long long TimeStamp,
	bool WaitIndicatesEventArrived,
	ENetEvent *Evt /*owned*/)
{
	int r = 0;

	GS_ALLOCA_VAR(EvtVec, ENetEvent, GS_MGMT_ARBITRARY_EVT_MAX);
	const size_t EvtSize = GS_MGMT_ARBITRARY_EVT_MAX;
	size_t EvtNum = 0;

	GS_ASSERT(EvtNum++ < EvtSize);
	EvtVec[0] = *GS_ARGOWN(&Evt);

	for (/*dummy*/; EvtNum < EvtSize; EvtNum++) {
		int NReady = 0;
		if (0 > (NReady = enet_host_service(Mgmt->mHost, EvtVec + EvtNum, 0)))
			GS_ERR_CLEAN(1);
		if (! NReady)
			break;
	}

	for (size_t i = 0; i < EvtNum; i++) {
		struct GsPacket Packet = {};
		if (EvtVec[i].type != ENET_EVENT_TYPE_RECEIVE)
			continue;
		Packet.data = EvtVec[i].packet->data;
		Packet.dataLength = EvtVec[i].packet->dataLength;
		if (!!(r = gs_vserv_mgmt_crank0(Mgmt, TimeStamp, &Packet)))
			GS_GOTO_CLEAN();
	}

clean:
	if (WaitIndicatesEventArrived && Evt && Evt->type == ENET_EVENT_TYPE_RECEIVE && Evt->packet)
		enet_packet_destroy(Evt->packet);

	return r;
}

void threadfunc(struct GsVServMgmt *Mgmt)
{
	int r = 0;

	typedef std::chrono::high_resolution_clock Clock;

	long long TimeStampLastRun = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();

	while (true) {
		int NReady = 0;
		ENetEvent Evt = {};
		long long TimeStampBeforeWait = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
		bool WaitIndicatesEventArrived = 0;
		if (TimeStampBeforeWait < TimeStampLastRun) /* backwards clock? wtf? */
			TimeStampBeforeWait = LLONG_MAX;        /* just ensure processing runs immediately */
		long long TimeRemainingToFullTick = GS_MGMT_ONE_TICK_MS - GS_MIN(TimeStampBeforeWait - TimeStampLastRun, GS_MGMT_ONE_TICK_MS);
		/* enet does not have a readinesss notification API - instead check + deliver one */
		if (0 > (NReady = enet_host_service(Mgmt->mHost, &Evt, TimeRemainingToFullTick)))
			GS_ERR_CLEANSUB(1);
		/* the way enet_host_service is used, do not error out until someone acquires ownership of the Evt ENetEvent */
		WaitIndicatesEventArrived = (NReady > 0);
		TimeStampLastRun = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
		if (!!(r = gs_vserv_mgmt_update(Mgmt, TimeStampLastRun, WaitIndicatesEventArrived, &Evt)))
			GS_GOTO_CLEANSUB();
	cleansub:
		if (!!r)
			GS_GOTO_CLEAN();
	}

clean:
	if (!!r)
		GS_ASSERT(0);
}

int stuff(struct GsAuxConfigCommonVars *CommonVars)
{
	int r = 0;

	std::random_device RandDev;

	struct GsVServMgmt *Mgmt = NULL;

	ENetAddress Addr = {};
	ENetHost *Host = NULL;
	ENetPeer *Peer = NULL;

	if (!!(r = gs_vserv_enet_init()))
		GS_GOTO_CLEAN();

	Addr.port = CommonVars->VServPortEnet;
	if (!!(r = enet_address_set_host(&Addr, CommonVars->VServHostNameBuf)))
		GS_GOTO_CLEAN();

	if (!(Host = enet_host_create(NULL, 128, 1, 0, 0)))
		GS_ERR_CLEAN(1);

	if (!(Peer = enet_host_connect(Host, &Addr, 1, 0)))
		GS_ERR_CLEAN(1);

	Mgmt = new GsVServMgmt();
	Mgmt->mAddr = Addr;
	Mgmt->mHost = GS_ARGOWN(&Host);
	Mgmt->mPeer = GS_ARGOWN(&Peer);
	Mgmt->mThread; /*dummy*/
	Mgmt->mRandGen = std::mt19937(RandDev());
	Mgmt->mRandDis = std::uniform_int_distribution<uint32_t>();

	Mgmt->mThread = sp<std::thread>(new std::thread(threadfunc, Mgmt));

	Mgmt->mThread->join();

clean:

	return r;
}

int main(int argc, char **argv)
{
	int r = 0;

	struct GsConfMap *ConfMap = NULL;
	struct GsAuxConfigCommonVars CommonVars = {};

	if (!!(r = gs_log_crash_handler_setup()))
		GS_GOTO_CLEAN();

	if (!!(r = gs_config_read_default_everything(&ConfMap)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_config_get_common_vars(ConfMap, &CommonVars)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_config_create_common_logs(ConfMap)))
		GS_GOTO_CLEAN();

	{
		log_guard_t Log(GS_LOG_GET("selfup"));
		if (!!(r = stuff(&CommonVars)))
			GS_GOTO_CLEAN();
	}

clean:
	GS_DELETE_F(&ConfMap, gs_conf_map_destroy);

	gs_log_crash_handler_dump_global_log_list_suffix("_log", strlen("_log"));

	if (!!r)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
