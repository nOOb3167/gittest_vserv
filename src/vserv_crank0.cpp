#include <cstring>
#include <cstdint>

#include <vector>
#include <set>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/vserv_net.h>

enum GsVServCmd {
	GS_VSERV_CMD_BROADCAST = 'b',
};

struct GsVServConExt
{
	struct GsAuxConfigCommonVars mCommonVars; /*notowned*/
	std::set<GsAddr *, gs_addr_p_less_t> mUsers;
};

struct GsVServCtlCb0
{
	struct GsVServCtlCb base;
	struct GsVServConExt *Ext; /*owned*/
};

uint16_t gs_read_short(uint8_t *Ptr)
{
	uint16_t r = 0;
	r |= (Ptr[0] & 0xFF) << 0;
	r |= (Ptr[1] & 0xFF) << 8;
	return r;
}

int gs_vserv_crank0(struct GsVServCtlCb *Cb, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond)
{
	int r = 0;

	struct GsVServConExt *Ext = ((struct GsVServCtlCb0 *) Cb)->Ext;

	GS_LOG(I, PF, "pkt [%d]", (int)Packet->dataLength);

	if (Ext->mUsers.find(Addr) == Ext->mUsers.end()) {
		Ext->mUsers.insert(Addr);
		GS_LOG(I, PF, "newcon [port=%d]", (int) gs_addr_port(Addr));
	}

	if (Packet->dataLength < 4)
		GS_ERR_CLEAN(1);

	switch (Packet->data[0]) {

	case GS_VSERV_CMD_BROADCAST:
	{
		uint8_t *PacketCpy = NULL;
		size_t LenPacketCpy = 0;
		size_t TmpCnt = 0;
		GS_ALLOCA_VAR(AddrVec, const struct GsAddr *, Ext->mUsers.size());
		if (!!(r = gs_packet_copy_create(Packet, &PacketCpy, &LenPacketCpy)))
			GS_GOTO_CLEAN_J(broadcast);
		for (auto it = Ext->mUsers.begin(); it != Ext->mUsers.end(); ++it)
			AddrVec[TmpCnt++] = *it;
		if (!!(r = gs_vserv_respond_enqueue_free(Respond, GS_ARGOWN(&PacketCpy), LenPacketCpy, AddrVec, Ext->mUsers.size())))
			GS_GOTO_CLEAN_J(broadcast);

	clean_broadcast:
		GS_DELETE_F(&PacketCpy, gs_vserv_write_elt_del_sp_free);
	}
	break;

	default:
		GS_ASSERT(0);

	}

clean:

	return r;
}

int gs_vserv_start_crank0(struct GsAuxConfigCommonVars *CommonVars)
{
	int r = 0;

	std::vector<int> ServFd;
	struct GsVServConExt *Ext = NULL;
	struct GsVServCtlCb0 *Cb0 = NULL;
	struct GsVServCtl *ServCtl = NULL;

	Ext = new GsVServConExt();
	Ext->mCommonVars = *CommonVars;
	Cb0 = new GsVServCtlCb0();
	Cb0->base.CbCrank = gs_vserv_crank0;
	Cb0->Ext = GS_ARGOWN(&Ext);

	ServFd.resize(1, -1);

	if (!!(r = gs_vserv_sockets_create(std::to_string(CommonVars->VServPort).c_str(), ServFd.data(), ServFd.size())))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_start_2(ServFd.data(), ServFd.size(), &Cb0->base, &ServCtl)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_ctl_quit_wait(ServCtl)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE(&Ext, struct GsVServConExt);
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);
	for (size_t i = 0; i < ServFd.size(); i++)
		gs_close_cond(&ServFd[i]);

	return r;
}
