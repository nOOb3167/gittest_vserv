#include <cstring>
#include <cstdint>

#include <memory>
#include <vector>
#include <set>
#include <map>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/vserv_net.h>

typedef uint8_t gs_vserv_group_mode_t;
typedef uint16_t gs_vserv_user_id_t;

enum GsVServCmd {
	GS_VSERV_CMD_BROADCAST = 'b',
	GS_VSERV_CMD_GROUPSET = 's',
};

enum GsVServGroupMode
{
	GS_VSERV_GROUP_MODE_S = 's',
};

struct GsVServManageId
{
	std::set<gs_vserv_user_id_t> mTaken;
	size_t mCounter;
};

struct GsVServGroupAll
{
	gs_vserv_user_id_t *mIdVec; size_t mIdNum;
	uint16_t *mSizeVec; size_t mSizeNum;
};

struct GsVServGroup
{
	sp<GsVServGroupAll> mAll;
	size_t mMyOffset;
	size_t mMySize;
};

struct GsVServUserGroup
{
	sp<GsVServGroup> mModeS;
};

struct GsVServUser
{
	// name
	// serv
	gs_vserv_user_id_t mId;
	struct GsVServUserGroup mGroup;
};

struct GsVServConExt
{
	struct GsAuxConfigCommonVars mCommonVars; /*notowned*/
	struct GsVServManageId *mManageId;
	std::map<GsAddr *, sp<GsVServUser>, gs_addr_p_less_t> mUsers;
	sp<GsVServGroupAll> mGroupAll;
};

struct GsVServCtlCb0
{
	struct GsVServCtlCb base;
	struct GsVServConExt *Ext; /*owned*/
};

int gs_vserv_manage_id_create(struct GsVServManageId **oManageId)
{
	int r = 0;

	struct GsVServManageId *ManageId = new GsVServManageId();

	ManageId->mTaken; /*dummy*/
	ManageId->mCounter = 0;

	if (oManageId)
		*oManageId = GS_ARGOWN(&ManageId);

clean:
	GS_DELETE(&ManageId, struct GsVServManageId);

	return r;
}

int gs_vserv_manage_id_destroy(struct GsVServManageId *ManageId)
{
	GS_DELETE(&ManageId, struct GsVServManageId);
	return 0;
}

int gs_vserv_manage_id_genid(struct GsVServManageId *ManageId, gs_vserv_user_id_t *oId)
{
	int r = 0;

	uint16_t Counter = ManageId->mCounter % UINT16_MAX;
	size_t RetryLimit = UINT16_MAX;

	while (ManageId->mTaken.find(Counter) != ManageId->mTaken.end()) {
		Counter = (Counter + 1) % UINT16_MAX;
		if (RetryLimit-- == 0)
			GS_ERR_CLEAN(1);
	}

	ManageId->mTaken.insert(Counter);

	if (oId)
		*oId = Counter;

clean:

	return r;
}

int gs_vserv_groupall_create(
	gs_vserv_user_id_t *IdVec, size_t IdNum, /*owned*/
	uint16_t *SizeVec, size_t SizeNum, /*owned*/
	struct GsVServGroupAll **oGroupAll)
{
	int r = 0;

	struct GsVServGroupAll *GroupAll = new GsVServGroupAll();

	GroupAll->mIdVec = GS_ARGOWN(&IdVec);
	GroupAll->mIdNum = IdNum;
	GroupAll->mSizeVec = GS_ARGOWN(&SizeVec);
	GroupAll->mSizeNum = SizeNum;

	if (oGroupAll)
		*oGroupAll = GS_ARGOWN(&GroupAll);

clean:
	// FIXME: freeing resources
	GS_DELETE(&GroupAll, struct GsVServGroupAll);

	return r;
}

int gs_vserv_groupall_destroy(struct GsVServGroupAll *GroupAll)
{
	GS_DELETE(&GroupAll, struct GsVServGroupAll);
	return 0;
}

int gs_vserv_user_create(struct GsVServManageId *ManageId, struct GsVServUser **oUser)
{
	int r = 0;

	struct GsVServUser *User = new GsVServUser();

	User->mGroup; /*dummy*/

	// FIXME: release the id on error
	if (gs_vserv_manage_id_genid(ManageId, &User->mId))
		GS_GOTO_CLEAN();

	if (oUser)
		*oUser = User;

clean:
	GS_DELETE(&User, struct GsVServUser);

	return r;
}

int gs_vserv_user_destroy(struct GsVServUser *User)
{
	// FIXME: conditionally (?) release the id if still owned at destruction time
	GS_DELETE(&User, struct GsVServUser);
	return 0;
}

uint16_t gs_read_short(uint8_t *Ptr)
{
	uint16_t r = 0;
	r |= (Ptr[0] & 0xFF) << 0;
	r |= (Ptr[1] & 0xFF) << 8;
	return r;
}

uint32_t gs_read_uint(uint8_t *Ptr)
{
	uint32_t r = 0;
	r |= (Ptr[0] & 0xFF) << 0;
	r |= (Ptr[1] & 0xFF) << 8;
	r |= (Ptr[2] & 0xFF) << 16;
	r |= (Ptr[3] & 0xFF) << 24;
	return r;
}

int gs_vserv_crank0(struct GsVServCtlCb *Cb, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond)
{
	int r = 0;

	struct GsVServConExt *Ext = ((struct GsVServCtlCb0 *) Cb)->Ext;

	GS_LOG(I, PF, "pkt [%d]", (int)Packet->dataLength);

	if (Ext->mUsers.find(Addr) == Ext->mUsers.end()) {
		struct GsVServUser *User = NULL;
		if (!!(r = gs_vserv_user_create(Ext->mManageId, &User)))
			GS_GOTO_CLEAN_J(user);
		Ext->mUsers[Addr] = sp<GsVServUser>(GS_ARGOWN(&User), gs_vserv_user_destroy);
		GS_LOG(I, PF, "newcon [port=%d, id=%d]", (int) gs_addr_port(Addr), (int) Ext->mUsers[Addr]->mId);
	clean_user:
		GS_DELETE_F(&User, gs_vserv_user_destroy);
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
			AddrVec[TmpCnt++] = it->first;
		if (!!(r = gs_vserv_respond_enqueue_free(Respond, GS_ARGOWN(&PacketCpy), LenPacketCpy, AddrVec, Ext->mUsers.size())))
			GS_GOTO_CLEAN_J(broadcast);

	clean_broadcast:
		GS_DELETE_F(&PacketCpy, gs_vserv_write_elt_del_sp_free);
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	case GS_VSERV_CMD_GROUPSET:
	{
		/* (cmd)[1], (idnum)[4], (idvec[idnum])[2*idnum] */

		struct GsVServGroupAll *GroupAll = NULL;

		size_t Offset = 0;

		gs_vserv_user_id_t *IdVec = NULL;
		uint32_t IdNum = 0;
		uint16_t *SizeVec = NULL;
		uint32_t SizeNum = 0;

		/* id vec */

		if (gs_packet_space(Packet, (Offset += 1), 4 /*idnum*/))
			GS_ERR_CLEAN_J(groupset, 1);

		IdNum = gs_read_uint(Packet->data);

		if (gs_packet_space(Packet, (Offset += 4), 2 * IdNum /*idvec*/))
			GS_ERR_CLEAN_J(groupset, 1);

		if (!(IdVec = (gs_vserv_user_id_t *)malloc(sizeof *IdVec * IdNum)))
			GS_ERR_CLEAN_J(groupset, 1);

		for (size_t i = 0; i < IdNum; i++)
			IdVec[i] = gs_read_short(Packet->data + Offset + (2 * i));

		/* size vec */

		if (gs_packet_space(Packet, (Offset += (2 * IdNum)), 4 /*sizenum*/))
			GS_ERR_CLEAN_J(groupset, 1);

		SizeNum = gs_read_uint(Packet->data + Offset);

		if (gs_packet_space(Packet, (Offset += 4), 2 * SizeNum))
			GS_ERR_CLEAN_J(groupset, 1);

		if (!(SizeVec = (uint16_t *)malloc(sizeof *SizeVec * SizeNum)))
			GS_ERR_CLEAN_J(groupset, 1);

		for (size_t i = 0; i < SizeNum; i++)
			SizeVec[i] = gs_read_short(Packet->data + Offset + (2 * i));

		/* processing */

		if (!!(r = gs_vserv_groupall_create(GS_ARGOWN(&IdVec), IdNum, GS_ARGOWN(&SizeVec), SizeNum, &GroupAll)))
			GS_GOTO_CLEAN_J(groupset);

		Ext->mGroupAll = sp<GsVServGroupAll>(GS_ARGOWN(&GroupAll), gs_vserv_groupall_destroy);

	clean_groupset:
		GS_DELETE_F(&GroupAll, gs_vserv_groupall_destroy);
		if (!!r)
			GS_GOTO_CLEAN();
	}

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
	struct GsVServManageId *ManageId = NULL;
	struct GsVServGroupAll *GroupAll = NULL;
	struct GsVServConExt *Ext = NULL;
	struct GsVServCtlCb0 *Cb0 = NULL;
	struct GsVServCtl *ServCtl = NULL;

	if (!!(r = gs_vserv_manage_id_create(&ManageId)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_groupall_create(NULL, 0, NULL, 0, &GroupAll)))
		GS_GOTO_CLEAN();

	Ext = new GsVServConExt();
	Ext->mCommonVars = *CommonVars;
	Ext->mManageId = GS_ARGOWN(&ManageId);
	Ext->mUsers; /*dummy*/
	Ext->mGroupAll = sp<GsVServGroupAll>(GS_ARGOWN(&GroupAll), gs_vserv_groupall_destroy);

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
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);
	// FIXME: GS_DELETE_F(&Ext, gs_vserv_con_ext_destroy);
	GS_DELETE_F(&GroupAll, gs_vserv_groupall_destroy);
	GS_DELETE_F(&ManageId, gs_vserv_manage_id_destroy);
	for (size_t i = 0; i < ServFd.size(); i++)
		gs_close_cond(&ServFd[i]);

	return r;
}
