#include <cstring>
#include <cstdint>

#include <memory>
#include <vector>
#include <set>
#include <map>
#include <utility>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/vserv_net.h>

#define GS_VSERV_USER_ID_INVALID 0xFFFF

typedef uint8_t gs_vserv_group_mode_t;
typedef uint16_t gs_vserv_user_id_t;

enum GsVServCmd {
	GS_VSERV_CMD_BROADCAST = 'b',
	GS_VSERV_M_CMD_GROUPSET = 's',
	GS_VSERV_CMD_GROUP_MODE_MSG = 'm',
	GS_VSERV_CMD_IDENT = 'i',
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
	std::map<gs_vserv_user_id_t, std::pair<gs_vserv_user_id_t *, uint16_t> > mCacheIdGroup;
};

struct GsVServUser
{
	uint8_t *mNameBuf; size_t mLenName;
	uint8_t *mServBuf; size_t mLenServ;
	gs_vserv_user_id_t mId;
};

struct GsVServConExt
{
	struct GsAuxConfigCommonVars mCommonVars; /*notowned*/
	struct GsVServManageId *mManageId;
	std::map<GsAddr, sp<GsVServUser>, gs_addr_less_t> mUsers;
	std::map<gs_vserv_user_id_t, GsAddr> mUserIdAddr;
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
	ManageId->mCounter = Counter;

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

int gs_vserv_groupall_cache_refresh(struct GsVServGroupAll *GroupAll)
{
	int r = 0;

	GroupAll->mCacheIdGroup.clear();

	gs_vserv_user_id_t *Ptr = GroupAll->mIdVec;
	
	for (size_t i = 0; i < GroupAll->mSizeNum; i++) {
		if (Ptr + GroupAll->mSizeVec[i] > GroupAll->mIdVec + GroupAll->mIdNum)
			GS_ERR_CLEAN(1);
		for (size_t j = 0; j < GroupAll->mSizeVec[i]; j++) {
			auto itb = GroupAll->mCacheIdGroup.insert(std::make_pair(Ptr[j], std::make_pair(Ptr, GroupAll->mSizeVec[i])));
			if (! itb.second) /* duplicate id in IdVec */
				GS_ERR_CLEAN(1);
		}
		Ptr += GroupAll->mSizeVec[i];
	}

clean:

	return r;
}

/** returned pointer / vec ownership does not transfer to caller
    use of returned data must cease before caller allows GroupAll to be destroyed */
int gs_vserv_groupall_lookup(
	struct GsVServGroupAll *GroupAll,
	gs_vserv_user_id_t Id,
	gs_vserv_user_id_t **oIdVec, /*null-returnable*/
	size_t *oIdNum)
{
	auto it = GroupAll->mCacheIdGroup.find(Id);

	if (it == GroupAll->mCacheIdGroup.end()) {
		*oIdVec = NULL;
		*oIdNum = 0;
	}
	else {
		*oIdVec = it->second.first;
		*oIdNum = it->second.second;
	}
	return 0;
}

int gs_vserv_user_create(struct GsVServUser **oUser)
{
	int r = 0;

	struct GsVServUser *User = new GsVServUser();

	User->mNameBuf = NULL; User->mLenName = 0;
	User->mServBuf = NULL; User->mLenServ = 0;
	User->mId = GS_VSERV_USER_ID_INVALID;

	if (oUser)
		*oUser = GS_ARGOWN(&User);

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

int gs_vserv_user_genid(struct GsVServUser *User, struct GsVServManageId *ManageId)
{
	// FIXME: surely will leak id if old one was not released
	return gs_vserv_manage_id_genid(ManageId, &User->mId);
}

int gs_vserv_enqueue_idvec(
	struct GsVServRespond *Respond,
	struct GsPacket *Packet,
	gs_vserv_user_id_t *IdVec, size_t IdNum,
	const std::map<gs_vserv_user_id_t, GsAddr> &UserIdAddr)
{
	int r = 0;

	uint8_t *PacketCpy = NULL;
	size_t LenPacketCpy = 0;
	size_t TmpCnt = 0;
	GS_ALLOCA_VAR(AddrVec, const struct GsAddr *, IdNum);
	if (!!(r = gs_packet_copy_create(Packet, &PacketCpy, &LenPacketCpy)))
		GS_GOTO_CLEAN();
	for (size_t i = 0; i < IdNum; i++) {
		auto itb = UserIdAddr.find(IdVec[i]);
		if (itb == UserIdAddr.end())
			GS_LOG(I, PF, "missing userid [id=%d]", (int) IdVec[i]);
		else
			AddrVec[TmpCnt++] = &itb->second;
	}
	if (!!(r = gs_vserv_respond_enqueue_free(Respond, GS_ARGOWN(&PacketCpy), LenPacketCpy, AddrVec, TmpCnt)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE_F(&PacketCpy, gs_vserv_write_elt_del_sp_free);

	return r;
}

uint8_t gs_read_byte(uint8_t *Ptr)
{
	return Ptr[0];
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

	sp<GsVServUser> User;

	GS_LOG(I, PF, "pkt [%d]", (int)Packet->dataLength);

	if (Ext->mUsers.find(*Addr) == Ext->mUsers.end()) {
		struct GsVServUser *User = NULL;
		if (!!(r = gs_vserv_user_create(&User)))
			GS_GOTO_CLEAN_J(user);
		if (!!(r = gs_vserv_user_genid(User, Ext->mManageId)))
			GS_GOTO_CLEAN_J(user);
		Ext->mUserIdAddr[User->mId] = *Addr;
		Ext->mUsers[*Addr] = sp<GsVServUser>(GS_ARGOWN(&User), gs_vserv_user_destroy);
		GS_LOG(I, PF, "newcon [port=%d, id=%d]", (int) gs_addr_port(Addr), (int) Ext->mUsers[*Addr]->mId);
	clean_user:
		GS_DELETE_F(&User, gs_vserv_user_destroy);
	}

	User = Ext->mUsers[*Addr];

	if (gs_packet_space(Packet, 0, 1))
		GS_ERR_CLEAN(1);

	switch (Packet->data[0]) {

	case GS_VSERV_CMD_IDENT:
	{
		/* (cmd)[1], (lenname)[4], (lenserv)[4], (name)[lenname], (serv)[lenserv] */

		struct GsVServUser *UserN = NULL;

		size_t Offset = 0;
		uint32_t LenName = 0;
		uint32_t LenServ = 0;
		uint8_t *NameBuf = NULL;
		uint8_t *ServBuf = NULL;

		if (gs_packet_space(Packet, (Offset += 1), 4 /*lenname*/ + 4 /*lenserv*/))
			GS_ERR_CLEAN_J(ident, 1);

		LenName = gs_read_uint(Packet->data + Offset);
		LenServ = gs_read_uint(Packet->data + Offset + 4);

		if (gs_packet_space(Packet, (Offset += 8), LenName + LenServ))
			GS_ERR_CLEAN_J(ident, 1);

		if (!(NameBuf = (uint8_t *)malloc(LenName)))
			GS_ERR_CLEAN_J(ident, 1);

		if (!(ServBuf = (uint8_t *)malloc(LenServ)))
			GS_ERR_CLEAN_J(ident, 1);

		memcpy(NameBuf, Packet->data + Offset, LenName);
		memcpy(ServBuf, Packet->data + Offset + LenName, LenServ);

		if (!!(r = gs_vserv_user_create(&UserN)))
			GS_GOTO_CLEAN_J(ident);

		UserN->mNameBuf = GS_ARGOWN(&NameBuf); UserN->mLenName = LenName;
		UserN->mServBuf = GS_ARGOWN(&ServBuf); UserN->mLenServ = LenServ;
		UserN->mId = User->mId;

		// FIXME: state mutation
		Ext->mUsers[*Addr] = sp<GsVServUser>(GS_ARGOWN(&UserN), gs_vserv_user_destroy);

	clean_ident:
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	case GS_VSERV_CMD_BROADCAST:
	{
		uint8_t *PacketCpy = NULL;
		size_t LenPacketCpy = 0;
		size_t TmpCnt = 0;
		GS_ALLOCA_VAR(AddrVec, const struct GsAddr *, Ext->mUsers.size());
		if (!!(r = gs_packet_copy_create(Packet, &PacketCpy, &LenPacketCpy)))
			GS_GOTO_CLEAN_J(broadcast);
		for (auto it = Ext->mUsers.begin(); it != Ext->mUsers.end(); ++it)
			AddrVec[TmpCnt++] = &it->first;
		if (!!(r = gs_vserv_respond_enqueue_free(Respond, GS_ARGOWN(&PacketCpy), LenPacketCpy, AddrVec, TmpCnt)))
			GS_GOTO_CLEAN_J(broadcast);

	clean_broadcast:
		GS_DELETE_F(&PacketCpy, gs_vserv_write_elt_del_sp_free);
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	case GS_VSERV_M_CMD_GROUPSET:
	{
		/* (cmd)[1], (idnum)[4], (sznum)[4], (idvec[idnum])[2*idnum], (szvec[sznum])(2*sznum) */

		struct GsVServGroupAll *GroupAll = NULL;

		size_t Offset = 0;

		uint32_t IdNum = 0;
		uint32_t SizeNum = 0;
		gs_vserv_user_id_t *IdVec = NULL;
		uint16_t *SizeVec = NULL;

		if (gs_packet_space(Packet, (Offset += 1), 4 /*idnum*/ + 4 /*sznum*/))
			GS_ERR_CLEAN_J(groupset, 1);

		IdNum = gs_read_uint(Packet->data + Offset);
		SizeNum = gs_read_uint(Packet->data + Offset + 4);

		if (gs_packet_space(Packet, (Offset += 8), 2 * IdNum /*idvec*/ + 2 * SizeNum /*szvec*/))
			GS_ERR_CLEAN_J(groupset, 1);

		if (!(IdVec = (gs_vserv_user_id_t *)malloc(sizeof *IdVec * IdNum)))
			GS_ERR_CLEAN_J(groupset, 1);

		if (!(SizeVec = (uint16_t *)malloc(sizeof *SizeVec * SizeNum)))
			GS_ERR_CLEAN_J(groupset, 1);

		for (size_t i = 0; i < IdNum; i++)
			IdVec[i] = gs_read_short(Packet->data + Offset + (2 * i));

		for (size_t i = 0; i < SizeNum; i++)
			SizeVec[i] = gs_read_short(Packet->data + Offset + (2 * IdNum) + (2 * i));

		/* processing */

		if (!!(r = gs_vserv_groupall_create(GS_ARGOWN(&IdVec), IdNum, GS_ARGOWN(&SizeVec), SizeNum, &GroupAll)))
			GS_GOTO_CLEAN_J(groupset);

		if (!!(r = gs_vserv_groupall_cache_refresh(GroupAll)))
			GS_GOTO_CLEAN_J(groupset);

		// FIXME: state mutation
		Ext->mGroupAll = sp<GsVServGroupAll>(GS_ARGOWN(&GroupAll), gs_vserv_groupall_destroy);

	clean_groupset:
		GS_DELETE_F(&GroupAll, gs_vserv_groupall_destroy);
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	case GS_VSERV_CMD_GROUP_MODE_MSG:
	{
		/* (cmd)[1], (mode)[1], (id)[2], (blk)[2], (seq)[2], (data)[...] */

		/* hold on to GroupAll (for synchronization purposes) */
		sp<GsVServGroupAll> GroupAll = Ext->mGroupAll;

		size_t Offset = 0;
		uint8_t Mode = 0;
		gs_vserv_user_id_t Id = 0;
		uint16_t Blk = 0;
		uint16_t Seq = 0;

		if (gs_packet_space(Packet, (Offset += 1), 1 /*mode*/ + 2 /*id*/ + 2 /*blk*/ + 2 /*seq*/))
			GS_ERR_CLEAN_J(groupmodemsg, 1);

		Mode = gs_read_byte(Packet->data + Offset);
		Id   = gs_read_short(Packet->data + Offset + 1);
		Blk  = gs_read_short(Packet->data + Offset + 3);
		Seq  = gs_read_short(Packet->data + Offset + 5);

		Offset += 7; /* rest is data */

		switch (Mode)
		{
			
		case GS_VSERV_GROUP_MODE_S:
		{
			gs_vserv_user_id_t *IdVec = NULL;
			size_t IdNum = 0;
			if (!!(r = gs_vserv_groupall_lookup(GroupAll.get(), Id, &IdVec, &IdNum)))
				GS_GOTO_CLEAN_J(groupmodemsg);
			if (! IdVec) {
				GS_LOG(I, PF, "ungrouped [id=%d]", (int)Id);
				GS_ERR_CLEAN_J(groupmodemsg, 0);
			}
			if (!!(r = gs_vserv_enqueue_idvec(Respond, Packet, IdVec, IdNum, Ext->mUserIdAddr)))
				GS_GOTO_CLEAN();
		}
		break;

		default:
			GS_ASSERT(0);
		}

	clean_groupmodemsg:
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

int gs_vserv_crankm0(struct GsVServCtlCb *Cb, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespondM *Respond)
{
	// FIXME: rework locking before processing these messages async?
	//   for now, probably just mutex Ext wholesale
	GS_ASSERT(0);
	return 0;
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
	Cb0->base.CbCrankM = gs_vserv_crankm0;
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
