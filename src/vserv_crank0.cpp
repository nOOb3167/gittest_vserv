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
#include <gittest/vserv_work.h>
#include <gittest/vserv_mgmt_priv.h>
#include <gittest/vserv_crank0_priv.h>

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

/** returned pointer / vec ownership does not transfer to caller
    use of returned data must cease before caller allows GroupAll to be destroyed */
int gs_vserv_groupall_all(
	struct GsVServGroupAll *GroupAll,
	gs_vserv_user_id_t Id,
	gs_vserv_user_id_t **oIdVec, /*null-returnable*/
	size_t *oIdNum)
{
	*oIdVec = GroupAll->mIdVec;
	*oIdNum = GroupAll->mIdNum;
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

int gs_vserv_con_ext_create(
	struct GsAuxConfigCommonVars *CommonVars,
	struct GsVServConExt **oExt)
{
	int r = 0;

	struct GsVServConExt *Ext = NULL;

	struct GsVServManageId *ManageId = NULL;
	struct GsVServGroupAll *GroupAll = NULL;

	if (!!(r = gs_vserv_manage_id_create(&ManageId)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_groupall_create(NULL, 0, NULL, 0, &GroupAll)))
		GS_GOTO_CLEAN();

	Ext = new GsVServConExt();
	Ext->mCommonVars = *CommonVars;
	Ext->mManageId = GS_ARGOWN(&ManageId);
	Ext->mUsers;      /*dummy*/
	Ext->mUserIdAddr; /*dummy*/
	Ext->mGroupAll = sp<GsVServGroupAll>(GS_ARGOWN(&GroupAll), gs_vserv_groupall_destroy);
	Ext->mLock = NULL;

	if (!!(r = gs_vserv_lock_create(&Ext->mLock)))
		GS_GOTO_CLEAN();

	if (oExt)
		*oExt = GS_ARGOWN(&Ext);

clean:
	GS_DELETE_F(&ManageId, gs_vserv_manage_id_destroy);
	GS_DELETE_F(&GroupAll, gs_vserv_groupall_destroy);
	// FIXME:
	//GS_DELETE_F(&Ext, gs_vserv_con_ext_destroy);

	return r;
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
	if (!!(r = gs_vserv_respond_enqueue_addrvec_free(Respond, GS_ARGOWN(&PacketCpy), LenPacketCpy, AddrVec, TmpCnt)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE_F(&PacketCpy, gs_vserv_write_elt_del_sp_free);

	return r;
}

int gs_vserv_crank0(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond)
{
	int r = 0;

	struct GsVServConExt *Ext = (struct GsVServConExt *) gs_vserv_ctl_get_con(ServCtl);

	sp<GsVServUser> User;

	if (!!(r = gs_vserv_lock_lock(Ext->mLock)))
		GS_GOTO_CLEAN();

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
		/* (cmd)[1], (rand)[4], (lenname)[4], (lenserv)[4], (name)[lenname], (serv)[lenserv] */

		struct GsVServUser *UserN = NULL;

		size_t Offset = 0;
		uint32_t Rand = 0;
		uint32_t LenName = 0;
		uint32_t LenServ = 0;
		uint8_t *NameBuf = NULL;
		uint8_t *ServBuf = NULL;

		uint8_t IdentAckBuf[7] = {};
		struct GsPacket PacketOut = { IdentAckBuf, 7 };

		if (gs_packet_space(Packet, (Offset += 1), 4 /*rand*/ + 4 /*lenname*/ + 4 /*lenserv*/))
			GS_ERR_CLEAN_J(ident, 1);

		Rand    = gs_read_uint(Packet->data + Offset + 0);
		LenName = gs_read_uint(Packet->data + Offset + 4);
		LenServ = gs_read_uint(Packet->data + Offset + 8);

		if (gs_packet_space(Packet, (Offset += 12), LenName + LenServ))
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

		/* (cmd)[1], (rand)[4], (id)[2] */

		if (gs_packet_space(Packet, 0, 1 /*cmd*/ + 4 /*rand*/ + 2 /*id*/))
			GS_GOTO_CLEAN_J(ident);

		gs_write_byte(IdentAckBuf + 0, GS_VSERV_CMD_IDENT_ACK);
		gs_write_uint(IdentAckBuf + 1, Rand);
		gs_write_uint(IdentAckBuf + 5, User->mId);

		if (!!(r = gs_vserv_enqueue_idvec(Respond, &PacketOut, &User->mId, 1, Ext->mUserIdAddr)))
			GS_GOTO_CLEAN_J(ident);

	clean_ident:
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	case GS_VSERV_CMD_NAMEGET:
	{
		/* (cmd)[1], (idvec)[2*..] */

		size_t Offset = 1;
		size_t IdNum = 0;
		gs_vserv_user_id_t *IdVec = NULL;

		uint8_t *OutBuf = NULL;
		size_t LenOut = 0;
		const size_t LimitOut = GS_VSERV_NAMELEN_ARBITRARY_SIZE_MAX;
		struct GsPacket PacketOut = {};
		size_t OffsetOut = 0;

		if ((Packet->dataLength - Offset) % 2 != 0)
			GS_ERR_CLEAN_J(nameget, 1);

		IdNum = (Packet->dataLength - Offset) / 2;
		GS_ALLOCA_ASSIGN(IdVec, gs_vserv_user_id_t, IdNum);

		for (size_t i = 0; i < IdNum; i++)
			IdVec[i] = gs_read_short(Packet->data + Offset + (2 * i));

		/* (cmd)[1], ((id)[2], (namenum)[4] (namevec)[namenum])[..] */

		if (!(OutBuf = (uint8_t *) malloc(LimitOut)))
			GS_ERR_CLEAN_J(nameget, 1);

		PacketOut.data = GS_ARGOWN(&OutBuf);
		PacketOut.dataLength = LimitOut;

		if (gs_packet_space(&PacketOut, (OffsetOut), 1 /*cmd*/))
			GS_ERR_CLEAN_J(nameget, 1);

		gs_write_byte(PacketOut.data + OffsetOut, GS_VSERV_CMD_NAMES);

		OffsetOut += 1;

		for (size_t i = 0; i < IdNum; i++) {
			auto it = Ext->mUserIdAddr.find(IdVec[i]);
			if (it == Ext->mUserIdAddr.end())
				continue;
			auto it2 = Ext->mUsers.find(it->second);
			if (it2 == Ext->mUsers.end())
				continue;
			if (gs_packet_space(&PacketOut, (OffsetOut), 4 /*namenum*/ + it2->second->mLenName /*namevec*/))
				break;
			gs_write_uint(PacketOut.data + OffsetOut, it2->second->mLenName);
			memcpy(PacketOut.data + OffsetOut + 4, it2->second->mNameBuf, it2->second->mLenName);
			Offset += 4 + it2->second->mLenName;
		}

		/* adjust packet to real length (vs maximum allowed) */

		PacketOut.dataLength = Offset;

		/* respond */

		if (!!(r = gs_vserv_enqueue_idvec(Respond, &PacketOut, &User->mId, 1, Ext->mUserIdAddr)))
			GS_GOTO_CLEAN_J(nameget);

	clean_nameget:
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
		if (!!(r = gs_vserv_respond_enqueue_addrvec_free(Respond, GS_ARGOWN(&PacketCpy), LenPacketCpy, AddrVec, TmpCnt)))
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

		/* allow client to send the packet with 'id' field value GS_VSERV_USER_ID_SERVFILL.
		   upon receiving such 'id', substitute it with the client's actual id. */

		if (Id == GS_VSERV_USER_ID_SERVFILL) {
			gs_write_short(Packet->data + Offset + 1, User->mId);
			Id = gs_read_short(Packet->data + Offset + 1);
		}

		/* the value of 'id' field is not really a choice anyway.
		   it must be the client's actual id. either apriori(sic) or after the above fixup. */

		if (Id != User->mId)
			GS_ERR_CLEAN_J(groupmodemsg, 1);

		Offset += 7; /* rest is data */

		switch (Mode)
		{

		case GS_VSERV_GROUP_MODE_S:
		{
			gs_vserv_user_id_t *IdVec = NULL;
			size_t IdNum = 0;
			gs_vserv_user_id_t DummyId = 0;
			if (!!(r = gs_vserv_groupall_lookup(GroupAll.get(), Id, &IdVec, &IdNum)))
				GS_GOTO_CLEAN_J(groupmodemsg);
			if (! IdVec) {
				// FIXME: for testing purposes, ungrouped just routes to id0
				static unsigned int Cnt = 0;
				if (!(Cnt++ % 250))
					GS_LOG(I, PF, "ungrouped [id=%d]", (int)Id);
				IdVec = &DummyId;
				IdNum = 1;

				//GS_LOG(I, PF, "ungrouped [id=%d]", (int)Id);
				//GS_ERR_CLEAN_J(groupmodemsg, 0);
			}
			if (!!(r = gs_vserv_enqueue_idvec(Respond, Packet, IdVec, IdNum, Ext->mUserIdAddr)))
				GS_GOTO_CLEAN();
		}
		break;

		default:
			GS_ASSERT(0);
		}

	noclean_groupmodemsg:

	clean_groupmodemsg:
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	default:
		GS_ASSERT(0);

	}

clean:
	GS_RELEASE_F(Ext->mLock, gs_vserv_lock_release);

	return r;
}

int gs_vserv_crankm0(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond)
{
	int r = 0;

	struct GsVServConExt *Ext = (struct GsVServConExt *) gs_vserv_ctl_get_con(ServCtl);

	if (!!(r = gs_vserv_lock_lock(Ext->mLock)))
		GS_GOTO_CLEAN();

clean:
	GS_RELEASE_F(Ext->mLock, gs_vserv_lock_release);

	return r;
}

int gs_vserv_start_crank0(struct GsAuxConfigCommonVars *CommonVars)
{
	int r = 0;

	std::vector<int> ServFd;
	struct GsVServConExt *Ext = NULL;
	struct GsVServWorkCb WorkCb = {};
	struct GsVServMgmtCb MgmtCb = {};
	struct GsVServQuitCtl *QuitCtl = NULL;
	struct GsVServWork *Work = NULL;
	struct GsVServMgmt *Mgmt = NULL;
	struct GsVServCtl *ServCtl = NULL;

	size_t ThreadNum = 1;

	WorkCb.CbThreadFunc = gs_vserv_receive_func;
	WorkCb.CbCrank = gs_vserv_crank0;

	MgmtCb.CbThreadFuncM = gs_vserv_mgmt_receive_func;
	MgmtCb.CbCrankM = gs_vserv_crankm0;

	/* socket FD creation split and pushed upwards from gs_vserv_start_2 / ServCtl creation.
	   prep work for future systemd integration (socket activation receives FD from outside) */

	ServFd.resize(ThreadNum, -1);

	if (!!(r = gs_vserv_sockets_create(std::to_string(CommonVars->VServPort).c_str(), ServFd.data(), ServFd.size())))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_con_ext_create(CommonVars, &Ext)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_quit_ctl_create(&QuitCtl)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_ctl_create_part(ThreadNum, GS_BASE_ARGOWN(&Ext), WorkCb, MgmtCb, &ServCtl)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_work_create(ThreadNum, ServFd.data(), ServFd.size(), ServCtl, QuitCtl, &Work)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_mgmt_create(CommonVars, QuitCtl, &Mgmt)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_ctl_create_finish(ServCtl, GS_ARGOWN(&QuitCtl), GS_ARGOWN(&Work), GS_ARGOWN(&Mgmt))))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_ctl_quit_wait(ServCtl)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);
	GS_DELETE_F(&Work, gs_vserv_work_destroy);
	// FIXME: GS_DELETE_F(&Ext, gs_vserv_con_ext_destroy);
	for (size_t i = 0; i < ServFd.size(); i++)
		gs_close_cond(&ServFd[i]);

	return r;
}
