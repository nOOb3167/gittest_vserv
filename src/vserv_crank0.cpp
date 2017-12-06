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

int g_vserv_crank0_timeout_check_disable = 0;

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

int gs_vserv_groupall_check_basic(struct GsVServGroupAll *GroupAll)
{
	int r = 0;

	std::set<gs_vserv_user_id_t> Uniq;
	size_t Cnt = 0;

	for (size_t i = 0; i < GroupAll->mIdNum; i++)
		Uniq.insert(GroupAll->mIdVec[i]);

	if (Uniq.size() != GroupAll->mIdNum)
		GS_ERR_CLEAN(1);

	for (size_t i = 0; i < GroupAll->mSizeNum; i++)
		Cnt += GroupAll->mSizeVec[i];

	if (Cnt != GroupAll->mIdNum)
		GS_ERR_CLEAN(1);

clean:

	return r;
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
	User->mTimeStampLastRecv = 0;

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
	Ext->mTimeStampLastUserTimeoutCheck = 0;
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

int gs_vserv_enqueue_oneshot(
	struct GsVServRespond *Respond,
	struct GsPacket *Packet,
	const struct GsAddr *Addr)
{
	int r = 0;

	uint8_t *PacketCpy = NULL;
	size_t LenPacketCpy = 0;

	if (!!(r = gs_packet_copy_create(Packet, &PacketCpy, &LenPacketCpy)))
		GS_GOTO_CLEAN();
	if (!!(r = gs_vserv_respond_enqueue_addrvec_free(Respond, GS_ARGOWN(&PacketCpy), LenPacketCpy, &Addr, 1)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE_F(&PacketCpy, gs_vserv_write_elt_del_sp_free);

	return r;
}

int gs_vserv_crank_identify_parse_ident(
	struct GsPacket *Packet,
	struct GsVServUser **oUserPartial /*id invalid*/,
	uint32_t *oRand)
{
	int r = 0;

	/* (cmd)[1], (rand)[4], (lenname)[4], (lenserv)[4], (name)[lenname], (serv)[lenserv] */

	struct GsVServUser *UserPartial = NULL;

	size_t Offset = 0;
	uint32_t Rand = 0;
	uint8_t *NameBuf = NULL; uint32_t LenName = 0;
	uint8_t *ServBuf = NULL; uint32_t LenServ = 0;

	if (gs_packet_space(Packet, 0, 1) || Packet->data[0] != GS_VSERV_CMD_IDENT)
		GS_ERR_CLEAN(1);

	if (gs_packet_space(Packet, (Offset += 1), 4 /*rand*/ + 4 /*lenname*/ + 4 /*lenserv*/))
		GS_ERR_CLEAN(1);

	Rand = gs_read_uint(Packet->data + Offset + 0);
	LenName = gs_read_uint(Packet->data + Offset + 4);
	LenServ = gs_read_uint(Packet->data + Offset + 8);

	if (gs_packet_space(Packet, (Offset += 12), LenName + LenServ))
		GS_ERR_CLEAN(1);

	if (!(NameBuf = (uint8_t *)malloc(LenName)))
		GS_ERR_CLEAN(1);

	if (!(ServBuf = (uint8_t *)malloc(LenServ)))
		GS_ERR_CLEAN(1);

	memcpy(NameBuf, Packet->data + Offset, LenName);
	memcpy(ServBuf, Packet->data + Offset + LenName, LenServ);

	if (!!(r = gs_vserv_user_create(&UserPartial)))
		GS_GOTO_CLEAN();

	UserPartial->mNameBuf = GS_ARGOWN(&NameBuf); UserPartial->mLenName = LenName;
	UserPartial->mServBuf = GS_ARGOWN(&ServBuf); UserPartial->mLenServ = LenServ;
	UserPartial->mId = GS_VSERV_USER_ID_INVALID;

	if (oUserPartial)
		*oUserPartial = GS_ARGOWN(&UserPartial);

	if (oRand)
		*oRand = Rand;

clean:
	GS_DELETE_F(&UserPartial, gs_vserv_user_destroy);

	return r;
}

int gs_vserv_crank_identify_respond_ident_ack(
	struct GsAddr *Addr,
	struct GsVServRespond *Respond,
	uint32_t UserRand,
	gs_vserv_user_id_t UserId)
{
	int r = 0;

	/* (cmd)[1], (rand)[4], (id)[2] */

	uint8_t IdentAckBuf[7] = {};
	struct GsPacket PacketOut = { IdentAckBuf, 7 };

	if (gs_packet_space(&PacketOut, 0, 1 /*cmd*/ + 4 /*rand*/ + 2 /*id*/))
		GS_ERR_CLEAN(1);

	gs_write_byte(IdentAckBuf + 0, GS_VSERV_CMD_IDENT_ACK);
	gs_write_uint(IdentAckBuf + 1, UserRand);
	gs_write_uint(IdentAckBuf + 5, UserId);

	if (!!(r = gs_vserv_enqueue_oneshot(Respond, &PacketOut, Addr)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_crank_identify(
	struct GsVServConExt *Ext,
	struct GsPacket *Packet,
	struct GsAddr *Addr,
	struct GsVServRespond *Respond,
	sp<GsVServUser> *oUser)
{
	int r = 0;

	auto it = Ext->mUsers.find(*Addr);

	struct GsVServUser *NewUser = NULL;
	uint32_t UserRand = 0;

	/* return existing */
	if (it != Ext->mUsers.end())
		GS_ERR_NO_CLEAN(0);

	/* missing - must be ident. create new. */
	if (!!(r = gs_vserv_crank_identify_parse_ident(Packet, &NewUser, &UserRand)))
		GS_GOTO_CLEAN();
	GS_ASSERT(NewUser->mId == GS_VSERV_USER_ID_INVALID);
	if (!!(r = gs_vserv_user_genid(NewUser, Ext->mManageId)))
		GS_GOTO_CLEAN();
	// FIXME: from here on, something needs to release the generated Id on failure
	/* acknowledge new */
	if (!!(r = gs_vserv_crank_identify_respond_ident_ack(Addr, Respond, UserRand, NewUser->mId)))
		GS_GOTO_CLEAN();
	/* insert new */
	Ext->mUserIdAddr.insert(std::make_pair(NewUser->mId, *Addr));
	it = Ext->mUsers.insert(std::make_pair(*Addr, sp<GsVServUser>(GS_ARGOWN(&NewUser), gs_vserv_user_destroy))).first;

	GS_LOG(I, PF, "newcon [addr=%X, port=%d, id=%d]", (unsigned int)gs_addr_addr(Addr), (int)gs_addr_port(Addr), (int)Ext->mUsers[*Addr]->mId);

noclean:
	if (oUser)
		*oUser = it->second;

clean:
	GS_DELETE_F(&NewUser, gs_vserv_user_destroy);

	return r;
}

int gs_vserv_crank_timeout_recv(
	struct GsVServConExt *Ext,
	struct GsAddr *Addr,
	struct GsVServUser *UserRecv,
	long long TimeStamp,
	int *oHaveAnyTimeout)
{
	int r = 0;

	int HaveAnyTimeout = 0;

	UserRecv->mTimeStampLastRecv = TimeStamp;

	if (g_vserv_crank0_timeout_check_disable)
		GS_ERR_NO_CLEAN(0);

	if (TimeStamp < Ext->mTimeStampLastUserTimeoutCheck + GS_CLNT_ARBITRARY_USER_TIMEOUT_CHECK_MS)
		GS_ERR_NO_CLEAN(0);

	for (auto it = Ext->mUsers.begin(); it != Ext->mUsers.end(); ++it) {
		if (TimeStamp < it->second->mTimeStampLastRecv + GS_CLNT_ARBITRARY_USER_TIMEOUT_MS)
			continue;
		/* timed out */
		/* UserRecv couldn't have timed out - supposedly we've just refreshed its timestamp */
		GS_ASSERT(it->second->mId != UserRecv->mId);
		HaveAnyTimeout = 1;
		break;
	}

noclean:
	if (oHaveAnyTimeout)
		*oHaveAnyTimeout = HaveAnyTimeout;

clean:

	return r;
}

int gs_vserv_crank_timeout_disconnect(
	struct GsVServConExt *Ext,
	long long TimeStamp)
{
	int r = 0;

	for (auto it = Ext->mUsers.begin(); it != Ext->mUsers.end(); /*dummy*/) {
		if (TimeStamp < it->second->mTimeStampLastRecv + GS_CLNT_ARBITRARY_USER_TIMEOUT_MS) {
			++it;
		}
		else {
			/* timed out */
			Ext->mUserIdAddr.erase(it->second->mId);
			it = Ext->mUsers.erase(it);
			break;
		}
	}

clean:

	return r;
}

int gs_vserv_crank0(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond)
{
	int r = 0;

	GS_MACRO_VSERV_CMD_LIST_VAR(CmdNumName);

	struct GsVServConExt *Ext = (struct GsVServConExt *) gs_vserv_ctl_get_con(ServCtl);

	sp<GsVServUser> User;

	long long TimeStamp = 0;
	int HaveAnyTimeout = 0;

	if (!!(r = gs_vserv_lock_lock(Ext->mLock)))
		GS_GOTO_CLEAN();

	TimeStamp = gs_vserv_timestamp();

	if (!!(r = gs_vserv_crank_identify(Ext, Packet, Addr, Respond, &User)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_vserv_crank_timeout_recv(Ext, Addr, User.get(), TimeStamp, &HaveAnyTimeout)))
		GS_GOTO_CLEAN();

	if (gs_packet_space(Packet, 0, 1))
		GS_ERR_CLEAN(1);

	for (size_t i = 0; i < CmdNumNameNum; i++)
		if (Packet->data[0] == CmdNumName[i].mNum)
			GS_LOG(I, PF, "pkt [cmd=[%s], len=%d]", CmdNumName[i].mStr, (int) Packet->dataLength);

	switch (Packet->data[0]) {

	case GS_VSERV_CMD_IDENT:
	{
		/* intention is to have already had a go at parsing this message
		   in gs_vserv_crank_identify. therefore just passthrough. */
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

	case GS_VSERV_CMD_PING:
	{
		/* (cmd)[1] */

		size_t Offset = 0;

		if (gs_packet_space(Packet, (Offset += 1), 0))
			GS_ERR_CLEAN_J(ping, 1);

	clean_ping:
		if (!!r)
			GS_GOTO_CLEAN();
	}
	break;

	default:
		GS_ASSERT(0);

	}

noclean:
	if (HaveAnyTimeout) {
		if (!!(r = gs_vserv_crank_timeout_disconnect(Ext, TimeStamp)))
			GS_GOTO_CLEAN();
	}

clean:
	GS_RELEASE_F(Ext->mLock, gs_vserv_lock_release);

	return r;
}

int gs_vserv_crankm0(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond)
{
	int r = 0;

	GS_MACRO_VSERV_CMD_LIST_VAR(CmdNumName);

	struct GsVServConExt *Ext = (struct GsVServConExt *) gs_vserv_ctl_get_con(ServCtl);

	if (!!(r = gs_vserv_lock_lock(Ext->mLock)))
		GS_GOTO_CLEAN();

	if (gs_packet_space(Packet, 0, 1))
		GS_ERR_CLEAN(1);

	for (size_t i = 0; i < CmdNumNameNum; i++)
		if (Packet->data[0] == CmdNumName[i].mNum)
			GS_LOG(I, PF, "pkt [cmd=[%s], len=%d]", CmdNumName[i].mStr, (int) Packet->dataLength);

	switch (Packet->data[0]) {

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

		if (!!(r = gs_vserv_groupall_check_basic(GroupAll)))
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

	case GS_VSERV_CMD_IDGET:
	{
		/* (cmd)[1], (generation)[4] */

		size_t Offset = 0;
		uint32_t Generation = 0;
		size_t TmpCnt = 0;
		size_t IdNum = 0;
		gs_vserv_user_id_t *IdVec = NULL;

		struct GsPacket PacketOut = {};
		size_t OffsetOut = 0;

		if (gs_packet_space(Packet, (Offset += 1), 4 /*generation*/))
			GS_ERR_CLEAN_J(idget, 1);

		Generation = gs_read_uint(Packet->data + Offset);

		Offset += 4;

		// FIXME: maybe it is better to source IDs from mGroupAll ?
		IdNum = Ext->mUserIdAddr.size();
		GS_ALLOCA_ASSIGN(IdVec, gs_vserv_user_id_t, IdNum);

		for (auto it = Ext->mUserIdAddr.begin(); it != Ext->mUserIdAddr.end() && TmpCnt < IdNum; ++it, ++TmpCnt)
			IdVec[TmpCnt] = it->first;
		GS_ASSERT(TmpCnt == IdNum);

		/* (cmd)[1], (generation)[4], (idnum)[4], (idvec)[2*idnum] */

		PacketOut.dataLength = GS_VSERV_NAMELEN_ARBITRARY_SIZE_MAX;
		GS_ALLOCA_ASSIGN(PacketOut.data, uint8_t, PacketOut.dataLength);

		if (gs_packet_space(&PacketOut, (OffsetOut), 1 /*cmd*/))
			GS_ERR_CLEAN_J(idget, 1);

		gs_write_byte(PacketOut.data + OffsetOut, GS_VSERV_CMD_IDS);

		if (gs_packet_space(&PacketOut, (OffsetOut += 1), 4 /*generation*/ + 4 /*idnum*/))
			GS_ERR_CLEAN_J(idget, 1);

		// FIXME: implement generation properly (on ID source data structure)
		gs_write_uint(PacketOut.data + OffsetOut + 0, Generation + 1);
		gs_write_uint(PacketOut.data + OffsetOut + 4, IdNum);

		OffsetOut += 8; /* rest filled with idvec */

		for (size_t i = 0; i < IdNum; i++) {
			if (gs_packet_space(&PacketOut, (OffsetOut), 2 /*id*/))
				GS_ERR_CLEAN_J(idget, 1);
			gs_write_short(PacketOut.data + OffsetOut, IdVec[i]);
			OffsetOut += 2;
		}

		/* adjust packet to real length (vs maximum allowed) */

		PacketOut.dataLength = OffsetOut;

		/* respond */

		if (!!(r = gs_vserv_enqueue_oneshot(Respond, &PacketOut, Addr)))
			GS_GOTO_CLEAN_J(idget);

	clean_idget:
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
