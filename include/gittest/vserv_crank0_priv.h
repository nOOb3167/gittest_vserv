#ifndef _VSERV_CRANK0_PRIV_H_
#define _VSERV_CRANK0_PRIV_H_

#include <stddef.h>

#include <map>
#include <set>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>
#include <gittest/vserv_clnt_helpers.h>

#define GS_VSERV_NAMELEN_ARBITRARY_SIZE_MAX 1472

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
	struct GsVServCon base;
	struct GsAuxConfigCommonVars mCommonVars; /*notowned*/
	struct GsVServManageId *mManageId;
	std::map<GsAddr, sp<GsVServUser>, gs_addr_less_t> mUsers;
	std::map<gs_vserv_user_id_t, GsAddr> mUserIdAddr;
	sp<GsVServGroupAll> mGroupAll;

	struct GsVServLock *mLock; /*owned*/
};

int gs_vserv_con_ext_create(
	struct GsAuxConfigCommonVars *CommonVars,
	struct GsVServConExt **oExt);

#endif /* _VSERV_CRANK0_PRIV_H_ */
