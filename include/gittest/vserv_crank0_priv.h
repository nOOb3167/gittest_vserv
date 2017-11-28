#ifndef _VSERV_CRANK0_PRIV_H_
#define _VSERV_CRANK0_PRIV_H_

#include <stddef.h>

#include <map>
#include <set>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>

#define GS_VSERV_USER_ID_INVALID 0xFFFF
#define GS_VSERV_USER_ID_SERVFILL 0xFFFF

#define GS_VSERV_NAMELEN_ARBITRARY_SIZE_MAX 1472

typedef uint8_t gs_vserv_group_mode_t;
typedef uint16_t gs_vserv_user_id_t;

enum GsVServCmd {
	GS_VSERV_CMD_BROADCAST = 'b',
	GS_VSERV_M_CMD_GROUPSET = 's',
	GS_VSERV_CMD_GROUP_MODE_MSG = 'm',
	GS_VSERV_CMD_IDENT = 'i',
	GS_VSERV_CMD_IDENT_ACK = 'I',
	GS_VSERV_CMD_NAMEGET = 'n',
	GS_VSERV_CMD_NAMES = 'N',
};

enum GsVServGroupMode
{
	GS_VSERV_GROUP_MODE_NONE = 0,
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
