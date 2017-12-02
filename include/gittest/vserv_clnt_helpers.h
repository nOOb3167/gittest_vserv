#ifndef _VSERV_CLNT_HELPERS_H_
#define _VSERV_CLNT_HELPERS_H_

#include <stdint.h>

#include <cstring>

#define GS_CLNT_ARBITRARY_PACKET_MAX 4096 /* but mind IP layer fragmentation issues of UDP */

#define GS_VSERV_USER_ID_INVALID 0xFFFF
#define GS_VSERV_USER_ID_SERVFILL 0xFFFF

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
	GS_VSERV_CMD_IDGET = 'd',
	GS_VSERV_CMD_IDS   = 'D',
};

enum GsVServGroupMode
{
	GS_VSERV_GROUP_MODE_NONE = 0,
	GS_VSERV_GROUP_MODE_S = 's',
};

struct GsName
{
	std::string mName;
	std::string mServ;
	uint16_t mId;
};

#endif /* _VSERV_CLNT_HELPERS_H_ */
