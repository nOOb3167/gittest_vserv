#ifndef _VSERV_NET_H_
#define _VSERV_NET_H_

#include <stddef.h>
#include <cstdint>

#ifdef _MSC_VER
#  include <malloc.h>  // alloca
#else
#  include <alloca.h>
#endif

#include <gittest/config.h>
#include <gittest/vserv_helpers.h>

#define GS_ADDR_RAWHASH_BUCKET(RAWHASH, NUM_BUCKETS) ((RAWHASH) % (NUM_BUCKETS))

/* intended to be forward-declared in header (API use pointer only) */
struct GsVServMgmt;
struct GsVServLock;
struct GsVServCtl;
struct GsVServRespond;
struct GsVServRespondM;
struct GsVServWrite;

/* receives pointer (Data) to the to-be-deleted data pointer (*Data)
   deletion must be skipped if *Data is NULL
   deletion must cause *Data to become NULL */
typedef int (*gs_data_deleter_t)(uint8_t **Data);
/* single indirection version of gs_data_deleter_t */
typedef int (*gs_data_deleter_sp_t)(uint8_t *Data);

struct GsAddr
{
	unsigned long long mSinFamily; /*AF_UNIX*/
	unsigned long long mSinPort; /*host byte order*/
	unsigned long long mSinAddr; /*host byte order*/
};

#ifdef __cplusplus
struct gs_addr_hash_t { size_t operator()(const struct GsAddr &k) const; };
struct gs_addr_equal_t { bool operator()(const GsAddr &a, const GsAddr &b) const; };
struct gs_addr_less_t { bool operator()(const GsAddr &a, const GsAddr &b) const; };
#endif /* __cplusplus */

enum GsSockType
{
	GS_SOCK_TYPE_NORMAL = 2,
	GS_SOCK_TYPE_EVENT = 3,
	GS_SOCK_TYPE_WAKE = 4,
};

struct GsVServCon
{
	struct GsVServMgmt * (*CbGetMgmt)(struct GsVServCon *Base);
};

struct GsVServWorkCb
{
	/* ServCtl->mThreadVec threads are made call this on start */
	int(*CbThreadFunc)(struct GsVServCtl *ServCtl, size_t SockIdx);
	/* called per-request */
	int(*CbCrank)(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespond *Respond);
};

/** @sa gs_vserv_receive_func gs_vserv_enet_receive_func */
struct GsVServMgmtCb
{
	/* ServCtl->mThreadMgmt thread is made call this on start */
	int(*CbThreadFuncM)(struct GsVServCtl *ServCtl);
	/* called per-request */
	int(*CbCrankM)(struct GsVServCtl *ServCtl, struct GsPacket *Packet, struct GsAddr *Addr, struct GsVServRespondM *Respond);
};

int gs_vserv_lock_create(struct GsVServLock **oLock);
int gs_vserv_lock_destroy(struct GsVServLock *Lock);
int gs_vserv_lock_lock(struct GsVServLock *Lock);
int gs_vserv_lock_unlock(struct GsVServLock *Lock);
int gs_vserv_lock_release(struct GsVServLock *Lock);

size_t gs_addr_rawhash(struct GsAddr *Addr);
size_t gs_addr_port(struct GsAddr *Addr);

/** @sa GsVServCtlReceiveCb */
int gs_vserv_receive_func(
	struct GsVServCtl *ServCtl,
	size_t SockIdx);

int gs_vserv_ctl_create_part(
	size_t ThreadNum,
	int *ioSockFdVec, size_t SockFdNum, /*owned/stealing*/
	struct GsVServCon *Con, /*owned*/
	struct GsVServWorkCb WorkCb,
	struct GsVServMgmtCb MgmtCb,
	struct GsVServCtl **oServCtl);
int gs_vserv_ctl_create_finish(
	struct GsVServCtl *ServCtl);
int gs_vserv_ctl_destroy(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_request(struct GsVServCtl *ServCtl);
int gs_vserv_ctl_quit_wait(struct GsVServCtl *ServCtl);
struct GsVServCon *    gs_vserv_ctl_get_con(struct GsVServCtl *ServCtl);
struct GsVServWorkCb * gs_vserv_ctl_get_workcb(struct GsVServCtl *ServCtl);
struct GsVServMgmtCb * gs_vserv_ctl_get_mgmtcb(struct GsVServCtl *ServCtl);

int gs_vserv_write_create(
	struct GsVServWrite **oWrite);
int gs_vserv_write_destroy(struct GsVServWrite *Write);
int gs_vserv_write_elt_del_free(uint8_t **DataBuf);
int gs_vserv_write_elt_del_sp_free(uint8_t *DataBuf);
int gs_vserv_write_drain_to(struct GsVServCtl *ServCtl, size_t SockIdx, int *oHaveEAGAIN);
int gs_vserv_respond_enqueue(
	struct GsVServRespond *Respond,
	gs_data_deleter_sp_t DataDeleterSp,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);
int gs_vserv_respond_enqueue_free(
	struct GsVServRespond *Respond,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);

int gs_vserv_sockets_create(
	const char *Port,
	int *ioSockFdVec, size_t SockFdNum);

int gs_vserv_start_2(
	int *ServFdVec, size_t ServFdNum, /*owned/stealing*/
	struct GsVServCon *Con, /*owned*/
	struct GsVServWorkCb WorkCb,
	struct GsVServMgmtCb MgmtCb,
	struct GsVServCtl **oServCtl);

/**/

int gs_vserv_start_crank0(struct GsAuxConfigCommonVars *CommonVars);

#endif /* _VSERV_NET_H_ */
