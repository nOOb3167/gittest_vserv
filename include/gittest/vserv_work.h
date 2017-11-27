#ifndef _VSERV_WORK_H_
#define _VSERV_WORK_H_

#include <stddef.h>

#include <deque>

#include <gittest/misc.h>
#include <gittest/vserv_net.h>

#define GS_VSERV_EPOLL_NUMEVENTS 8
#define GS_VSERV_UDP_SIZE_MAX 65535

struct GsVServRespond;
struct GsVServWork;

int gs_vserv_receive_func(
	struct GsVServCtl *ServCtl,
	size_t SockIdx);

int gs_vserv_respond_enqueue(
	struct GsVServRespond *Respond,
	gs_data_deleter_sp_t DataDeleterSp,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);
int gs_vserv_respond_enqueue_free(
	struct GsVServRespond *Respond,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec);

int gs_vserv_work_create(
	size_t ThreadNum,
	int *ioSockFdVec, size_t SockFdNum, /*owned/stealing*/
	struct GsVServCtl *ServCtl, /*partial/refonly*/
	struct GsVServQuitCtl *QuitCtl, /*notowned*/
	struct GsVServWork **oWork);
int gs_vserv_work_destroy(struct GsVServWork *Work);

#endif /* _VSERV_WORK_H_ */
