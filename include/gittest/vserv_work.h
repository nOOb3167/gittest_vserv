#ifndef _VSERV_WORK_H_
#define _VSERV_WORK_H_

#include <stddef.h>
#include <stdint.h>

#include <gittest/vserv_net.h>

#define GS_VSERV_EPOLL_NUMEVENTS 8
#define GS_VSERV_UDP_SIZE_MAX 65535

/* receives pointer (Data) to the to-be-deleted data pointer (*Data)
   deletion must be skipped if *Data is NULL
   deletion must cause *Data to become NULL */
typedef int (*gs_data_deleter_t)(uint8_t **Data);
/* single indirection version of gs_data_deleter_t */
typedef int (*gs_data_deleter_sp_t)(uint8_t *Data);

struct GsVServWork;

int gs_vserv_receive_func(
	struct GsVServCtl *ServCtl,
	size_t SockIdx);

int gs_vserv_write_elt_del_free(uint8_t **DataBuf);
int gs_vserv_write_elt_del_sp_free(uint8_t *DataBuf);

int gs_vserv_work_create(
	size_t ThreadNum,
	int *ioSockFdVec, size_t SockFdNum, /*owned/stealing*/
	struct GsVServCtl *ServCtl, /*partial/refonly*/
	struct GsVServQuitCtl *QuitCtl, /*notowned*/
	struct GsVServWork **oWork);
int gs_vserv_work_destroy(struct GsVServWork *Work);

#endif /* _VSERV_WORK_H_ */
