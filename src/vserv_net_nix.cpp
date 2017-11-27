#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include <functional>  // std::hash
#include <utility>
#include <memory>
#include <vector>
#include <deque>
#include <map>

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <gittest/misc.h>
#include <gittest/filesys.h>
#include <gittest/log.h>
#include <gittest/vserv_net.h>

struct GsVServLock
{
	pthread_mutex_t mMutex;
	bool mHaveLock;
};

struct GsVServCtl
{
	size_t mNumThread;
	pthread_t *mThreadVec; size_t mThreadNum;
	pthread_t *mThreadMgmt; size_t mThreadMgmtNum;
	struct GsVServQuitCtl *mQuitCtl;
	struct GsVServWork *mWork;
	// FIXME: no mMgmt - mCon provides access to what SHOULD be mMgmt via CbGetMgmt() (helper gs_vserv_ctl_get_mgmt())
	/* shared (work&mgmt) context */
	struct GsVServCon *mCon; /*notowned*/ // FIXME: needs CbDestroy?
	struct GsVServWorkCb mWorkCb;
	struct GsVServMgmtCb mMgmtCb;
};

struct GsVServPthreadCtx
{
  struct GsVServCtl *mServCtl;
  size_t mSockIdx;
};

static int gs_addr_sockaddr_in(const struct GsAddr *Addr, struct sockaddr_in *SockAddr);
static int gs_eventfd_read(int EvtFd);
static int gs_eventfd_write(int EvtFd, int Value);
static void * gs_vserv_work_func_pthread(
	void *arg);
static void * gs_vserv_mgmt_func_pthread(
	void *arg);

size_t gs_addr_hash_t::operator()(const struct GsAddr &k) const {
	// FIXME: https://stackoverflow.com/questions/35985960/c-why-is-boosthash-combine-the-best-way-to-combine-hash-values
	return (    (std::hash<unsigned long long>()(k.mSinFamily) << 1)
		     ^ ((std::hash<unsigned long long>()(k.mSinPort) << 1) >> 1)
			 ^ ((std::hash<unsigned long long>()(k.mSinAddr) << 2) >> 2));
}

bool gs_addr_equal_t::operator()(const GsAddr &a, const GsAddr &b) const {
	return a.mSinPort == b.mSinFamily
		&& a.mSinPort == b.mSinPort
		&& a.mSinAddr == b.mSinAddr;
}

bool gs_addr_less_t::operator()(const GsAddr &a, const GsAddr &b) const {
	return gs_addr_hash_t()(a) < gs_addr_hash_t()(b);
}

int gs_vserv_quit_ctl_create(struct GsVServQuitCtl **oQuitCtl)
{
	int r = 0;

	struct GsVServQuitCtl *QuitCtl = NULL;

	int EvtFdExitReq = -1;
	int EvtFdExit = -1;

	// thread requesting exit 0 -> 1 -> 0
	if (-1 == (EvtFdExitReq = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);
	// controller (servctl) ordering exit 0 -> NumThread -> -=1 -> .. -> 0
	if (-1 == (EvtFdExit = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE)))
		GS_ERR_CLEAN(1);

	QuitCtl = new GsVServQuitCtl();
	QuitCtl->mEvtFdExitReq = GS_FDOWN(&EvtFdExitReq);
	QuitCtl->mEvtFdExit = GS_FDOWN(&EvtFdExit);

	if (oQuitCtl)
		*oQuitCtl = GS_ARGOWN(&QuitCtl);

clean:
	gs_close_cond(&EvtFdExit);
	gs_close_cond(&EvtFdExitReq);

	return r;
}

int gs_vserv_quit_ctl_destroy(struct GsVServQuitCtl *QuitCtl)
{
	if (QuitCtl) {
		gs_close_cond(&QuitCtl->mEvtFdExitReq);
		gs_close_cond(&QuitCtl->mEvtFdExit);
	}

	return 0;
}

int gs_vserv_quit_ctl_reflect_evt_fd_exit(struct GsVServQuitCtl *QuitCtl, int *oFd)
{
	if (oFd)
		*oFd = QuitCtl->mEvtFdExit;
	return 0;
}

int gs_vserv_lock_create(struct GsVServLock **oLock)
{
	int r = 0;

	struct GsVServLock *Lock = new GsVServLock();

	if (!! pthread_mutex_init(&Lock->mMutex, NULL))
		GS_ERR_CLEAN(1);
	Lock->mHaveLock = 0;

	if (oLock)
		*oLock = GS_ARGOWN(&Lock);

clean:
	GS_DELETE(&Lock, struct GsVServLock);

	return r;
}

int gs_vserv_lock_destroy(struct GsVServLock *Lock)
{
	if (Lock) {
		if (!! pthread_mutex_destroy(&Lock->mMutex))
			GS_ASSERT(0);
		GS_DELETE(&Lock, struct GsVServLock);
	}
	return 0;
}

int gs_vserv_lock_lock(struct GsVServLock *Lock)
{
	if (!! pthread_mutex_lock(&Lock->mMutex))
		return 1;
	Lock->mHaveLock = 1;
	return 0;
}

int gs_vserv_lock_unlock(struct GsVServLock *Lock)
{
	/* NOTE: HaveLock zeroes before actually unlocking */
	Lock->mHaveLock = 0;
	if (!! pthread_mutex_unlock(&Lock->mMutex))
		return 1;
	return 0;
}

int gs_vserv_lock_release(struct GsVServLock *Lock)
{
	if (Lock->mHaveLock)
		if (!! pthread_mutex_unlock(&Lock->mMutex))
			return 1;
	return 0;
}

size_t gs_addr_rawhash(struct GsAddr *Addr)
{
	return gs_addr_hash_t()(*Addr);
}

size_t gs_addr_port(struct GsAddr *Addr)
{
	return Addr->mSinPort;
}

int gs_addr_sockaddr_in(const struct GsAddr *Addr, struct sockaddr_in *SockAddr)
{
	if (Addr->mSinFamily != AF_INET)
		return 1;
	SockAddr->sin_family = AF_INET;
	SockAddr->sin_port = htons(Addr->mSinPort);
	SockAddr->sin_addr.s_addr = htonl(Addr->mSinAddr);
	return 0;
}

int gs_eventfd_read(int EvtFd)
{
	int r = 0;
	char    Buf[8] = {};
	ssize_t NRead  = 0;

	while (-1 == (NRead = read(EvtFd, Buf, 8))) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			continue;
		GS_ERR_CLEAN(1);
	}
	GS_ASSERT(NRead == 8);

clean:

	return r;
}

int gs_eventfd_write(int EvtFd, int Value)
{
	int r = 0;

	uint64_t Val    = (uint64_t)Value;
	char     Buf[8] = {};
	ssize_t  NWrite = 0;

	GS_ASSERT(sizeof Val == sizeof Buf);

	memcpy(Buf, &Val, 8);

	while (-1 == (NWrite = write(EvtFd, Buf, 8))) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			continue;
		GS_ERR_CLEAN(1);
	}
	GS_ASSERT(NWrite == 8);

clean:

  return 0;
}

void * gs_vserv_work_func_pthread(
	void *arg)
{
	int r = 0;

	struct GsVServPthreadCtx *Ctx = (struct GsVServPthreadCtx *) arg;
	struct GsVServCtl *ServCtl = Ctx->mServCtl;
	size_t SockIdx = Ctx->mSockIdx;

	log_guard_t Log(GS_LOG_GET("serv"));

	if (!!(r = ServCtl->mWorkCb.CbThreadFunc(ServCtl, SockIdx)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE(&Ctx, struct GsVServPthreadCtx);

	if (!!r)
		GS_ASSERT(0);

	return NULL;
}

void * gs_vserv_mgmt_func_pthread(
	void *arg)
{
	int r = 0;

	struct GsVServPthreadCtx *Ctx = (struct GsVServPthreadCtx *) arg;
	struct GsVServCtl *ServCtl = Ctx->mServCtl;
	
	GS_ASSERT(Ctx->mSockIdx == -1);

	log_guard_t Log(GS_LOG_GET("mgmt"));

	if (!!(r = ServCtl->mMgmtCb.CbThreadFuncM(ServCtl)))
		GS_GOTO_CLEAN();

clean:
	GS_DELETE(&Ctx, struct GsVServPthreadCtx);

	if (!!r)
		GS_ASSERT(0);

	return NULL;
}

int gs_vserv_ctl_create_part(
	size_t ThreadNum,
	struct GsVServCon *Con, /*owned*/
	struct GsVServWorkCb WorkCb,
	struct GsVServMgmtCb MgmtCb,
	struct GsVServCtl **oServCtl)
{
	int r = 0;

	struct GsVServCtl *ServCtl = NULL;

	ServCtl = new GsVServCtl();
	ServCtl->mNumThread = ThreadNum;
	ServCtl->mThreadNum = ThreadNum;
	ServCtl->mThreadVec = new pthread_t[ThreadNum];
	ServCtl->mThreadMgmtNum = 1;
	ServCtl->mThreadMgmt = new pthread_t[1];
	ServCtl->mQuitCtl = NULL;
	ServCtl->mWork = NULL;
	ServCtl->mCon = GS_ARGOWN(&Con);
	ServCtl->mWorkCb = WorkCb;
	ServCtl->mMgmtCb = MgmtCb;

	if (! ServCtl->mThreadVec || ! ServCtl->mThreadMgmt)
		GS_ERR_CLEAN(1);

	if (oServCtl)
		*oServCtl = GS_ARGOWN(&ServCtl);

clean:
	GS_DELETE_F(&ServCtl, gs_vserv_ctl_destroy);

	return r;
}

int gs_vserv_ctl_create_finish(
	struct GsVServCtl *ServCtl,
	struct GsVServQuitCtl *QuitCtl, /*owned*/
	struct GsVServWork *Work /*owned*/)
{
	int r = 0;

	size_t ThreadsInitedCnt = 0;
	bool AttrInited = false;
	pthread_attr_t Attr = {};

	/**/

	ServCtl->mQuitCtl = GS_ARGOWN(&QuitCtl);
	ServCtl->mWork = GS_ARGOWN(&Work);

	/* create threads */

	if (!!(r = pthread_attr_init(&Attr)))
		GS_GOTO_CLEAN();
	AttrInited = true;

	for (size_t i = 0; i < ServCtl->mNumThread; i++) {
		struct GsVServPthreadCtx *Ctx = new GsVServPthreadCtx();
		Ctx->mServCtl = ServCtl;
		Ctx->mSockIdx = i;
		if (!!(r = pthread_create(ServCtl->mThreadVec + i, &Attr, gs_vserv_work_func_pthread, Ctx)))
			GS_GOTO_CLEAN();
		Ctx = NULL;
		ThreadsInitedCnt++;
	}

	{
		GS_ASSERT(ServCtl->mThreadMgmtNum == 1);
		struct GsVServPthreadCtx *Ctx = new GsVServPthreadCtx();
		Ctx->mServCtl = ServCtl;
		Ctx->mSockIdx = -1;
		if (!!(r = pthread_create(ServCtl->mThreadMgmt + 0, &Attr, gs_vserv_mgmt_func_pthread, Ctx)))
			GS_GOTO_CLEAN();
		Ctx = NULL;
	}

clean:
	if (AttrInited)
		if (!!(r = pthread_attr_destroy(&Attr)))
			GS_ASSERT(0);
	GS_DELETE_F(&QuitCtl, gs_vserv_quit_ctl_destroy);
	GS_DELETE_F(&Work, gs_vserv_work_destroy);

	return r;
}

int gs_vserv_ctl_destroy(struct GsVServCtl *ServCtl)
{
	int r = 0;

	if (ServCtl) {
		GS_DELETE_ARRAY(&ServCtl->mThreadVec, pthread_t);
		GS_DELETE_ARRAY(&ServCtl->mThreadMgmt, pthread_t);

		gs_close_cond(&ServCtl->mEvtFdExit);
		gs_close_cond(&ServCtl->mEvtFdExitReq);

		if (ServCtl->mWork) {
			for (size_t i = 0; i < ServCtl->mSockFdNum; i++)
				gs_close_cond(ServCtl->mSockFdVec + i);
			GS_DELETE_ARRAY(&ServCtl->mSockFdVec, int);

			for (size_t i = 0; i < ServCtl->mEPollFdNum; i++)
				gs_close_cond(ServCtl->mEPollFdVec + i);
			GS_DELETE_ARRAY(&ServCtl->mEPollFdVec, int);

			for (size_t i = 0; i < ServCtl->mWriteNum; i++)
				GS_DELETE_F(&ServCtl->mWriteVec[i], gs_vserv_write_destroy);
			GS_DELETE_ARRAY(&ServCtl->mWriteVec, struct GsVServWrite *);

			for (size_t i = 0; i < ServCtl->mWakeAsyncNum; i++)
				gs_close_cond(ServCtl->mWakeAsyncVec + i);
			GS_DELETE_ARRAY(&ServCtl->mWakeAsyncVec, int);

			GS_DELETE(&ServCtl->mWork, struct GsVServWork);
		}

		GS_DELETE(&ServCtl, struct GsVServCtl);
	}

clean:

	return r;
}

int gs_vserv_ctl_quit_request(struct GsVServCtl *ServCtl)
{
	int r = 0;

	if (!!(r = gs_eventfd_write(ServCtl->mEvtFdExitReq, 1)))
		GS_GOTO_CLEAN();

clean:

	return r;
}

int gs_vserv_ctl_quit_wait(struct GsVServCtl *ServCtl)
{
	int r = 0;

	// FIXME: port to GsVServQuitCtl
	GS_ASSERT(0);

	GS_ALLOCA_VAR(RetVal, void *, ServCtl->mThreadNum);

	if (!!(r = gs_eventfd_read(ServCtl->mEvtFdExitReq)))
		GS_GOTO_CLEAN();

	if (!!(r = gs_eventfd_write(ServCtl->mEvtFdExit, ServCtl->mNumThread)))
		GS_GOTO_CLEAN();

	for (size_t i = 0; i < ServCtl->mThreadNum; i++)
		if (!!(r = pthread_join(ServCtl->mThreadVec[i], RetVal + i)))
			GS_GOTO_CLEAN();

clean:

	return r;
}

struct GsVServWork * gs_vserv_ctl_get_work(struct GsVServCtl *ServCtl)
{
	return ServCtl->mWork;
}

struct GsVServMgmt * gs_vserv_ctl_get_mgmt(struct GsVServCtl *ServCtl)
{
	return ServCtl->mCon->CbGetMgmt(ServCtl->mCon);
}

struct GsVServCon * gs_vserv_ctl_get_con(struct GsVServCtl *ServCtl)
{
	return ServCtl->mCon;
}

struct GsVServWorkCb * gs_vserv_ctl_get_workcb(struct GsVServCtl *ServCtl)
{
	return &ServCtl->mWorkCb;
}

struct GsVServMgmtCb * gs_vserv_ctl_get_mgmtcb(struct GsVServCtl *ServCtl)
{
	return &ServCtl->mMgmtCb;
}

int gs_vserv_write_create(
	struct GsVServWrite **oWrite)
{
	int r = 0;

	struct GsVServWrite *Write = NULL;

	Write = new GsVServWrite();
	Write->mTryAtOnce = false;
	Write->mQueue;

	if (oWrite)
		*oWrite = GS_ARGOWN(&Write);

clean:
	GS_DELETE(&Write, struct GsVServWrite);

	return r;
}

int gs_vserv_write_destroy(struct GsVServWrite *Write)
{
	if (Write) {
		GS_DELETE(&Write, struct GsVServWrite);
	}
	return 0;
}

int gs_vserv_write_elt_del_free(uint8_t **DataBuf)
{
	if (*DataBuf) {
		free(*DataBuf);
		*DataBuf = NULL;
	}
	return 0;
}

int gs_vserv_write_elt_del_sp_free(uint8_t *DataBuf)
{
	free(DataBuf);
	return 0;
}

/**
	for epoll(2) EPOLLET edge-triggered mode specifically, writing until EAGAIN is important
	  as no further EPOLLOUT (writability) events will be received otherwise (socket remains writable)
*/
int gs_vserv_write_drain_to(struct GsVServCtl *ServCtl, size_t SockIdx, int *oHaveEAGAIN)
{
	int r = 0;

	struct GsVServWrite *Write = ServCtl->mWriteVec[SockIdx];
	int Fd = ServCtl->mSockFdVec[SockIdx];

	int HaveEAGAIN = 0;

	std::deque<GsVServWriteEntry>::iterator it;

	if (Write->mQueue.empty())
		GS_ERR_NO_CLEAN(0);

	for (it = Write->mQueue.begin(); it != Write->mQueue.end(); ++it) {
		ssize_t NSent = 0;
		struct sockaddr_in SockAddr = {};
		if (!!(r = gs_addr_sockaddr_in(&it->mAddr, &SockAddr)))
			GS_GOTO_CLEAN();
		while (-1 == (NSent = sendto(Fd, it->mElt.mData.get(), it->mElt.mLenData, MSG_NOSIGNAL, (struct sockaddr *) &SockAddr, sizeof SockAddr))) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				HaveEAGAIN = 1;
				goto donewriting;
			}
			GS_ERR_CLEAN(1);
		}
	}
donewriting:
	Write->mQueue.erase(Write->mQueue.begin(), it);

noclean:
	if (oHaveEAGAIN)
		*oHaveEAGAIN = HaveEAGAIN;

clean:

	return r;
}

/** WARNING: this function is affected by caller CPU
      the designed flow is: x-th receiver calls crank with 'Respond',
	  crank on x-th receiver calls ex gs_vserv_respond_enqueue.
	  maybe should just acquire mutexes */
int gs_vserv_respond_enqueue(
	struct GsVServRespond *Respond,
	gs_data_deleter_sp_t DataDeleterSp,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec)
{
	int r = 0;

	struct GsVServCtl *ServCtl = Respond->mServCtl;
	struct GsVServWrite *Write = ServCtl->mWriteVec[Respond->mSockIdx];
	int Fd = ServCtl->mSockFdVec[Respond->mSockIdx];

	size_t NumWrite = 0;

	/* feature may send some messages immediately */

	if (Write->mTryAtOnce) {
		for (size_t NumWrite = 0; NumWrite < LenAddrVec; NumWrite++) {
			ssize_t NSent = 0;
			struct sockaddr_in SockAddr = {};
			if (!!(r = gs_addr_sockaddr_in(AddrVec[NumWrite], &SockAddr)))
				GS_GOTO_CLEAN();
			while (-1 == (NSent = sendto(Fd, DataBuf, LenData, MSG_NOSIGNAL, (struct sockaddr *) &SockAddr, sizeof SockAddr))) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					goto donewriting;
				GS_ERR_CLEAN(1);
			}
		}
	}

donewriting:

	/* queue any not yet sent */

	if (NumWrite < LenAddrVec) {
		std::shared_ptr<uint8_t> Sp(GS_ARGOWN(&DataBuf), DataDeleterSp);
		for (size_t i = NumWrite; i < LenAddrVec; i++) {
			struct GsVServWriteEntry Entry;
			Entry.mAddr = *AddrVec[i];
			Entry.mElt.mLenData = LenData;
			Entry.mElt.mData = Sp;
			Write->mQueue.push_back(std::move(Entry));
		}
	}

clean:
	GS_DELETE_F(&DataBuf, DataDeleterSp);

	return r;
}

int gs_vserv_respond_enqueue_free(
	struct GsVServRespond *Respond,
	uint8_t *DataBuf, size_t LenData, /*owned*/
	const struct GsAddr **AddrVec, size_t LenAddrVec)
{
	return gs_vserv_respond_enqueue(Respond, gs_vserv_write_elt_del_sp_free, DataBuf, LenData, AddrVec, LenAddrVec);
}

int gs_vserv_sockets_create(
	const char *Port,
	int *ioSockFdVec, size_t SockFdNum)
{
	int r = 0;

	struct addrinfo Hints = {};
	struct addrinfo *Res = NULL, *Rp = NULL;
	int TmpFd = -1;

	/* AI_PASSIVE causes INADDR_ANY equivalent */
	Hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	// FIXME: RIP ipv6, see AF_UNSPEC
	Hints.ai_family = AF_INET;
	Hints.ai_socktype = SOCK_DGRAM;
	Hints.ai_protocol = 0;

	for (size_t i = 0; i < SockFdNum; i++)
		ioSockFdVec[i] = -1;

	if (!!(r = getaddrinfo(NULL, Port, &Hints, &Res)))
		GS_GOTO_CLEAN();

	for (Rp = Res; Rp != NULL; Rp = Rp->ai_next) {
		bool RpFound = false;

		if (-1 == (TmpFd = socket(Rp->ai_family, Rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, Rp->ai_protocol)))
			GS_ERR_CLEAN(1);
		if (0 == bind(TmpFd, Rp->ai_addr, Rp->ai_addrlen))
			RpFound = true;

		gs_close_cond(&TmpFd);

		if (RpFound)
			break;
	}

	if (Rp == NULL)
		GS_ERR_CLEAN(1);

	for (size_t i = 0; i < SockFdNum; i++) {
		int OptReuseport = 1;
		if (-1 == (ioSockFdVec[i] = socket(Rp->ai_family, Rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, Rp->ai_protocol)))
			GS_ERR_CLEAN(1);
		if (-1 == setsockopt(ioSockFdVec[i], SOL_SOCKET, SO_REUSEPORT, &OptReuseport, sizeof OptReuseport))
			GS_ERR_CLEAN(1);
		if (-1 == bind(ioSockFdVec[i], Rp->ai_addr, Rp->ai_addrlen))
			GS_ERR_CLEAN(1);
	}

clean:
	if (!!r) {
		for (size_t i = 0; i < SockFdNum; i++)
			gs_close_cond(ioSockFdVec + i);
	}

	gs_close_cond(&TmpFd);
	if (Res)
		freeaddrinfo(Res);

	return r;
}
