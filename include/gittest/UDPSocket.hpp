#ifndef _GITTEST_UDPSOCKET_H_
#define _GITTEST_UDPSOCKET_H_

#ifdef _WIN32
// needed for mingw according to minetest socket.cpp
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0501
#endif
// include winsock2.h before windows.h scrubs
#  include <winsock2.h>
#  include <windows.h>
#  include <ws2tcpip.h>
typedef SOCKET socket_t;
#endif

struct GsVServClntAddress
{
	unsigned long long mSinFamily;
	unsigned long long mSinPort; /* host byte order */
	unsigned long long mSinAddr; /* host byte order */
};

class UDPSocket
{
public:
	UDPSocket() {
		init();
	}

	~UDPSocket() {
		if (mHandle != INVALID_SOCKET) {
			closesocket(mHandle);
			mHandle = INVALID_SOCKET;
		}
	}

	void Bind(GsVServClntAddress Addr) {
		int r = 0;

		/* lol this API, bind with void return */

		struct sockaddr_in SockAddr = {};

		SockAddr.sin_family = mSinFamily;
		SockAddr.sin_port = htons(Addr.mSinPort);
		SockAddr.sin_addr.s_addr = htonl(Addr.mSinAddr);

		if (Addr.mSinFamily != mSinFamily)
			GS_ERR_CLEAN(1);

		if (SOCKET_ERROR == bind(mHandle, (struct sockaddr *) &SockAddr, sizeof SockAddr))
			GS_ERR_CLEAN(1);

	clean:
		if (!!r)
			GS_ASSERT(0);
	}

	bool init() {
		int r = 0;

		mHandle = INVALID_SOCKET;
		mSinFamily = AF_INET;
		if (INVALID_SOCKET == (mHandle = socket(mSinFamily, SOCK_DGRAM, 0)))
			GS_ERR_CLEAN(1);
		mTimeoutMs = 0;

	clean:
		if (!!r) {
			if (mHandle != INVALID_SOCKET) {
				closesocket(mHandle);
				mHandle = INVALID_SOCKET;
			}
		}

		return r;
	}

	void Send(const GsVServClntAddress &Dest, const void *Data, int Size) {
		int r = 0;

		struct sockaddr_in SockAddr = {};
		int NSent = 0;

		if (Dest.mSinFamily != mSinFamily)
			GS_ERR_CLEAN(1);
		if (Dest.mSinFamily != AF_INET)
			GS_ERR_CLEAN(1);

		SockAddr.sin_family = Dest.mSinFamily;
		SockAddr.sin_port = htons(Dest.mSinPort);
		SockAddr.sin_addr.s_addr = htonl(Dest.mSinAddr);

		if (SOCKET_ERROR == (NSent = sendto(mHandle, (const char *) Data, Size, 0, (struct sockaddr *) &SockAddr, sizeof SockAddr)))
			GS_ERR_CLEAN(1);
		if (NSent < Size)
			GS_ERR_CLEAN(1);

	clean:
		if (!!r)
			GS_ASSERT(0);
	}

	int Receive(GsVServClntAddress &Sender, void *Data, int Size) {
		int r = 0;

		if (! WaitData(mTimeoutMs))
			return -1;

		struct sockaddr_in SockAddr = {};
		int SockAddrLen = sizeof SockAddr;
		int NRecv = 0;

		if (SOCKET_ERROR == (NRecv = recvfrom(mHandle, (char *) Data, Size, MSG_TRUNC, (struct sockaddr *) &SockAddr, &SockAddrLen)))
			GS_ERR_CLEAN(1);
		if (SockAddrLen != sizeof SockAddr)
			GS_ERR_CLEAN(1);
		if (NRecv > Size)  // MSG_TRUNC effect for too-long datagrams
			GS_ERR_CLEAN(1);

		Sender.mSinFamily = SockAddr.sin_family;
		Sender.mSinPort = ntohs(SockAddr.sin_port);
		Sender.mSinAddr = ntohl(SockAddr.sin_addr.s_addr);

	clean:
		if (!!r)
			NRecv = -1;

		return NRecv;
	}

	bool WaitData(int TimeoutMs) {
		int r = 0;

		fd_set RSet;
		struct timeval TVal = {};

		int NReady = -1;

		FD_ZERO(&RSet);
		FD_SET(mHandle, &RSet);
		TVal.tv_sec = TimeoutMs;
		TVal.tv_usec = 0;

		if (SOCKET_ERROR == (NReady = select(mHandle + 1, &RSet, NULL, NULL, &TVal)))
			GS_ERR_CLEAN(1);
		if (NReady == 0)
			return false;
		if (! FD_ISSET(mHandle, &RSet))
			return false;

		return true;

	clean:
		if (!!r)
			GS_ASSERT(0);
		/* dummy */
		return false;
	}

	static int GetHostByName(const char *Name, unsigned long long *oAddr) {
		struct hostent *HostEnt = NULL;

		struct in_addr InAddr = {};

		if (!(HostEnt = gethostbyname(Name)))
			return 1;

		GS_ASSERT(HostEnt->h_addrtype == AF_INET);
		InAddr = *(struct in_addr *) HostEnt->h_addr;
		*oAddr = ntohl(InAddr.s_addr);

		return 0;
	}

private:
	SOCKET mHandle;
	unsigned long long mSinFamily;
	unsigned long long mTimeoutMs;
};

#endif /* _GITTEST_UDPSOCKET_H_ */
