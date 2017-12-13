#include <cstddef>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

// https://github.com/systemd/systemd/blob/master/src/libsystemd/sd-daemon/sd-daemon.c
//   sd_pid_notify_with_fds

// https://davejingtian.org/2015/02/17/retrieve-pid-from-the-packet-in-unix-domain-socket-a-complete-use-case-for-recvmsgsendmsg/
//   """Don't construct an explicit credentials structure. (It
//      is not necessary to do so, if we just want the receiver to
//      receive our real credentials.)"""

// printing env vars
//  extern char**environ;
//  for (char **env = environ; *env; env++)
//    printf("e %s\n", *env);

// https://www.freedesktop.org/software/systemd/man/sd_notify.html
//   see for possible state values */
// const char StateBuf[] = "READY=1";
// int failed = gs_sd_notify(0, "READY=1");

int gs_sd_notify(int UnsetEnvironment, const char *State)
{
	bool Success = false;

	const char *Env = NULL;
	struct sockaddr_un Addr = {};
	int Fd = -1;

	if (! (Env = getenv("NOTIFY_SOCKET")))
		goto clean;

	if (strlen(Env) <= 1 || strlen(Env) > sizeof Addr.sun_path - 1 || (Env[0] != '@' && Env[0] != '/'))
		goto clean;

	Addr.sun_family = AF_UNIX;
	memmove(Addr.sun_path, Env, strlen(Env) + 1);
	/* abstract socket address indicated by starting @ in env var
	   abstract socket address indicated by starting 0 in sun_path
	   see unix(7) */
	if (Addr.sun_path[0] == '@')
		Addr.sun_path[0] = 0;

	if (0 > (Fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)))
		goto clean;
	if (0 > sendto(Fd, State, strlen(State), MSG_NOSIGNAL, (struct sockaddr *) &Addr, sizeof Addr))
		goto clean;

	Success = true;

 clean:
	if (Fd != -1)
		close(Fd);

	if (UnsetEnvironment)
		unsetenv("NOTIFY_SOCKET");

	return ! Success;
}
