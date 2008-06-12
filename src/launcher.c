/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *  Paul Klissner <paul.klissner@sun.com>
 *  Michael Bender <michael.bender@sun.com>
 *
 */


#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <syslog.h>
#include <ucred.h>
#include <unistd.h>
#include <wait.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/conf.h>
#include <sys/filio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <thread.h>
#include <syslog.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "pcsc_config.h"
#include "pcsclite.h"
#include "clientcred.h"
#include "auth.h"
#include "launcher.h"
#include "daemon_utils.h"
#include "misc.h"
#include "debuglog.h"
#include "validate.h"
#include "sys_generic.h"
#include "thread_generic.h"
#include "pcscd-validate.h"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define NONULL(a) (a) ? (a) : "<null>"


extern char *execPath;
extern int Init;

struct {
	int nbrInstancesLaunched;
	int nbrInstancesActive;
} LauncherStats;

typedef struct fdQ {
	struct fdQ *next;
	int fd;
} fdQ_t;

//#define DEFER_FD_CLOSE

typedef struct pcscd {
	struct pcscd *next;		// pointer to next entry
	int dpyNbr;			// display instance services
	int pid;			// pid obtained from ping
	int inFifo;			// Receive fifo
	int outFifo;			// Xmit fifo
	time_t launchTime;		// Time of last launch
	char inFifoName[256];		// Receive fifo Name
	char outFifoName[256];		// Xmit fifo Name
	int nbrFdsSentToInstance;	// Total fds  sent to instance
	char logbuf[256];		// Holds messages
	int fdToSend;			// most recent fd to send to instance
	int nbrFdsQueued;		// Count of fd's in queue
	fdQ_t *fdQhead;			// List of fds to send to instance
	PCSCLITE_THREAD_T tid		; // instance timeout thread
	PCSCLITE_MUTEX  fdQLock;	// Locks access to fdQ
	PCSCLITE_COND   fdQNotify;	// Notify that queue has data
#ifdef DEFER_FD_CLOSE
	fdQ_t *garbageFdQhead;		// List of fds to close
	PCSCLITE_MUTEX  garbageFdQlock; // Locks access to garbageFdQ
#endif
} pcscd_t;

PCSCLITE_MUTEX instDBm;			// instance database lock
pcscd_t *instanceQ;			// Instance queue listhead

#undef ERROR
#define ERROR -1
#undef SUCCESS
#define SUCCESS 0

static int  PopFd(fdQ_t **);
static void QueueFd(fdQ_t **, int);
static pcscd_t *FindInstanceByDpy(pcscd_t **, int);
static void AddInstance(pcscd_t **, pcscd_t *);
static void RemoveInstance(pcscd_t **, pcscd_t *);
static void QueueFdToInstance(int, int);
static void IncomingClientConnect(LPVOID);
static void LauncherExitHandler(int);
static void ManageInstance(LPVOID);
static int  IsPrefixed(char *f, char *);
static void ExecInstance(pcscd_t *inst);
static int  ConnectInstance(pcscd_t *);
static int  ForwardClientToInstance(int fdToSend, pcscd_t *);
static int  LaunchInstanceDaemon(pcscd_t *);
static void CloseInstanceFifos(pcscd_t *);
static int  WaitForEnqueuedFd(pcscd_t *);
static void AbortInstance(pcscd_t *);
static void EradicateInstance(pcscd_t *);
static void PeriodicCleanup(LPVOID);
static int IsInstanceRunning(pcscd_t *);

void signal_trap(int);
int wellKnownPortSocket;


static void
ManageInstance(LPVOID context) {
	pcscd_t *inst = (pcscd_t *)context;
	int rv, fd = 0;
	char fifoDirPath[MAXPATHLEN];

	bzero(fifoDirPath, MAXPATHLEN);

	sprintf(fifoDirPath, "%s/fifo", pcscCfg.baseDir);
	if (CFGEnsurePathExists(fifoDirPath) < 0) {
		Log2(PCSC_LOG_CRITICAL, "Err creating dir %s\n", fifoDirPath);
		return; // thread exit;
	}
	sprintf(inst->outFifoName, "%s/%d.o", fifoDirPath, inst->dpyNbr);
	sprintf(inst->inFifoName,  "%s/%d.i", fifoDirPath, inst->dpyNbr);

	for(;;) {
		while (ConnectInstance(inst) == ERROR) {
			if (LaunchInstanceDaemon(inst) == ERROR) {
				if (inst->dpyNbr >= 0) {
					Log1(PCSC_LOG_ERROR,
					     "Terminating instance thread");
					EradicateInstance(inst);
					return;
				}
			}
		}
		do {
			if (fd == 0)
				fd = WaitForEnqueuedFd(inst);
			if ((rv = ForwardClientToInstance(fd, inst)) == SUCCESS)
				fd = 0;
		} while (rv == SUCCESS);
	}
}

static int
ConnectInstance(pcscd_t *inst)
{
	int rv, pid;

	if (inst->dpyNbr < 0) {
		Log3(PCSC_LOG_DEBUG,
		    "<%4.4x> Error: Cannot connect to :%d",
		    thr_self(), inst->dpyNbr);

	}
	Log3(PCSC_LOG_DEBUG,
	    "<%4.4x> Connect to :%d fifos", thr_self(), inst->dpyNbr);

	inst->pid = 0;
	if (inst->inFifo == 0 &&
	    (inst->inFifo = OpenFifo(inst->inFifoName, 0)) < 0) {
		Log3(PCSC_LOG_DEBUG, "<%4.4x> No in fifo for :%d",
		    thr_self(), inst->dpyNbr);
		return ERROR;
	}

	if (inst->outFifo == 0 &&
	    (inst->outFifo = OpenFifo(inst->outFifoName, 1)) < 0) {
		Log3(PCSC_LOG_DEBUG, "<%4.4x> No out fifo for :%d",
		    thr_self(), inst->dpyNbr);
		return ERROR;
	}

	if (!IsInstanceRunning(inst))
		return ERROR;

	rv = PingFifo(inst->outFifo, inst->inFifo, pcscCfg.fifoPingTimeout);
	if (rv == INSTANCE_DIED) {
		AbortInstance(inst);
		Log3(PCSC_LOG_DEBUG, "<%4.4x> Instance :%d dead or dying",
		    thr_self(), inst->dpyNbr);
		return ERROR;

	} else if (rv < 0) {
		AbortInstance(inst);
		syslog(LOG_ERR, "Err contacting instance :%d. Abandoning", inst->dpyNbr);
		Log3(PCSC_LOG_DEBUG,
		    "<%4.4x> Ping :%d fail. Abandoning", thr_self(), inst->dpyNbr);
		return ERROR;

	}
	pid = rv;
	if (pid != inst->pid) {
		/* Make sure old instance is gone */
		if (inst->pid != 0)
			StopInstance(inst->dpyNbr, inst->pid);
		sprintf(inst->logbuf,
		    "<%4.4x> Using new pid=%d for :%d, prev=%d",
		    thr_self(), pid, inst->dpyNbr, inst->pid);
		Log2(PCSC_LOG_DEBUG, "%s", inst->logbuf);
	}
	inst->pid = pid;
	return SUCCESS;
}

static int
ForwardClientToInstance(int fdToSend, pcscd_t *inst)
{
	int sendStat;
	if (pcscCfg.verbose) {
		sprintf(inst->logbuf,
			"<%4.4x> XMIT#:%d fd=%d->instance :%d (pid=%d)",
			thr_self(), inst->nbrFdsSentToInstance,
			inst->fdToSend, inst->dpyNbr, inst->pid);
		Log2(PCSC_LOG_DEBUG, "%s", inst->logbuf);
	}

	if (!IsInstanceRunning(inst))
		return ERROR;

	inst->fdToSend = fdToSend;
	sendStat = SendClientFd(inst->outFifo, inst->inFifo, inst->fdToSend,
	    pcscCfg.fifoPingTimeout);

	if (sendStat < 0) {
		if (sendStat == INSTANCE_DIED) {
			Log2(PCSC_LOG_DEBUG, "Fifo message: :%d dead or dying",
			    inst->dpyNbr);
		} else {
			Log2(PCSC_LOG_CRITICAL,  "Unexpected failure to send fd to "
			    "pcscd instance :%d abandoning\n", inst->dpyNbr);
		}
		return ERROR;
	}
	++inst->nbrFdsSentToInstance;

#ifndef DEFER_FD_CLOSE
	SYS_CloseFile(inst->fdToSend);
#else
{
	int fdToClose;
	if (pcscCfg.verbose)
		Log3(PCSC_LOG_DEBUG, "<%4.4x> Queue fd=%d to close",
		    thr_self(), inst->fdToSend);
	SYS_MutexLock(&inst->garbageFdQlock);
	if ((fdToClose = PopFd(&inst->garbageFdQhead)) != -1) {
		if (pcscCfg.verbose)
			Log3(PCSC_LOG_DEBUG,
			    "<%4.4x> Completing deferred "
			    "close of fd: %d",
			    thr_self(), fdToClose);
		SYS_CloseFile(fdToClose);
	}
	SYS_MutexUnLock(&inst->garbageFdQlock);

	SYS_MutexLock(&inst->garbageFdQlock);
	QueueFd(&inst->garbageFdQhead, inst->fdToSend);
	SYS_MutexUnLock(&inst->garbageFdQlock);
}
#endif

	return SUCCESS;
}

static int
LaunchInstanceDaemon(pcscd_t *inst)
{
	int hyperbole = 0, chkcnt = 0, pid;
	/*
	 * Clean up old fifos and pid - makes for faster start up.
	 */
	CloseInstanceFifos(inst);
	CFGRmPath(inst->inFifoName);
	CFGRmPath(inst->outFifoName);
	DeletePidFile(inst->dpyNbr);
	StopInstance(inst->dpyNbr, 0);

	 /*
	  * If we've relaunched too many times too fast, terminate instance.
	  */
	if (time(NULL) - inst->launchTime < pcscCfg.relaunchInterval) {
	    if (++hyperbole > pcscCfg.relaunchThreshold) {
		Log1(PCSC_LOG_ERROR,
		    "**************************************");
		syslog(LOG_ERR, "Re-launching pcscd instance :%d "
			"too frequencly.  Abandoning\n", pcscCfg.dpyNbr);
		Log2(PCSC_LOG_ERROR,
		    "Relaunching instance :%d too frequently",
		    inst->dpyNbr);
		Log1(PCSC_LOG_ERROR,
		    "**************************************");
		return ERROR;
	    }
	}

	Log1(PCSC_LOG_DEBUG,"**************************************");
	Log2(PCSC_LOG_DEBUG,"Launching new instance for dpy :%d", inst->dpyNbr);
	Log1(PCSC_LOG_DEBUG,"**************************************");

	Log3(PCSC_LOG_DEBUG, "<%4.4x> Making new fifos for :%d",
	    thr_self(), inst->dpyNbr);

	if (mkfifo(inst->inFifoName, S_IWUSR | S_IRUSR) < 0) {
		Log4(PCSC_LOG_ERROR,
		    "Couldn't create fifo %s for instance :%d: %s",
		     inst->inFifoName, inst->dpyNbr, strerror(errno));
	}
	if (mkfifo(inst->outFifoName, S_IWUSR | S_IRUSR) < 0) {
		Log4(PCSC_LOG_ERROR,
		    "Couldn't create fifo %s for instance :%d: %s",
		     inst->outFifoName, inst->dpyNbr, strerror(errno));
	}

	/*
	 * Exec the new instance in such way as to prevent zombies
	 */
	Log2(PCSC_LOG_DEBUG, "Forking new pcscd instance for display :%d",
		inst->dpyNbr);
	switch(fork()) {
	case 0: // child
		setsid(); // Become session leader w/o controlling tty
		switch(fork()) {
		case 0: // child
			ExecInstance(inst);
		case -1:
			Log2(PCSC_LOG_CRITICAL,
			     "Can't fork: %s", strerror(errno));
			return ERROR;
		default:  // parrent: Allow session leader to exit
			exit(0);
		}
	case -1:
		Log2(PCSC_LOG_CRITICAL,
		     "Can't fork: %s", strerror(errno));
		return ERROR;
	}

	inst->launchTime = time(NULL);
	/*
	 * Wait for pid file to appear
	 */
	Log1(PCSC_LOG_DEBUG, "Waiting for pid file to appear");
	while ((pid = GetPidFromFile(inst->dpyNbr)) == 0 &&
		++chkcnt < MAX_INST_CHECKS)
			usleep(100000);

	++LauncherStats.nbrInstancesLaunched;

	if (chkcnt >= MAX_INST_CHECKS) {
		Log3(PCSC_LOG_CRITICAL,
		    "FATAL: Instance pid file for :%d not created within %d seconds",
		     inst->dpyNbr, MAX_INST_CHECKS);
		return ERROR;
	}

	Log3(PCSC_LOG_DEBUG, "Found pid=%d for new instance (launch #%d)",
		pid, LauncherStats.nbrInstancesLaunched);
	return SUCCESS;
}

static void
IncomingClientConnect(LPVOID context) {

	int rv, clientSockFd = (int)context;
	PCSCLITE_CRED_T cred;
	char line[LINEMAX], logbuf[LINEMAX], *cp;
	int dpyNbr, screenNbr;
	in_addr_t xHostIp;
	thread_t tid = thr_self();

	if (pcscCfg.verbose) {
		write(2, "\n", 1);
		Log3(PCSC_LOG_DEBUG,
			"<%4.4x> Validation thread started for (fd=%d) ",
			tid, clientSockFd);
	}
	/*
	 * Protocol requires connecting clients to immediately
	 * present X display that owns reader.
	 */
	memset(line, 0, sizeof (line));
	if ((rv = read(clientSockFd, line, sizeof(line))) < 0) {
		while (rv < 0 && (errno == EINTR || errno == EAGAIN)) {
			sleep(50000);
			rv = read(clientSockFd, line, sizeof(line));
		}
		if (rv < 0) {
			Log3(PCSC_LOG_ERROR,
			    "<%4.4x> Error reading from client sock: %s",
			    tid, strerror(errno));
			Log3(PCSC_LOG_ERROR,
			    "<%4.4x> closed (fd=%d), thread exiting",
			    tid, clientSockFd);
			SYS_CloseFile(clientSockFd);
		}
		return;
	}

	/*
	 * Parse display info.  Terminate conn. immediately on err.
	 */
	if ((cp = strchr(line, '\r')) != NULL)
	     *cp = '\0';
	/*
	 * If we got pinged, reply and exit (don't need to log it)
	 */
	if (strncasecmp(line, "PING", 4) == 0) {
		int pid;
		char resp[20], logresp[20];
		if (line[5] == '\0') {
			SYS_CloseFile(clientSockFd);
			return;
		}
		pid = atoi(line + 4);

		if (pcscCfg.verbose > 1)
			Log4(PCSC_LOG_DEBUG,
			    "<%4.4x> Validation (fd=%d) recvd: \"%s\"",
			    tid, clientSockFd, line);

		sprintf(logresp, "ACK %d", pid);
		sprintf(resp, "%s\n", logresp);

		if (pcscCfg.verbose > 1)
			Log4(PCSC_LOG_DEBUG,
			    "<%4.4x> Validation (fd=%d) reply: \"%s\"",
			    tid, clientSockFd, logresp);

		SendMsg(clientSockFd, resp);
		SYS_CloseFile(clientSockFd);
		return;
	}

	if (pcscCfg.verbose)
		Log4(PCSC_LOG_DEBUG,
			"<%4.4x> Validation thr (fd=%d) received: \"%s\"",
			tid, clientSockFd, line);
	/*
	 * Parse X Display parameter from client.
	 */
	rv = CFGParseXdisplay(line, &dpyNbr, &screenNbr, &xHostIp);
	if (rv != CFG_SUCCESS || dpyNbr == -1) {

		Log3(PCSC_LOG_ERROR,
		    "<%4.4x> Received invalid $DISPLAY info: %s", tid, line);
		Log3(PCSC_LOG_ERROR,
		    "<%4.4x> closed (fd=%d), thread exiting",
		    tid, clientSockFd);
		syslog(LOG_ERR,
			"Launcher: Receive invalid $DISPLAY: %s", line);
		Log3(PCSC_LOG_ERROR,
		    "<%4.4x> closed (fd=%d), thread exiting",
		    tid, clientSockFd);
		SYS_CloseFile(clientSockFd);
		return;
	}
	if (pcscCfg.useAuthentication) {
		void *ctx;

		if (AUTHGetClientCreds(clientSockFd, &cred) < 0) {
			Log3(PCSC_LOG_ERROR,
			    "<%4.4x> Error getting creds %s", tid, strerror(errno));
			Log2(PCSC_LOG_ERROR,
			    "<%4.4x> Couldn't get client creds. Terminating "
			    "client conn.", tid);
			Log3(PCSC_LOG_ERROR,
			    "<%4.4x> closed (fd=%d), thread exiting",
			    tid, clientSockFd);
			SYS_CloseFile(clientSockFd);
			return;
		}
		cred.dpyNbr = dpyNbr;
		cred.screenNbr = screenNbr;
		cred.clientXhostIP = xHostIp;

		sprintf(logbuf,	"<%4.4x> [ PID:%d uid:(%d, %d) %s:%d.%d ]",
		      tid, (int)cred.pid, (int)cred.euid, (int)cred.egid,
		      inet_ntoa(*(struct in_addr *)&cred.clientXhostIP),
		      cred.dpyNbr, cred.screenNbr);

		write(2, "\n", 1);
		Log2(PCSC_LOG_DEBUG, "%s", logbuf);

		char *facilityTag = NULL;
		void *resource = NULL;
		unsigned int flags;

		if (VALgetDisplayStatus(dpyNbr, &ctx, &flags) != DISPLAY_IS_VALID ||
		    VALgetDisplayTag(dpyNbr, ctx, &facilityTag) == NULL) {
			Log3(PCSC_LOG_ERROR,
			    "<%4.4x> Display :%d failed validation check",
			    tid, dpyNbr);
			SendMsg(clientSockFd, AUTHFAIL);
			SYS_CloseFile(clientSockFd);
			Log3(PCSC_LOG_DEBUG,
			    "<%4.4x> closed (fd=%d), thread exiting",
			    tid, clientSockFd);
			if (facilityTag != NULL)
				free(facilityTag);
			return;
		}
		VALgetDisplayResource(cred.dpyNbr, ctx, &resource);
		if (AUTHCheckDaemon((const char *)facilityTag, &cred,
		    resource) < 0) {
			Log2(PCSC_LOG_ERROR,
			    "<%4.4x> Auth check failed. Terminating client",
			    tid);
			SendMsg(clientSockFd, AUTHFAIL);
			SYS_CloseFile(clientSockFd);
			Log3(PCSC_LOG_DEBUG,
			    "<%4.4x> closed (fd=%d), thread exiting",
			    tid, clientSockFd);
			if (facilityTag != NULL)
				free(facilityTag);
			if (resource != NULL)
				free(resource);
			return;
		}
		Log3(PCSC_LOG_DEBUG,
		    "<%4.4x> Authenticated client \"%s\"",
		    tid, NONULL(facilityTag));

		if (flags & DISPLAY_HAS_NEW_PROVIDER) {
			 Log3(PCSC_LOG_DEBUG,
				 "\"%s\" display :%d has a new provider",
				 facilityTag, dpyNbr);
			 StopInstance(dpyNbr, 0);
		 }
		 if (facilityTag != NULL)
			free(facilityTag);
		 if (resource != NULL)
			free(resource);
	}
	QueueFdToInstance(dpyNbr, clientSockFd);
}


void
Launcher(int wellKnownPort)
{
	struct sockaddr_in ipaddr, clientIp;
	struct linger l = {0, 0};
	static socklen_t len;
	unsigned int threadp;
	unsigned int mode;
	int clientSockFd;
	int sndbufsize = 4096;
	int rcvbufsize = 4096;
	l.l_onoff  = 1;
	l.l_linger = 0;

	Log1(PCSC_LOG_DEBUG, "Setup launcher signal handlers\n");
	SetupSignalHandlers(LauncherExitHandler, 1);

	/*
	 * Create client connect socket
	 */
	if ((wellKnownPortSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		Log2(PCSC_LOG_CRITICAL,
			"Create socket: %s", strerror(errno));
		return;
	}
	/*
	 * Don't get stuck on CLOSED_WAIT / TIMED_WAIT
	 */
	mode = 1;
	if (setsockopt(wellKnownPortSocket, SOL_SOCKET, SO_REUSEADDR,
	    &mode, sizeof (mode)) < 0) {
	       Log2(PCSC_LOG_CRITICAL,
		   "setsockopt()/SO_REUSEADDR: %s", strerror(errno));
	       return;
	}
	/*
	 * No reason to linger, turn off for quicker recovery.
	 */
	if (setsockopt(wellKnownPortSocket, SOL_SOCKET, SO_LINGER,
	     &l, sizeof (l)) < 0) {
		Log2(PCSC_LOG_CRITICAL,
		    "setsockopt()/SO_LINGER: %s", strerror(errno));
		return;
	}
	/*
	 * Since launched instances don't need this socket.
	 * make sure it is automatically closed when we exec.
	 */
	if (fcntl(wellKnownPortSocket, F_SETFD, FD_CLOEXEC) < 0) {
		Log2(PCSC_LOG_CRITICAL,
		    "fcntl(FD_CLOEXEC) %s", strerror(errno));
		return;
	}

	/*
	 * Bind client connect socket to well known port
	 */
	bzero((char *)&ipaddr, sizeof (ipaddr));

	ipaddr.sin_family = AF_UNIX;
	ipaddr.sin_addr.s_addr = INADDR_ANY;
	ipaddr.sin_port = htons(wellKnownPort);

	if (bind(wellKnownPortSocket, (struct sockaddr *) &ipaddr,
	    sizeof(ipaddr)) < 0) {
		Log2(PCSC_LOG_CRITICAL,
		    "Bind to socket: %s", strerror(errno));
		return;
	 }
	/*
	 * Listen for client connections forever.
	 */
	for(;;) {

		if (pcscCfg.verbose) {
			write(2, "\n", 1);
			Log1(PCSC_LOG_DEBUG, "(Listen for client connection)");
		}

		if (listen(wellKnownPortSocket, 5) < 0)  {
			Log2(PCSC_LOG_DEBUG,
			    "Listen on socket: %s", strerror(errno));
			return;
		}
		/*
		 * Accept connections on well-known port.
		 */

		errno = 0;
		len = sizeof (clientIp);
		do {
			if ((clientSockFd = accept(wellKnownPortSocket,
			    (struct sockaddr *) &clientIp, &len)) < 0 &&
			     errno != EINTR) {
				     Log2(PCSC_LOG_CRITICAL,
					  "Accept on socket: %s", strerror(errno));
				     return;
			}
		} while (clientSockFd < 0 && errno == EINTR);

		if (pcscCfg.verbose) {
			Log2(PCSC_LOG_DEBUG,
			    "(Accepted connection [new fd=%d])", clientSockFd);
		}
		if (setsockopt(
			clientSockFd, SOL_SOCKET, SO_LINGER,
		     &l, sizeof (l)) < 0) {
			Log2(PCSC_LOG_CRITICAL,
			    "setsockopt()/SO_LINGER: %s", strerror(errno));
			return;
		}
		if (setsockopt(clientSockFd, SOL_SOCKET, SO_SNDBUF,
		     &sndbufsize, sizeof (sndbufsize)) < 0) {
			Log2(PCSC_LOG_CRITICAL,
			    "setsockopt()/SO_SNDBUF: %s", strerror(errno));
			return;
		}
		if (setsockopt(clientSockFd, SOL_SOCKET, SO_RCVBUF,
		     &rcvbufsize, sizeof (rcvbufsize)) < 0) {
			Log2(PCSC_LOG_CRITICAL,
			    "setsockopt()/SO_RCVBUF: %s", strerror(errno));
			return;
		}

		/*
		 * Don't get stuck on CLOSED_WAIT / TIMED_WAIT
		 */
		mode = 1;
		if (setsockopt(clientSockFd, SOL_SOCKET, SO_REUSEADDR,
		    &mode, sizeof (mode)) < 0) {
		       Log2(PCSC_LOG_CRITICAL,
			   "setsockopt()/SO_REUSEADDR: %s", strerror(errno));
		       return;
		}
		if (fcntl(clientSockFd, F_SETFD, FD_CLOEXEC) < 0) {
			char cmd[64];
			Log3(PCSC_LOG_CRITICAL, "fcntl(fd=%d, FD_CLOEXEC) %s",
				clientSockFd, strerror(errno));
			return;
		}
		if (SYS_ThreadCreate(&threadp,
		    THREAD_ATTR_DETACHED,
		    (PCSCLITE_THREAD_FUNCTION()) IncomingClientConnect,
		    (LPVOID) clientSockFd) != 1) {
				Log1(PCSC_LOG_CRITICAL,
				     "SYS_ThreadCreate failed");
				exit(EXIT_FAILURE);
		}
		if (pcscCfg.verbose)
			Log3(PCSC_LOG_DEBUG,
			    "(Created thread <%4.4x> to handle fd=%d)",
			    (int)threadp, clientSockFd);
	}
}


/**
 * @brief queues fd to end of list
 *
 * Must be called with newInst->fdQLock held.
 */
static void
QueueFd(fdQ_t **qHead, int fd) {
	fdQ_t *fdq, **ppfdq;

	ppfdq = qHead;
	fdq = malloc(sizeof (struct fdQ));
	if (fdq == NULL) {
		Log1(PCSC_LOG_CRITICAL, "Out of Memory");
		exit(EXIT_FAILURE);
	}
	fdq->fd = fd;
	fdq->next = NULL;

	while(*ppfdq != NULL)
		ppfdq = &(*ppfdq)->next;

	*ppfdq = fdq;
	fdq->next = NULL;
}

/**
 * @brief pops fd of top of list and returns it (null if no entry)
 *
 * Must be called with newInst->fdQLock held.
 *
 */
static int
PopFd(fdQ_t **qHead) {
	int fd;
	fdQ_t *fdq;
	if ((fdq = *qHead) == NULL)
		return -1;
	fd = fdq->fd;
	*qHead = (*qHead)->next;
	free(fdq);
	return fd;
}


/**
 * @brief Looks up instance data in our cache
 */
static pcscd_t *
FindInstanceByDpy(pcscd_t **qhead, int dpy) {
	pcscd_t *pi = *qhead;
	SYS_MutexLock(&instDBm);
	while(pi != NULL) {
		if (pi->dpyNbr == dpy) {
			SYS_MutexUnLock(&instDBm);
			return pi;
		}
		pi = pi->next;
	}
	SYS_MutexUnLock(&instDBm);
	return NULL;
}

static void
AddInstance(pcscd_t **qhead, pcscd_t *newInst) {
	pcscd_t **ppi = qhead;

	SYS_MutexLock(&instDBm);
	while(*ppi != NULL)
		ppi = &(*ppi)->next;
	*ppi = newInst;
	SYS_MutexUnLock(&instDBm);
	++LauncherStats.nbrInstancesActive;
}

static void
RemoveInstance(pcscd_t **qhead, pcscd_t *inst) {
	pcscd_t **pprev, **ppi = qhead;

	SYS_MutexLock(&instDBm);
	if (*qhead == inst) {
		*qhead = inst->next;
		SYS_MutexUnLock(&instDBm);
		return;
	}
	while (*ppi != inst && *ppi != NULL)  {
		pprev = ppi;
		ppi = &(*ppi)->next;
	}

	(*pprev)->next = (*ppi)->next;
	SYS_MutexUnLock(&instDBm);
	--LauncherStats.nbrInstancesActive;
}

static void
CloseInstanceFifos(pcscd_t *inst)
{
	if (inst->inFifo != 0) {
		close(inst->inFifo);
		inst->inFifo = 0;
	}
	if (inst->outFifo != 0) {
		close(inst->outFifo);
		inst->outFifo = 0;
	}
}

static int
WaitForEnqueuedFd(pcscd_t *inst)
{
	int fdToSend;
	SYS_MutexLock(&inst->fdQLock);
	while((fdToSend = PopFd(&inst->fdQhead)) == -1)
		SYS_CondWait(&inst->fdQNotify, &inst->fdQLock);
	--inst->nbrFdsQueued;
	SYS_MutexUnLock(&inst->fdQLock);
	return fdToSend;
}

static void
LauncherExitHandler(int signo)
{

	Log1(PCSC_LOG_DEBUG, "LauncherExitHandler called\n");
	SYS_CloseFile(wellKnownPortSocket);
	signal_trap(signo);
}

void dumpContexts()
{
}

/**
 * @brief sends Fd to instance, creating instance if necessary.
 */
static void
QueueFdToInstance(int dpyNbr, int clientFd)
{
	pcscd_t *newInst, *inst;
	int rv;

	Log4(PCSC_LOG_DEBUG,
	    "<%4.4x> QueueFdToInstance(:%d, fd=%d)",
	    thr_self(), dpyNbr, clientFd);

	if ((inst = FindInstanceByDpy(&instanceQ, dpyNbr)) == NULL) {

		Log3(PCSC_LOG_DEBUG,
		    "<%4.4x> No instance cached for :%d", thr_self(), dpyNbr);
		newInst =(pcscd_t *)malloc(sizeof (struct pcscd));

		if (newInst == NULL) {
			Log1(PCSC_LOG_CRITICAL, "Out Of Memory");
			exit(EXIT_FAILURE);
		}
		bzero(newInst, sizeof(struct pcscd));
		newInst->dpyNbr = dpyNbr;
		SYS_MutexLock(&newInst->fdQLock);
		QueueFd(&newInst->fdQhead, clientFd);
		++newInst->nbrFdsQueued;
		SYS_MutexUnLock(&newInst->fdQLock);
		AddInstance(&instanceQ, newInst);

		/*
		 * Create a per-instance thread to handle sending fds
		 */
		if ((rv = SYS_ThreadCreate(&newInst->tid,
		    THREAD_ATTR_DETACHED,
		    (PCSCLITE_THREAD_FUNCTION()) ManageInstance,
		    (LPVOID) newInst)) != 1) {
			  Log2(PCSC_LOG_CRITICAL,
			     "<%4.4x> SYS_ThreadCreate failed",thr_self());
			  exit(EXIT_FAILURE);
		}
	} else {
		char logbuf[LINEMAX];
		sprintf(logbuf,
			"<%4.4x> Instance :%d found (pid=%d) send fd=%d",
		    thr_self(), dpyNbr, inst->pid, clientFd);
		Log2(PCSC_LOG_DEBUG, "%s", logbuf);
		SYS_MutexLock(&inst->fdQLock);
		QueueFd(&inst->fdQhead, clientFd);
		++inst->nbrFdsQueued;
		SYS_CondSignal(&inst->fdQNotify);
		SYS_MutexUnLock(&inst->fdQLock);
	}
}

static void
AbortInstance(pcscd_t *inst)
{
	Log3(PCSC_LOG_ERROR, "AbortInstance() Stopping instance :%d (pid=%d)",
		inst->dpyNbr, inst->pid);
	StopInstance(inst->dpyNbr, inst->pid);
	StopInstance(inst->dpyNbr, 0);
}

static void
EradicateInstance(pcscd_t *inst) {
	int clientFd;
	Log3(PCSC_LOG_ERROR, "EradicateInstance() Stopping instance :%d (pid=%d)",
		inst->dpyNbr, inst->pid);
	StopInstance(inst->dpyNbr, inst->pid);
	StopInstance(inst->dpyNbr, 0);
	Log2(PCSC_LOG_ERROR, "EradicateInstance(): Removing instance :%d", inst->dpyNbr);
	SYS_MutexLock(&inst->fdQLock);
	RemoveInstance(&instanceQ, inst);
	if (inst->fdToSend != 0)
		SYS_CloseFile(inst->fdToSend);
	while((clientFd = PopFd(&inst->fdQhead)) != -1) {
		--inst->nbrFdsQueued;
		SendMsg(clientFd, LAUNCHFAIL);
		SYS_CloseFile(clientFd);
	}
	SYS_MutexUnLock(&inst->fdQLock);
	SYS_MutexDestroy(&inst->fdQLock);
#ifdef DEFER_FD_CLOSE
	SYS_MutexDestroy(&inst->garbageFdQlock);
#endif
	free(inst);
}



static void
ExecInstance(pcscd_t *inst)
{
	char disp[256], *argv[8];
	char *envp[] = { disp, 0 };
	char buf[10];
	int pid, rv;

	Log3(PCSC_LOG_DEBUG,
		"(as FORKED Child): Launching new pcscd instance:\n\n"
		"(as FORKED Child): exec():  %s -I -x :%d\n",
		execPath, inst->dpyNbr);
	/*
	 * ctrun (Solaris) is used here to exempt child from the Launcher's
	 * SMF contract, so that SMF doesn't try to manage our instances for us.
	 */
	argv[0] = "/bin/ctrun";
	argv[1] = "-l";
	argv[2] = "none";
	argv[3] = execPath;
	argv[4] = "-I";
	argv[5] = "-x";
	argv[6] = buf;
	argv[7] = 0;

	sprintf(disp, "DISPLAY=:%d", inst->dpyNbr);
	sprintf(buf, ":%d", inst->dpyNbr);

	rv = execve("/bin/ctrun", argv, envp);
	if (rv < 0) {
		Log3(PCSC_LOG_CRITICAL,
			"FORKED Child: Error execing /bin/ctrun %s -I -x %s",
			execPath, buf);
		exit(EXIT_FAILURE);
	}

	Log2(PCSC_LOG_CRITICAL, "FORKED Child: execve(): %s", strerror(errno));
	exit(EXIT_FAILURE);
}

int
IsInstanceRunning(pcscd_t *inst)
{
	int pid;

	Log2(PCSC_LOG_DEBUG, "-> isInstanceRunning(%d)", inst->dpyNbr);
	if ((pid = GetPidFromFile(inst->dpyNbr)) == 0) {
		Log2(PCSC_LOG_DEBUG,
			"  Couldn't find pid for display :%d", inst->dpyNbr);
		if (inst->pid != 0) {
			Log2(PCSC_LOG_DEBUG,
				"  Terminating prev instance pid=%d", inst->pid);
			StopInstance(inst->dpyNbr, inst->pid);
		}
		return 0;
	}
	/*
	 * Check to see if PID is running (but don't actually send signal)
	 */
	 if (kill(pid, 0) < 0) {
		 Log4(PCSC_LOG_DEBUG, "  pid=%d (from :%d pid file) : \"%s\"",
			 pid, inst->dpyNbr, strerror(errno));
		 return 0;
	 }
	Log3(PCSC_LOG_DEBUG, " PID=%d is running for display :%d", pid, inst->dpyNbr);
	return 1;
}


