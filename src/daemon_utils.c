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
#include <sys/time.h>

#include "pcsc_config.h"
#include "validate.h"
#include "daemon_utils.h"
#include "launcher.h"
#include "instance.h"
#include "pcsclite.h"
#include "debuglog.h"
#include <sys/socket.h>

#define LINEMAX	256
#define NONULL(a) (a) ? (a) : "<null>"

int instanceTotalFdsReceived = 0;
static int isPrefixed(char *, char *);

int
GetPidFromFile(int dpyNbr)
{
	char pidPath[256], pidbuf[10];
	FILE *pidFile;
	int pid;
	sprintf(pidPath, "%s/pid/%d", pcscCfg.baseDir, dpyNbr);
	if ((pidFile = fopen(pidPath, "r")) == NULL) {
// This needs to be silent
//		Log3(PCSC_LOG_DEBUG,
//			"GetPidFromFile:  Error opening %s: %s",
//			pidPath, strerror(errno));

		return 0;
	}
	setvbuf(pidFile, pidbuf, _IONBF, sizeof (pidbuf));
	fgets(pidbuf, sizeof (pidbuf), pidFile);
	fclose(pidFile);
	return atoi(pidbuf);
}
void
DeletePidFile(int dpyNbr)
{
	char pidPath[256];
	sprintf(pidPath, "%s/pid/%d", pcscCfg.baseDir, dpyNbr);
	unlink(pidPath);
}


int
StopInstance(int dpyNbr, int pid)
{
#define RETRY_MAX 20
	char fifoPath[256], cmd[256], *cfg, *inst;
	int instanceOutFifo, fpid, r = 0, cnt = 0;
	int instanceTerminated = 0;
	struct sigaction action;

	/*
	 * If pid is 0 we look up the pid for the specified
	 * display's instance in the pid directory and
	 */
	if (pid == 0) {
		sprintf(fifoPath,"%s/fifo/%d.i",
		    pcscCfg.baseDir, dpyNbr);

		if ((fpid = GetPidFromFile(dpyNbr)) != 0) {
			Log3(PCSC_LOG_DEBUG, "Terminating instance :%d, pid=%d",
				dpyNbr, fpid);

			if ((instanceOutFifo = open(fifoPath, O_RDWR)) >= 0)
				 SendCmd(instanceOutFifo, INSTANCE_DIED_TOKEN);
			 /*
			  * Be *sure* it's gone
			  */
			while (kill(fpid, SIGKILL) == 0 && ++cnt < 100) {
				instanceTerminated = 1;
				usleep(250000);
			}

			DeletePidFile(dpyNbr);
		} else {
			Log2(PCSC_LOG_INFO, "Can't stop instance :%d "
			    "(Couldn't find PID file)", dpyNbr);
			return;

		}
	} else {
		char buf[LINEMAX], dpy[10];
		FILE *fp;

		/*
		 * On the very slim chance that the pid's have cycled
		 * and been re-used, make sure we're terminating a pcscd
		 * process targetted for the originally named display.
		 * This makes the chance of terminating the wrong program
		 * impossible, and the chances of terminating the wrong
		 * pcscd instance astronomically slim.
		 *
		 * Some day this should be improved to make it impossible
		 * to ever fail under any circumstances.
		 */
		sprintf(cmd, "pargs -l %d", pid);
		if ((fp = popen(cmd , "r")) == NULL ||
		     fgets(buf, LINEMAX, fp) == NULL)
				return -1;
		pclose(fp);

		sprintf(dpy, ":%d", dpyNbr);
		if (strncmp(buf, pcscCfg.argv0, strlen(pcscCfg.argv0)) != 0 ||
		    strstr(buf, dpy) == NULL) {
			fprintf(stderr, "Error: Process args don't match.\n");
			pid = 0;
		} else {
			Log3(PCSC_LOG_DEBUG,
				"Terminating instance :%d, pid=%d", dpyNbr, pid);
			while (kill(pid, SIGKILL) == 0 && ++cnt < 100) {
				instanceTerminated = 1;
				usleep(250000);
			}

			DeletePidFile(dpyNbr);
		}
	}

	/*
	 * Do per platform specific instance clean up if a process was terminated.
	 */
		 if (VALfindInstanceFiles(dpyNbr, &cfg, &inst) == 0) {
			bzero(cmd, sizeof(cmd));
			sprintf(cmd, "%s -m STOP -x :%d -P %s -b %s -p %d",
				inst, dpyNbr, cfg, pcscCfg.baseDir, pid);
			if (system(cmd) < 0)
				Log3(PCSC_LOG_CRITICAL,
				    "system(\"%s\") failed: %s", cmd, strerror(errno));

			free(cfg);

			free(inst);
		}
	return pid;
}

/*
 * Receive file descriptor from parent process
 * If we can an fd, we cancel self-termination timer.
 */
int
ReceiveClientFd(int inFifo, int outFifo, int *receivedFd, int timeout) {
	char rcvbuf[LINEMAX];
	struct strrecvfd fdDescr;
	int rv, len;

	Log1(PCSC_LOG_DEBUG, "ReceiveClientFd()....");
	bzero(rcvbuf, sizeof (rcvbuf));
	/*
	 * Receive fd from fifo
	 */
	if ((rv = ioctl(inFifo, I_RECVFD, &fdDescr)) < 0) {
		if (pcscCfg.pcscdExiting)
			return TERMINATED;
		if (errno == EBADMSG) {
		       Log3(PCSC_LOG_DEBUG,
			   "ReceiveClientFd(i:%d, o:%d): Non-FD msg from fifo",
			   inFifo, outFifo);
		       /*
			* Receive non-FD message
			*/
		       len = sizeof (rcvbuf);
		       rv = DoFifoReceive(inFifo, rcvbuf, len,
			    pcscCfg.fifoPingTimeout);
		       if (rv < 0)
			       return rv;

		       return (DoFifoCmd(outFifo, rcvbuf));
		}
	}
	if (pcscCfg.pcscdExiting)
		return TERMINATED;

	Log3(PCSC_LOG_DEBUG,
	    "RECV# %d: Received fd=%d", ++instanceTotalFdsReceived, fdDescr.fd);

	/*
	 * Cancel self-termination timer before we ACK
	 */
	LockContextLookup();
	CancelInstanceTimer();

	/*
	 * unlocked after context thread created
	 */
	if (SendCmd(outFifo, FIFO_FD_ACK) < 0) {
		Log4(PCSC_LOG_CRITICAL,
			"ReceiveClientFd(i:%d, o:%d) "
			"Err writing ACK to fifo: %s",
			inFifo, outFifo, strerror(errno));
		return -1;

	}
	*receivedFd = fdDescr.fd;
	return SUCCESS;
}

/**
 * @brief Send ping message to out-fifo, expect in-fifo response
 *
 * The two fifo mechanism is a speed (performance) optimization.
 * It allows us to avoid the problem wherein if we used a single
 * fifo and send a 'ping' message, if we read back from the fifo
 * too soon (before receiver gets it), we'll REMOVE the message
 * from the fifo before the other side can read it.
 * To avoid that we'd have to wait a min. amount of time,
 * which means that we introduce an unnecessary delay
 * if the other side happens to be really fast with the response.
 */
int
PingFifo(int outFifo, int inFifo, int timeout) {
	char rcvbuf[LINEMAX];
	int len, pid;

	if (SendCmd(outFifo, FIFO_PING_CMD) < 0) {
		Log3(PCSC_LOG_ERROR, "<%4.4x> PingFifo(outfd=%d) Err sending",
		    thr_self(), outFifo);
		return ERROR;
	}
	len = sizeof (rcvbuf);
	switch(DoFifoReceive(inFifo, rcvbuf, len, timeout)) {
	case ERROR:
		Log3(PCSC_LOG_ERROR,
		    "<%4.4x> PingFifo(outfd=%d): Err receiving",
		    thr_self(), outFifo);
		return ERROR;
	case TIMEOUT:
		Log3(PCSC_LOG_ERROR, "<%4.4x> PingFifo(outfd=%d) ACK timed out",
		    thr_self(), outFifo);
		return TIMEOUT;
	}

	if (strcmp(rcvbuf, INSTANCE_DIED_TOKEN) == 0)
		return INSTANCE_DIED;

	if (!isPrefixed(rcvbuf, "PID="))
		return ERROR;

	pid = atoi(rcvbuf + 4);

	Log4(PCSC_LOG_DEBUG, "<%4.4x> PingFifo((outfd=%d): OK pid=%d",
		    thr_self(), outFifo, pid);

	return pid;
}


/*
 * @brief Handle 'non-FD' message
 *
 * Handles case where instance was waiting for an FD to be
 * sent to the fifo, but instead got a message.  The message
 * was read, and handed to this function to process it.
 */
int
DoFifoCmd(int outFifo, char *cmd) {
	char sndbuf[LINEMAX];
	/*
	 * If it's a ping message, respond with PID
	 */
	if (isPrefixed(cmd, FIFO_PING_CMD)) {
		Log4(PCSC_LOG_DEBUG,
		    "<%4.4x> DoFifoCmd(o:%d) Got PING. Replying with PID=%d",
		    thr_self(), outFifo, getpid());

		sprintf(sndbuf, "PID=%d", (int)getpid());

		if (SendMsg(outFifo, sndbuf) < 0) {
			Log4(PCSC_LOG_ERROR,
			    "<%4.4x> DoFifoCmd(fd=%d):SendMsg(): %s",
			    thr_self(), outFifo, strerror(errno));
			return ERROR;
		}
		return INTERRUPTED;

	} else if (isPrefixed(cmd, FIFO_EXIT_CMD)) {
		kill(getpid(), SIGTERM);
		return TERMINATED;
	}
	Log4(PCSC_LOG_ERROR,
		"<%4.4x> DoFifoCmd(fd=%d): Bad fifo msg: \"%s\"",
		thr_self(), outFifo, cmd);
	return ERROR;
}

/**
 * @brief Open an existing fifo and set fd characteristics.
 */
int
OpenFifo(char *fifoName, int ndelay)
{
	int fd;

	if ((fd = open(fifoName, O_RDWR)) < 0) {
		Log4(PCSC_LOG_ERROR, "<%4.4x> OpenFifo(%s):\n%s",
		    thr_self(), NONULL(fifoName), strerror(errno));
		return ERROR;
	}
	{
		char logbuf[LINEMAX];
		sprintf(logbuf, "<%4.4x> %s -> fd=%d",
		    thr_self(), NONULL(fifoName), fd);
		Log2(PCSC_LOG_DEBUG, "%s", logbuf);
	}
	if (ndelay) {
		if (fcntl(fd, F_SETFL, O_NDELAY) < 0) {
			Log4(PCSC_LOG_DEBUG,
			    "<%4.4x> OpenFifo(%s):fcntl(O_NDELAY): %s",
			    thr_self(), fifoName, strerror(errno));
			return ERROR;
		}
	}

	if (fcntl(fd, F_SETFL, FD_CLOEXEC) < 0) {
		Log4(PCSC_LOG_DEBUG,
		    "<%4.4x> OpenFifo(%s):fcntl(FD_CLOEXEC): %s",
		    thr_self(), fifoName, strerror(errno));
		return ERROR;
	}
	return fd;
}

/*
 * Receive response respons from fifo which is returned to
 * caller.  If timeout, an error is returned.
 */
int
DoFifoReceive(int inFifo, void *rcvbuf, int rcvlen, int timesecs)
{
	fd_set read_fd;
	struct timeval tv;
	tv.tv_sec = timesecs;
	tv.tv_usec = 0;
	char logbuf[LINEMAX];
	int rv;

	FD_ZERO(&read_fd);
	FD_SET(inFifo, &read_fd);

	if (pcscCfg.verbose)
		Log3(PCSC_LOG_DEBUG, "<%4.4x> DoFifoReceive(infd=%d):select()",
		    thr_self(), inFifo);

	if ((rv = select(inFifo + 1, &read_fd, NULL, NULL, &tv)) < 0) {
		while (rv < 0 && (errno == EINTR || errno == EAGAIN)) {
			usleep(50000);
			rv = select(inFifo + 1, &read_fd, NULL, NULL, &tv);
		}
		if (rv < 0) {
			Log4(PCSC_LOG_ERROR,
			    "<%4.4x> DoFifoReceive():select(infd=%d): %s",
			    thr_self(), inFifo, strerror(errno));
			return ERROR;      // Error
		}
	} else if (rv == 0) {
		Log4(PCSC_LOG_ERROR,
		    "<%4.4x> DoFifoReceive():select(infd=%d) Timeout (%d secs)",
		    thr_self(), inFifo, timesecs);
		return TIMEOUT;
	}

	if (FD_ISSET(inFifo, &read_fd)) {
		if (read(inFifo, rcvbuf, rcvlen) < 0) {
			while (rv < 0 && (errno == EINTR || errno == EAGAIN)) {
				usleep(50000);
				rv = select(inFifo + 1, &read_fd, NULL, NULL, &tv);
			}
			if (rv < 0) {
				Log4(PCSC_LOG_ERROR,
					"<%4.4x> DoFifoReceive():read(infd=%d) failed: %s",
					thr_self(), inFifo, strerror(errno));
				return ERROR;      // Error
			}
		}
	}

	if (pcscCfg.verbose) {
		sprintf(logbuf, "<%4.4x> DoFifoReceive(infd=%d): ...Read %d bytes",
		    thr_self(), inFifo, rv);

		Log2(PCSC_LOG_DEBUG, "%s", logbuf);
	}
	return SUCCESS;
}


/*
 * @brief  Send client's file descriptor over fifo
 *
 * Send's client's FD over pipe and expect response.
 */
int
SendClientFd(int outFifo, int inFifo, int fdToSend, int timeout) {
	char rcvbuf[LINEMAX];
	int rv;

	if (pcscCfg.verbose)
		Log4(PCSC_LOG_DEBUG,
			"SendClientFd(outfd=%d, infd:%d sendfd:%d)",
			outFifo, inFifo, fdToSend);

	if (ioctl(outFifo, I_SENDFD, fdToSend) < 0) {
		Log4(PCSC_LOG_CRITICAL,
		    "<%4.4x> SendClientFd(fd=%d) ioctl(I_SENDFD): %s",
		    thr_self(), outFifo, strerror(errno));
		return ERROR;
	}
	bzero(rcvbuf,sizeof (rcvbuf));
	rv = DoFifoReceive(inFifo, rcvbuf, sizeof (rcvbuf), timeout);
	switch(rv){
	case ERROR:
		Log4(PCSC_LOG_CRITICAL,
		   "<%4.4x> SendClientFd(outfd=%d, send:fd=%d) ACK error",
		   thr_self(), outFifo, fdToSend);
		return ERROR;
	case TIMEOUT:
		Log4(PCSC_LOG_CRITICAL,
		    "<%4.4x> SendClientFd(outfd=%d, send:fd=%d) ACK timeout",
		    thr_self(), outFifo, fdToSend);
		return TIMEOUT;
	default:
		break;
	}
	if (strcmp(rcvbuf, INSTANCE_DIED_TOKEN) == 0)
		return INSTANCE_DIED;

	if (!isPrefixed(rcvbuf, FIFO_FD_ACK)) {
		Log4(PCSC_LOG_CRITICAL,
		    "<%4.4x> SendClientFd(outfd=%d, sendfd=%d): Bad ACK msg:",
		    thr_self(), outFifo, fdToSend);
		Log3(PCSC_LOG_CRITICAL,
		    "<%4.4x>   Expected ACK as \"%s\"",
		    thr_self(), FIFO_FD_ACK);
		Log3(PCSC_LOG_CRITICAL,
		    "<%4.4x>   Received: \"%s\"",
		    thr_self(), rcvbuf);
		return ERROR;
	}
	return SUCCESS;
}

/*
 * Send Message to fd
 */
int
SendMsg(int fd, char *s)
{
	int rv =  write(fd, s, strlen(s) + 1);
	while (rv < 0 && (errno == EINTR || errno == EAGAIN)) {
		usleep(50000);
		rv =  write(fd, s, strlen(s) + 1);
	}
	if (rv < 0) {
		Log4(PCSC_LOG_ERROR,
		    "<%4.4x> SendMsg(): Err during write(fd=%d): %s",
		    thr_self(), fd, strerror(errno));
		return ERROR;
	}
	return SUCCESS;
}

/*
 * Send Command to fd
 */
int
SendCmd(int fd, char *s)
{
	int rv =  write(fd, s, strlen(s) + 1);
	while (rv < 0 && (errno == EINTR || errno == EAGAIN)) {
		usleep(50000);
		rv =  write(fd, s, strlen(s) + 1);
	}
	if (rv < 0) {
		Log4(PCSC_LOG_ERROR,
		    "<%4.4x> SendCmd(): Err during write(fd=%d): %s",
		    thr_self(), fd, strerror(errno));
		return ERROR;
	}
	return SUCCESS;
}

void
catch_SIGHUP(int signo)
{
	FILE *fp;
	char buf[256];

	Log1(PCSC_LOG_DEBUG, "Caught SIGHUP\n");

	sprintf(buf, "/tmp/pcscd_%d", (int)getpid());
	if ((fp = fopen(buf, "w+")) == NULL) {
		Log2(PCSC_LOG_CRITICAL,
		    "Couldn't open file /tmp/pcscd_%d",
		     (int)getpid());
	}
	CFGdumpCfg(fp);
	fclose(fp);
}

void
catch_SIGCHLD(int signo)
{
	int stat, pid;
	pid = wait(&stat);
	Log2(PCSC_LOG_DEBUG, "\nCaught SIGCHLD for pid %d\n", pid);

}

void
SetupSignalHandlers(void (*fp)(int), int trapKbdSignals) {

	struct sigaction action;
	action.sa_handler = fp;
	action.sa_flags = 0;

	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL) < 0) {
		Log2(PCSC_LOG_CRITICAL,
		     "Sigaction failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (trapKbdSignals &&
	    sigaction(SIGQUIT, &action, NULL) < 0 ||
	    sigaction(SIGINT,  &action, NULL) < 0) {
		Log2(PCSC_LOG_CRITICAL,
		     "Sigaction failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	action.sa_handler = catch_SIGHUP;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	if (sigaction(SIGHUP, &action, NULL) < 0) {
		Log2(PCSC_LOG_CRITICAL, "Sigaction failed: %s",
		     strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Disable zombie creation and SIGCHLD (both) - helps performance
	 * prevents zombies, and prevent difficult EINTR issues.
	 */
	action.sa_handler = NULL;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_NOCLDWAIT | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &action, NULL) < 0) {
		Log2(PCSC_LOG_CRITICAL, "Sigaction failed: %s",  strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/*
 * Returns true if buf is begins with string s
 */
static int
isPrefixed(char *buf, char *s) {
	return (strncmp(buf, s, strlen(s)) == 0);
}
