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

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "pcsc_config.h"
#include "pcsclite.h"
#include "winscard_msg.h"
#include "winscard_svc.h"
#include "daemon_utils.h"
#include "instance.h"
#include "hotplug.h"
#include "debuglog.h"
#include "sys_generic.h"
#include "powermgt_generic.h"

#define LINEMAX	256
extern PCSCLITE_MUTEX usbNotifierMutex;
PCSCLITE_MUTEX contextLookupMutex;
extern char ReCheckSerialReaders;
extern char AraKiri;
extern void at_exit(void);
static void InstanceSvcRunLoop(int, int);
static void TimerThread(LPVOID);

extern void SetStdOutErr(char *);
extern void setupLogging();

char pidPath[LINEMAX];

PCSCLITE_THREAD_T timeoutThreadP;
PCSCLITE_MUTEX timerMutex;
#define INFINITE_TIME -1
int timeRemaining = INFINITE_TIME;

/*
 * Fifos last the duraction of the instance.
 */
char instanceInFifoName[FIFONAME_MAX_BUFSIZE];
char instanceOutFifoName[FIFONAME_MAX_BUFSIZE];
int inFifo, outFifo;

#define NONULL(a) (a) ? (a) : "<null>"


/*
 * The following inherits the configuration of the parent
 * and assumes X Display information is already configured.
 */
void
InitializeInstance(void)
{
	static char display[_POSIX_HOST_NAME_MAX + 15];
	char cmdstr[LINEMAX];
	char confstr[LINEMAX];
	char pidbuf[PID_ASCII_SIZE + 1];
	int  rv, pid;
	FILE *pidFile;

	Log3(PCSC_LOG_DEBUG,
		"Initializing new instance: pcscd -I -x :%d, pid=%d\n",
		pcscCfg.dpyNbr, getpid());

	Log1(PCSC_LOG_DEBUG, "Setup instance signal handlers");
	SetupSignalHandlers(InstanceExitHandler, 0);

	/*
	 * Fork to ditch our launcher (ctrun)
	 */
	switch(fork()) {
	case 0:
		break;
	case -1:
		Log1(PCSC_LOG_CRITICAL, "Error forking");
	default: // Exit if parent or error (fallthru intentional)
		exit(0);
	}

	setsid();
	sprintf(pidPath, "%s/pid", launcherCfg.baseDir);
	CFGEnsurePathExists(pidPath);
	sprintf(pidPath, "%s/pid/%d", launcherCfg.baseDir, pcscCfg.dpyNbr);
	pcscCfg.pcscdPIDFile = strdup(pidPath);

	/*
	 * Make sure previous instance [if any] isn't running
	 */
	if ((pidFile = fopen(pidPath, "rb")) != NULL) {
		fgets(pidbuf, sizeof (pidbuf), pidFile);
		fclose(pidFile);
		pid = atoi(pidbuf);
		StopInstance(pcscCfg.dpyNbr, pid);
	}
	/*
	 * Replace the file with our pid
	 */
	CFGRmPath(pidPath);
	if ((pidFile = fopen(pidPath, "wb")) != NULL) {
		fprintf(pidFile, "%u\n", (unsigned) getpid());
		fclose(pidFile);
	}


	/* If X display # exists, make available to IFD handlers */
	if (pcscCfg.dpyNbr != -1) {
		sprintf(display, "DISPLAY=:%d", pcscCfg.dpyNbr);
		Log2(PCSC_LOG_DEBUG, "putenv(%s)", display);
		putenv(display);
	}

	/*
	 * Resolve wildcard for the base dir
	 */
	if (pcscCfg.baseDir != NULL) {
		if (pcscCfg.baseDirWild) {
			char dpyNbr[6];
			if (pcscCfg.dpyNbr == -1) {
				CFGperror(CFG_UNDEFINED_DISPLAY, "");
				exit(EXIT_FAILURE);
			}
			sprintf(dpyNbr, "%d", pcscCfg.dpyNbr);
			CFGresolveWildcard(&pcscCfg.baseDir, dpyNbr);
		}
	}

	/*
	 * Look for parent fifos.  We're launched and they're not there,
	 * something is wrong.
	 */
	sprintf(instanceInFifoName, "%s/fifo/%d.o",
		launcherCfg.baseDir, pcscCfg.dpyNbr);

	sprintf(instanceOutFifoName,"%s/fifo/%d.i",
		launcherCfg.baseDir, pcscCfg.dpyNbr);

	if ((inFifo = open(instanceInFifoName, O_RDWR)) < 0) {
		Log2(PCSC_LOG_CRITICAL,
		     "Couldn't open fifo %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((outFifo = open(instanceOutFifoName, O_RDWR)) < 0) {
		Log2(PCSC_LOG_CRITICAL,
		     "Couldn't open fifo %s", strerror(errno));
		exit(EXIT_FAILURE);
	}


	/*
	 * Launch Xserver tag-specific initialization script to
	 * setup pcscd basedir and environment for this instance.
	 */
	Log1(PCSC_LOG_DEBUG, "Launching instance setup script:");
	Log2(PCSC_LOG_DEBUG, "  script  = %s",
		NONULL(pcscCfg.instanceScript));
	Log2(PCSC_LOG_DEBUG, "  conf    = %s",
		NONULL(pcscCfg.pcscConfigFile));
	Log2(PCSC_LOG_DEBUG, "  base    = %s",
		NONULL(pcscCfg.baseDir));
	Log2(PCSC_LOG_DEBUG, "  display = %d", pcscCfg.dpyNbr);
	Log2(PCSC_LOG_DEBUG, "  pid     = %d", getpid());

	sprintf(cmdstr, "%s -m START -x :%d -P %s -b %s -p %d",
	    pcscCfg.instanceScript, pcscCfg.dpyNbr,
	    pcscCfg.pcscConfigFile, pcscCfg.baseDir,
	    getpid());

	if (system(cmdstr) < 0)
		Log3(PCSC_LOG_CRITICAL,
		"system(\"%s\") failed: %s", cmdstr, strerror(errno));

	/*
	 * Adapt server configuration file paths, assigning
	 * a default value (based on header constants) to any path
	 * unspecified by the administrator.
	 */
	if (pcscCfg.readerConfigFile == NULL)
		pcscCfg.readerConfigFile =
		    CFGRetrofitPath(
		       PCSCLITE_CONFIG_DIR "/reader.conf", "/etc");
	else
		pcscCfg.readerConfigFile =
		    CFGRetrofitPath(pcscCfg.readerConfigFile, NULL);

	if (pcscCfg.ifdPluginDir != NULL)
		pcscCfg.ifdPluginDir =
		    CFGRetrofitPath(pcscCfg.ifdPluginDir, NULL);

	if (pcscCfg.useMappedMemory) {
		if (pcscCfg.pcscdMemMappedFile == NULL)
			pcscCfg.pcscdMemMappedFile =
			    CFGRetrofitPath(PCSCLITE_PUBSHM_FILE, "/var/run");
		else
			pcscCfg.pcscdMemMappedFile =
			CFGRetrofitPath(pcscCfg.pcscdMemMappedFile, NULL);
	} else {
		pcscCfg.pcscdMemMappedFile = NULL;
	}

	if (pcscCfg.transportType == SOCKET_UNIX) {
		if (pcscCfg.netBindFile == NULL) {
			pcscCfg.netBindFile =
			    CFGRetrofitPath(PCSCLITE_CSOCK_NAME, "/var/run");
		} else {
			pcscCfg.netBindFile =
			    CFGRetrofitPath(pcscCfg.netBindFile, NULL);
		}
	}

	if (pcscCfg.useMappedMemory) {
		CFGEnsurePathExists(
		    SYS_Dirname(pcscCfg.pcscdMemMappedFile));
	}


	/*
	 * Display this instance's configuration context.
	 */
	CFGdumpCfg(NULL);
	/*
	 * Allocate memory for reader structures
	 */

	RFAllocateReaderSpace();
	/*
	 * Load reader.conf for this instance and start
	 * ifd handlers.
	 */
	if (pcscCfg.readerConfigFile && strlen(pcscCfg.readerConfigFile) > 0 &&
	    CFGDoesFileExist(pcscCfg.readerConfigFile))  {
		Log2(PCSC_LOG_DEBUG, "Loading static readers from %s\n",
			pcscCfg.readerConfigFile);
		rv = RFStartSerialReaders(pcscCfg.readerConfigFile);
		if (rv != 0) {
			Log3(PCSC_LOG_CRITICAL,
			     "Invalid reader config file:%s: %s",
			     pcscCfg.readerConfigFile, strerror(errno));
			at_exit();
		}
		Log1(PCSC_LOG_DEBUG, "Readers loaded\n");

	} else {
		Log1(PCSC_LOG_DEBUG, "No static readers configured");
	}
	usleep(200000);
	/*
	 * Set the default globals
	 */
	g_rgSCardT0Pci.dwProtocol = SCARD_PROTOCOL_T0;
	g_rgSCardT1Pci.dwProtocol = SCARD_PROTOCOL_T1;
	g_rgSCardRawPci.dwProtocol = SCARD_PROTOCOL_RAW;

	InstanceSvcRunLoop(inFifo, outFifo);

}

/**
 * @brief The Server's Message Queue Listener function.
 *
 * An endless loop calls the function \c SHMProcessEventsServer() to check for
 * messages sent by clients.
 * If the message is valid, \c CreateContextThread() is called to serve this
 * request.
 */
static void
InstanceSvcRunLoop(int inFifo, int outFifo)
{
	int rv = 0;
	DWORD dwClientID; /* Connection ID used to reference the Client */

	Log1(PCSC_LOG_DEBUG, "Main Instance run loop starting...\n");
	/*
	 * Start instance timer thread, and begin timeout countdown
	 * If we don't get any connections, we'll eventually timeout.
	 */
	if (SYS_ThreadCreate(&timeoutThreadP, THREAD_ATTR_DETACHED,
		(PCSCLITE_THREAD_FUNCTION( )) TimerThread,
		(LPVOID) pcscCfg.instanceTimeout) != 1) {
			Log1(PCSC_LOG_CRITICAL, "SYS_ThreadCreate failed");
	}

	StartInstanceTimer();

	if (ContextsInitialize() == -1) {
		Log1(PCSC_LOG_CRITICAL, "Error initializing pcscd.");
		exit(EXIT_FAILURE);
	}

	signal(SIGALRM, SIG_IGN); // Ignore SIGALRM (which Solaris sends)
	signal(SIGPIPE, SIG_IGN);

	/*
	 * This function always returns zero
	 */
	rv = SYS_MutexInit(&usbNotifierMutex);

	/*
	 * Set up the search for USB/PCMCIA devices
	 */
	HPSearchHotPluggables();
	HPRegisterForHotplugEvents();

	/*
	 * Set up the power management callback routine
	 */
	PMRegisterForPowerEvents();

	for (;;) {
		switch (rv = ReceiveClientFd(inFifo, outFifo,
		    (int *)&dwClientID, pcscCfg.fifoPingTimeout)) {
		case 0:
			/*
			 * Send ACK message to client
			 */
			SendMsg(dwClientID, CONNECTOK);

			Log2(PCSC_LOG_DEBUG,
				"Client fd=%d received from launcher",
				dwClientID);
			Log2(PCSC_LOG_DEBUG,
				"Creating context fd=%d", dwClientID);

			rv = CreateContextThread(&dwClientID);
			if (rv != SCARD_S_SUCCESS) {
				Log1(PCSC_LOG_ERROR,
				   "Problem during context thread creation");
				AraKiri = TRUE;
			}
			break;
		case ERROR:
			Log1(PCSC_LOG_ERROR,
			     "Error in ReceiveClientFD");
			break;
		case TIMEOUT:
			Log1(PCSC_LOG_ERROR,
			     "Timed out reading non-FD message");
			break;
		case INTERRUPTED:
			// Interrupted by "PING", silently re-start
			break;
		case TERMINATED:
			Log1(PCSC_LOG_DEBUG,
				"InstanceSvcRunLoop: pcscd Terminated");
			sleep(3600);  //If we're not dead already, wait for it
			break;
		case SEVERE:
			/* Don't display if exiting or re-reading config */
			if ((!AraKiri) && (!ReCheckSerialReaders))
				Log1(PCSC_LOG_ERROR, "Err in ReceiveClientFd");
			break;
		}

		if (AraKiri) {
			/*
			 * Stop hotplug thread, wait for exit.
			 */
			HPStopHotPluggables();
			SYS_Sleep(1);
			/*
			 * Stop all drivers
			 */
			RFCleanupReaders(1);
		}
	}
}


void
InstanceExitHandler(int signo)
{
	char cmdstr[1024], outFifoName[256];

	if (signo != 0)
		Log2(PCSC_LOG_DEBUG, "Received signal %d. Cleaning up\n", signo);
	/*
	 * This helps the launcher detect instance death faster
	 * than having to time out on a PING.
	 */
	Log1(PCSC_LOG_DEBUG, "Sending INSTANCE_DIED to fifo\n");
	SendCmd(outFifo, INSTANCE_DIED_TOKEN);

	/*
	 * Remove fifos (after queing message to them)
	 * so launcher doesn't try to
	 * contact us over them after we're gone.
	 */
	(void) CFGRmPath(instanceOutFifoName);
	(void) CFGRmPath(instanceInFifoName);

	/*
	 * Remove our pid tracking file
	 */
	(void) CFGRmPath(pcscCfg.pcscdPIDFile);

	/*
	 * Run the helper script in termination mode
	 */
	sprintf(cmdstr, "%s -m STOP -x :%d -P %s -b %s -p %d",
	    pcscCfg.instanceScript,  pcscCfg.dpyNbr,
	    pcscCfg.pcscConfigFile,  pcscCfg.baseDir,
	    getpid());

	Log2(PCSC_LOG_DEBUG, "Invoking instance script to clean-up:\n%s\n", cmdstr);

	if (system(cmdstr) < 0)  {
		Log3(PCSC_LOG_CRITICAL,
		    "system(\"%s\") failed: %s", cmdstr, strerror(errno));
	}


	Log1(PCSC_LOG_DEBUG, "Instance shutdown complete. Exiting...\n");
	pcscCfg.pcscdExiting = 1;
	kill(getpid(), SIGKILL);
	exit(0); // just in case

/*
 * We don't want to get hung up in this code... probably just remove it
	HPStopHotPluggables();
	SYS_Sleep(1);
	RFCleanupReaders(0); // Unload reader drivers
	exit(0);
*/
}

/**
 * @brief Thread to terminate process after some period inactivty
 *
 * This is only used in 'launcher mode' and if enabled.
 * One thread lasts the duration of the process.
 * The timeout can be canceled or reinstated at will.
 */
static void TimerThread(LPVOID arg)
{
	for (;;) {
		SYS_MutexLock(&timerMutex);
		if (timeRemaining != INFINITE_TIME) {
			if (--timeRemaining == 0) {
				Log2(PCSC_LOG_DEBUG,
				    "instance (pid=%d): "
				    "Inactivity timer expired.", getpid());
				InstanceExitHandler(0);
			}
		}
		SYS_MutexUnLock(&timerMutex);
		sleep(1);
	}
}

void StartInstanceTimer()
{
	SYS_MutexLock(&timerMutex);
	if (pcscCfg.instanceTimeout > 0)
		timeRemaining = pcscCfg.instanceTimeout;
	SYS_MutexUnLock(&timerMutex);
	if (pcscCfg.instanceTimeout > 0) {
		Log3(PCSC_LOG_DEBUG,
			"instance (pid=%d): %d sec exit timer started",
			getpid(), pcscCfg.instanceTimeout);
	}
}

void CancelInstanceTimer()
{
	int saveRemaining;

	SYS_MutexLock(&timerMutex);
	saveRemaining = timeRemaining;
	timeRemaining = INFINITE_TIME;
	SYS_MutexUnLock(&timerMutex);

	if (saveRemaining != INFINITE_TIME) {
		Log2(PCSC_LOG_DEBUG,
			"pcscd pid=%d inactivity timeout canceled", getpid());

		Log3(PCSC_LOG_DEBUG, "%d out of %d secs remaining.",
			saveRemaining, pcscCfg.instanceTimeout);
	}
}

void
LockContextLookup()
{
	SYS_MutexLock(&contextLookupMutex);
}

void
UnlockContextLookup()
{
	SYS_MutexUnLock(&contextLookupMutex);
}


