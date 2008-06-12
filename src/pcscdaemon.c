/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2005
 *  David Corcoran <corcoran@linuxnet.com>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *  Paul Klissner <paul.klissner@sun.com>
 *
 * $Id$
 *
 * @file
 * @brief This is the main pcscd daemon.
 *
 * The function \c main() starts up the communication environment.\n
 * Then an endless loop is calld to look for Client connections. For each
 * Client connection a call to \c CreateContextThread() is done.
 */


#include "config.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/varargs.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <syslog.h>


#include <dlfcn.h>
#include <link.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "misc.h"
#include "pcsclite.h"
#include "pcsc_config.h"
#include "daemon_utils.h"
#include "debuglog.h"
#include "instance.h"
#include "winscard_msg.h"
#include "winscard_svc.h"
#include "sys_generic.h"
#include "thread_generic.h"
#include "hotplug.h"
#include "readerfactory.h"
#include "configfile.h"
#include "powermgt_generic.h"
#include "pcscdaemon.h"
#include "validate.h"

PCSCLITE_MUTEX usbNotifierMutex;
char *execPath;
struct pcsc_cfg_data pcscCfg;
struct pcsc_cfg_data launcherCfg;

char AraKiri = FALSE;
static char Init = TRUE;
extern char ReCheckSerialReaders;
static int column = 0;

void printWrap(const char *, ...);
void ListInvocationModes();
void usage(char const * const);


/**
 * @brief The Server's Message Queue Listener function.
 *
 * An endless loop calls the function \c SHMProcessEventsServer() to
 * check for messages sent by clients.
 *
 * If the message is valid, \c CreateContextThread() is called to
 * serve this request.
 */
void
SVCServiceRunLoop(void)
{
	int rsp = 0;
	LONG rv = 0;
	DWORD dwClientID;  /* Connection ID (fd) used to reference Client */

	if (SHMInitializeCommonSegment() == -1) {
		Log1(PCSC_LOG_CRITICAL, "Error initializing pcscd.");
		exit(-1);
	}

	if (ContextsInitialize() == -1) {
		Log1(PCSC_LOG_CRITICAL, "Error initializing pcscd.");
		exit(-1);
	}

	signal(SIGALRM, SIG_IGN); // Disable SIGALRM sent by Solaris
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP,  SIG_IGN); // Disable SIGHUP sent by Solaris if shell

	(void) SYS_MutexInit(&usbNotifierMutex);

	/*
	 * Set up the search for USB/PCMCIA devices
	 */
	HPSearchHotPluggables();
	HPRegisterForHotplugEvents();

	/*
	 * Set up the power management callback routine
	 */
	PMRegisterForPowerEvents();

	while (TRUE) {
		switch (rsp = SHMProcessEventsServer(&dwClientID, 0)) {
		case 0:
			Log2(PCSC_LOG_DEBUG,
			     "A new context thread creation "
			     "is requested: %d", dwClientID);

			rv = CreateContextThread(&dwClientID);

			if (rv != SCARD_S_SUCCESS)  {
				Log1(PCSC_LOG_ERROR,
				     "Problem in context thread creation");
				AraKiri = TRUE;
			}
			break;

		case 2:
			/*
			 * Timeout in SHMProcessEventsServer(): do nothing
			 * this is used to catch the Ctrl-C signal at some
			 * time when nothing else happens
			 */
			break;

		case -1:
			/* Don't display if exiting or re-reading config */
			if ((!AraKiri) && (!ReCheckSerialReaders))
				Log1(PCSC_LOG_ERROR,
				     "Error in SHMProcessEventsServer");
			break;

		default:
			Log2(PCSC_LOG_ERROR,
			    "SHMProcessEventsServer unknown retval: %d", rsp);
			break;
		}
		if (AraKiri) {
			/* stop the hotpug thread and waits its exit */
			HPStopHotPluggables();
			SYS_Sleep(1);

			RFCleanupReaders(1);  // Stop all driver
		}
	}
}


int
main(int argc, char **argv)
{
	char args[LINEMAX];
	char cwd[LINEMAX];
	char name[LINEMAX];
	char tmp[MAXPATHLEN];
	char *cp;
	int i, opt, servicePort = 0;
	int stopInstFlag = 0, rv;
	int dpyNbr, screenNbr;
	int instpid = 0;
	in_addr_t xHostIp;

#ifdef PCSCLITE_PORTSVC_PORTNO
	servicePort = PCSCLITE_PORTSVC_PORTNO;
#else
	servicePort = 0;
#endif

	pcscCfg.argv0 = strdup(argv[0]);
	ChkVersion();

	/*
	 * Build list of the valid options.
	 */
	bzero(args, sizeof (args));
	for (i = 0; longOpts[i].name != NULL; i++) {
		char item[4];
		if (longOpts[i].has_arg)
			sprintf(item, "%c:", longOpts[i].val);
		else
			sprintf(item, "%c", longOpts[i].val);
		strcat(args, item);
	}

	/*
	 * Check for these options first
	 */
	CFGSetConfigConsumer(DEFAULT);
	while ((opt = GETOPT(argc, argv, args, longOpts, optIndex)) != -1) {
		switch(opt) {
		case OPT_INSTANCE:
			CFGSetConfigConsumer(INSTANCE);
			break;
		case OPT_LAUNCHER:
			CFGSetConfigConsumer(LAUNCHER);
			break;
		}
	}

	/*
	 * Set up defaults
	 */
	DebugLogSetLogType(DEBUGLOG_SYSLOG_DEBUG);
	DebugLogSetLevel(PCSC_LOG_CRITICAL);

	CFGDefault("USE_AUTHENTICATION",	"FALSE");
	CFGDefault("TRANSPORT",			"SOCKET_UNIX");
	CFGDefault("USE_MAPPED_MEMORY",		"TRUE");
	CFGDefault("PORT_NUMBER_WILD",		"FALSE");
	CFGDefault("INSTANCE_TIMEOUT",		"0");
	CFGDefault("BASE_DIR_WILD",		"FALSE");
	CFGDefault("LOG_LEVEL",			"CRITICAL");
	CFGDefault("LOG_TYPE",			"SYSLOG");
	CFGDefault("STATUS_POLL_RATE",		"400000");
	CFGDefault("FIFO_PING_TIMEOUT",         "4");
	CFGDefault("RELAUNCH_THRESHOLD",        "2");
	CFGDefault("RELAUNCH_INTERVAL",         "1");

	pcscCfg.pcscConfigFile = PCSCLITE_CONFIG_DIR "/pcscd.conf";


	/*
	 * Scan options for arguments to process prior to loading config file
	 */
	 optind = 0;  // Reset for re-processing cmd line args
	 while ((opt = GETOPT(argc, argv, args, longOpts, optIndex)) != -1) {
		switch(opt) {
		case OPT_STOPINST:
			/*
			 * Defer geting X display #
			 */
			stopInstFlag = TRUE;
			break;

		case OPT_LAUNCHER:  //Intentionally handled before & after file load.
			if (servicePort > 0) {
				rv = CFGSetArg(opt, "LAUNCH_MODE", "LAUNCHER", USER);
				if (rv != CFG_SUCCESS) {
					CFGperror(rv, "OPT_LAUNCHER");
					exit(EXIT_FAILURE);
				}
			} else {
				Log2(PCSC_LOG_ERROR,
				     "-%c option not enabled. See "
				     "'configure --enable-portsvc'",
				     OPT_LAUNCHER);
				exit(EXIT_FAILURE);
			}
			break;
		case OPT_INSTANCE:  //Intentionally handled before & after file load.

			if (servicePort > 0) {
				rv = CFGSetArg(opt, "LAUNCH_MODE", "INSTANCE", USER);
				if (rv != CFG_SUCCESS) {
					CFGperror(rv, "OPT_INSTANCE");
					exit(EXIT_FAILURE);
				}
			} else {
				Log2(PCSC_LOG_ERROR,
				     "-%c option not enabled. See "
				     "'configure --enable-portsvc'",
				     OPT_INSTANCE);
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_DISPLAY:
			rv = CFGParseXdisplay(optarg,
				 &dpyNbr, &screenNbr, &xHostIp);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_DISPLAY");
				exit(EXIT_FAILURE);
			}
			pcscCfg.dpyNbr = dpyNbr;
			pcscCfg.screenNbr = screenNbr;
			pcscCfg.xHostIp = xHostIp;
			break;

		case OPT_CONFIG:
			pcscCfg.pcscConfigFile = strdup(optarg);
			break;

		case OPT_PID:
			instpid = atoi(optarg);
			if (instpid == 0) {
				Log1(PCSC_LOG_CRITICAL, "Invalid PID");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_LOGFILE:
			rv = CFGSetArg(opt, "LOG_FILE", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "LOG_FILE");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_FOREGROUND:
			DebugLogSetLogType(DEBUGLOG_STDERR_DEBUG);
			rv = CFGSetArg(opt, "RUN_IN_FOREGROUND", "TRUE",  USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_FOREGROUND");
				exit(EXIT_FAILURE);
			}

			rv = CFGProcessKvp("LOG_TYPE", "STDERR", USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_FOREGROUND");
				exit(EXIT_FAILURE);
			}

			break;

		case OPT_LOGTYPE:
			rv = CFGSetArg(opt, "LOG_TYPE", optarg,  USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_LOGTYPE");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_LOGLEVEL:
			DebugLogSetLevel(PCSC_LOG_DEBUG);
			rv = CFGSetArg(opt, "LOG_LEVEL", optarg,  USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_SET_LOGLEVEL");
				exit(EXIT_FAILURE);
			}
			break;

		default:
			break;
		}
	}

	/*
	 * Load main config file, used by both launcher and instance.
	 * (instance also loads instance-specific conf later).
	 */
	rv = CFGLoadConfigFile(pcscCfg.pcscConfigFile);
	if (rv != CFG_SUCCESS) {
		CFGperror(rv, "Error loading configuration file");
		exit(EXIT_FAILURE);
	}
	bcopy(&pcscCfg, &launcherCfg, sizeof (pcscCfg));

	CFGSetupLogging();
	if (pcscCfg.logType == STDERR && pcscCfg.logFile != NULL) {
		pcscCfg.logFile = CFGRetrofitPath(pcscCfg.logFile, NULL);
		CFGStdOutErr(pcscCfg.logFile);
	}

	sprintf(tmp, "%s/pcscd_validate.conf", 	PCSCLITE_LIB_DIR);
	pcscCfg.validateConf = strdup(tmp);

	VALloadPlugins();

	if (pcscCfg.launchMode == INSTANCE) {
		char *cfg, *inst;
		if (VALfindInstanceFiles(pcscCfg.dpyNbr, &cfg, &inst) < 0) {
			Log2(PCSC_LOG_CRITICAL,
			    "Couldn't find instance files for display %d",
			    pcscCfg.dpyNbr);
			exit(EXIT_FAILURE);
		}
		pcscCfg.pcscConfigFile = cfg;
		pcscCfg.instanceScript = inst;
		(void) CFGLoadConfigFile(pcscCfg.pcscConfigFile);
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
		CFGSetupLogging();
		if (pcscCfg.logType == STDERR && pcscCfg.logFile != NULL) {
			pcscCfg.logFile = CFGRetrofitPath(pcscCfg.logFile, NULL);
			CFGStdOutErr(pcscCfg.logFile);
		}
		Log2(PCSC_LOG_DEBUG, "pcscd PID=%d logging...\n", getpid());
		if (pcscCfg.apduDebug) {
			Log1(PCSC_LOG_DEBUG,
				"Setting APDU debug mode");
			DebugLogSetCategory(DEBUG_CATEGORY_APDU);
		}
	}


	if (stopInstFlag) {
		if (instpid == 0) {
			fprintf(stderr, "Must specify valid PID\n");
			exit(-1);
		}
		StopInstance(pcscCfg.dpyNbr, instpid);
		exit(0);
	} else if (pcscCfg.launchMode == LAUNCHER) {
		if (*argv[0] != '/') {
			Log1(PCSC_LOG_CRITICAL,
			     "Must invoke with full path to executable\n"
			     "in launcher mode");
			exit(EXIT_FAILURE);
		}
		execPath = strdup(argv[0]);

		if (pcscCfg.portNbr == 0 && servicePort > 0)
			pcscCfg.portNbr =  servicePort;

		pcscCfg.dpyNbr = -1;
		pcscCfg.screenNbr = -1;
		pcscCfg.xHostIp = -1;

		if (strlen(XSERVERS_FILE) == 0) {
		    Log1(PCSC_LOG_CRITICAL,
			 "Must configure with --enable-xtag=<Xservers PATH>\n"
			 "To run in port service/daemon-launcher mode (-#)");
		    exit(EXIT_FAILURE);
		}
	} else if (pcscCfg.launchMode != INSTANCE) {
		/*
		* Attempt to read DISPLAY from the environment.
		* We excuse it here if it's not defined, because it may
		* be passed as an argv[] option, or simply not required
		* depending on other options pcscd was launched with.
		*/
		int rv = CFGParseXdisplay(SYS_Getenv("DISPLAY"),
			&dpyNbr, &screenNbr, &xHostIp);
		pcscCfg.dpyNbr = dpyNbr;
		pcscCfg.screenNbr = screenNbr;
		pcscCfg.xHostIp = xHostIp;
		switch(rv) {
		case CFG_SUCCESS:
		case CFG_UNDEFINED_DISPLAY:
			break;
		default:
			CFGperror(rv, "Error parsing display");
			exit(EXIT_FAILURE);
		}
	}



	/*
	 * Re-scan command line arguments for remaining arguments.
	 * Arguments found in this scan override the conf file
	 * settings.
	 */
	optind = 0;  // Reset for re-processing cmd line args
	while ((opt = GETOPT(argc, argv, args, longOpts, optIndex)) != -1) {
		switch (opt) {
		case OPT_LAUNCHER: //handled before & after file load.

			if (servicePort > 0) {
				rv = CFGSetArg(opt, "LAUNCH_MODE", "LAUNCHER", USER);
				if (rv != CFG_SUCCESS) {
					CFGperror(rv, "OPT_LAUNCHER");
					exit(EXIT_FAILURE);
				}
			} else {
				Log2(PCSC_LOG_ERROR,
				     "-%c option not enabled. See "
				     "'configure --enable-portsvc'",
				     OPT_LAUNCHER);
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_INSTANCE:  //Instance processing both before & after file load.

			if (servicePort > 0) {
				rv = CFGSetArg(opt, "LAUNCH_MODE", "INSTANCE", USER);
				if (rv != CFG_SUCCESS) {
					CFGperror(rv, "OPT_INSTANCE");
					exit(EXIT_FAILURE);
				}
			} else {
				Log2(PCSC_LOG_ERROR,
				     "-%c option not enabled. See "
				     "'configure --enable-portsvc'",
				     OPT_INSTANCE);
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_USEAUTH:
			rv =  CFGSetArg(opt, "USE_AUTHENTICATION", "TRUE", USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_USEAUTH");
				exit(EXIT_FAILURE);
			}
			break;
		case OPT_READERCFG:
			Log2(PCSC_LOG_DEBUG, "using new config file: %s",
			     optarg);
			rv = CFGSetArg(opt, "READER_CONFIG_FILE", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_READERCFG");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_BASEDIR:
			rv = CFGSetArg(opt, "BASE_DIR", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_BASEDIR");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_IFDLIBDIR:
			rv = CFGSetArg(opt, "IFD_PLUGIN_PATH", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_IFDLIBDIR");
				exit(EXIT_FAILURE);
			}
			break;
		case OPT_PORT:
			rv = CFGSetArg(opt, "PORT_NUMBER", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_PORT");
				exit(EXIT_FAILURE);
			}
			break;
		case OPT_VERBOSE:
			rv = CFGSetArg(opt, "VERBOSE", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_VERBOSE");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_TRANSPORT:
			rv = CFGSetArg(opt, "TRANSPORT", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_TRANSPORT");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_TIMEOUT:
			rv = CFGSetArg(opt, "INSTANCE_TIMEOUT", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_TIMEOUT");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_MAPFILE:
			rv = CFGSetArg(opt, "MEMORY_USEMAPPED_FILE", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_MAPFILE");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_USEMAPPED:
			rv = CFGSetArg(opt, "USE_MAPPED_MEMORY", optarg, USER);
			if (rv != CFG_SUCCESS) {
				CFGperror(rv, "OPT_USEMAPPED");
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_HELP:
			usage(argv[0]);
			return EXIT_SUCCESS;

		case OPT_VERSION:
			print_version();
			return EXIT_SUCCESS;

		case OPT_APDU:
			DebugLogSetCategory(DEBUG_CATEGORY_APDU);
			break;

		case OPT_FOREGROUND:    /* Ignore (processed earlier) */
		case OPT_STOPINST:      /* Ignore (processed earlier) */
		case OPT_DISPLAY:       /* Ignore (processed earlier) */
		case OPT_CONFIG:        /* Ignore (processed earlier) */
		case OPT_LOGTYPE:       /* Ignore (processed earlier) */
		case OPT_LOGLEVEL:      /* Ignore (processed earlier) */
		case OPT_LOGFILE:       /* Ignore (processed earlier) */
			break;
		default:
			usage (argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (argv[optind]) {
		printf("Unknown option: %s\n\n", argv[optind]);
		usage(argv[0]);
		return EXIT_SUCCESS;
	}
	/*
	 * Create subdirectory under specified base dir if
	 * a wildcard was specified and set that as the new
	 * base dir.
	 */
	if (pcscCfg.baseDir != NULL) {
		if (pcscCfg.baseDirWild) {
			char dpyNbr[6];
			if (pcscCfg.dpyNbr == -1) {
				Log1(PCSC_LOG_CRITICAL, "Undefined $DISPLAY");
				return EXIT_FAILURE;
			}
			sprintf(dpyNbr, "%d", pcscCfg.dpyNbr);
			CFGresolveWildcard(&pcscCfg.baseDir, dpyNbr);
		}
		rv = CFGEnsurePathExists(pcscCfg.baseDir);
	}


	chdir(pcscCfg.baseDir);

	/*
	 * These commands need to be deferred until this point
	 * to allow all the options from the command line to be
	 * provided, along with the loading of the configuration
	 * file, and the overrides applied if any.
	 */
	if (pcscCfg.launchMode == INSTANCE) {
		InitializeInstance();
		exit(0);
	}

	/*
	 * Adjust port number by the wildcard specifier, if any.
	 */
	 if (pcscCfg.portNbrWild) {
		    if (pcscCfg.dpyNbr == -1) {
			  Log1(PCSC_LOG_CRITICAL, "Undefined $DISPLAY");
			  return EXIT_FAILURE;
		    }
		    CFGresolveWildcard(&pcscCfg.portNbr,
			(void *)pcscCfg.dpyNbr);
	 }

	/* If X display # exists, make available to IFD handlers */
	if (pcscCfg.dpyNbr != -1) {
		static char display[_POSIX_HOST_NAME_MAX + 15];
		sprintf(display, "DISPLAY=:%d", pcscCfg.dpyNbr);
		putenv(display);
	}

	/*
	 * Adapt all of the server configuration file paths, assigning
	 * a default value (based on header constants) to any path
	 * unspecified by the administrator.
	 *.
	 * If a base directory was specified, adapt resultant filepaths
	 * to be relative to it using the following method:
	 *
	 *   a. Unspecified files which were assigned default names in the
	 *      first step are put into *default* subtree locations under
	 *      the base dir.
	 *
	 *   b. Filepaths that were specified by the administrator are
	 *      converted from absolute paths to relative paths under the
	 *      base dir.
	 *
	 * Note: If the IFD library plugin dir is specified by the admin,
	 *       it overrides any dir locations specified in readers.conf
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

	if (pcscCfg.transportType == SOCKET_UNIX ||
	    pcscCfg.launchMode == LAUNCHER) {
		if (pcscCfg.netBindFile == NULL) {
			pcscCfg.netBindFile =
			    CFGRetrofitPath(PCSCLITE_CSOCK_NAME, "/var/run");
		} else {
			pcscCfg.netBindFile =
			    CFGRetrofitPath(pcscCfg.netBindFile, NULL);
		}
	}
#ifdef USE_RUN_PID
	if (pcscCfg.pcscdPIDFile == NULL) {
		pcscCfg.pcscdPIDFile =
		    CFGRetrofitPath(USE_RUN_PID, "/var/run");
	} else {
		pcscCfg.pcscdPIDFile =
		    CFGRetrofitPath(pcscCfg.pcscdPIDFile, NULL);
	}
#endif
	if (pcscCfg.launchMode == LAUNCHER) {
		pcscCfg.readerConfigFile = NULL;
		pcscCfg.ifdPluginDir = NULL;
		pcscCfg.pcscdMemMappedFile = NULL;
		pcscCfg.netBindFile = NULL;
		pcscCfg.useMappedMemory = FALSE;
	}

	/*
	 * Make sure directory exists for these files.
	 * Depending on the paths configured by the admin, these
	 * directories may overlap or even refer multiply to the
	 * same directory, but it is harmless, since it won't create
	 * directories that exist.
	 */
	if (pcscCfg.netBindFile != NULL) {
		CFGEnsurePathExists(
		    cp = SYS_Dirname(pcscCfg.netBindFile));
		if (cp != NULL)
			free(cp);
	}

	if (pcscCfg.useMappedMemory) {
		CFGEnsurePathExists(
		    cp = SYS_Dirname(pcscCfg.pcscdMemMappedFile));
		if (cp != NULL)
			free(cp);
	}

#ifdef USE_RUN_PID
	if (pcscCfg.pcscdPIDFile != NULL) {
		CFGEnsurePathExists(
		    cp = SYS_Dirname(pcscCfg.pcscdPIDFile));
		if (cp != NULL)
			free(cp);
	}
#endif

	CFGdumpCfg(NULL);

	if (DoRunCheck() < 0)
		return EXIT_FAILURE;

	if (!pcscCfg.runInForeground) {
		Daemonize();
	}

	/*
	 * cleanly remove /tmp/pcsc when exiting
	 */
	signal(SIGQUIT, signal_trap);
	signal(SIGTERM, signal_trap);
	signal(SIGINT,  signal_trap);

#ifdef USE_RUN_PID
	/*
	 * Record our pid to make it easier to kill the correct pcscd
	 */
	{
		FILE *f;
		if ((f = fopen(pcscCfg.pcscdPIDFile, "wb")) != NULL)
		{
			fprintf(f, "%u\n", (unsigned) getpid());
			fclose(f);
		}
	}
#endif

	if (pcscCfg.launchMode == LAUNCHER) {
		Init = FALSE;
		Launcher(pcscCfg.portNbr);
		return 0;
	}

	/* cleanly remove /var/run/pcsc.* files when exiting */
	if (atexit(at_exit))
		Log2(PCSC_LOG_CRITICAL,
		     "atexit() failed: %s", strerror(errno));

	RFAllocateReaderSpace(); // Allocate memory for reader structs

	/*
	 * Grab the information from the reader.conf
	 */
	if (pcscCfg.readerConfigFile) {
		if ( RFStartSerialReaders(pcscCfg.readerConfigFile) != 0) {
			Log3(PCSC_LOG_CRITICAL,
			     "Invalid reader config file:\n%s: %s",
			     pcscCfg.readerConfigFile, strerror(errno));
			at_exit();
		}
	}
	/*
	 * Set the default globals
	 */
	g_rgSCardT0Pci.dwProtocol  = SCARD_PROTOCOL_T0;
	g_rgSCardT1Pci.dwProtocol  = SCARD_PROTOCOL_T1;
	g_rgSCardRawPci.dwProtocol = SCARD_PROTOCOL_RAW;

	Log1(PCSC_LOG_DEBUG, "pcsc-lite " VERSION " daemon ready.");

	Init = FALSE;  // Post initialization
	/*
	 * signal_trap() merely sets a global var, used by main loop
	 */
	signal(SIGQUIT, signal_trap);
	signal(SIGTERM, signal_trap);
	signal(SIGINT,  signal_trap);
	signal(SIGHUP,  signal_trap);
	signal(SIGUSR1, signal_reload);

	SVCServiceRunLoop();

	Log1(PCSC_LOG_ERROR, "SVCServiceRunLoop returned");
	return EXIT_FAILURE;
}

void
Daemonize()
{
	int si, so, se;

	Log2(PCSC_LOG_DEBUG,
		"Sending daemon to background: %d\n",getpid());
	/*
	* First fork guarantees we're not process group leader.
	*/
	switch(fork()) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "Bad fork: %s\n", strerror(errno));
	default:
		exit(0);
	}
	setsid(); // Become session leader w/o controlling tty
	/*
	 * 2nd fork - allow session leader to exit.
	 * Now we        are forever detached from a controlling tty.
	 */
	switch(fork()) {
	case 0:
		break;
	case -1:
		fprintf(stderr, "Bad fork: %s\n", strerror(errno));
	default:
		exit(0);
	}
	/*
	 * Assign sysin, sysout, syserr to mute (leaving them
	 * closed is bad practice).  They can be connected to
	 * other source or targets subsequently, depending on
	 * configuration settings.
	 */
	if ((si = open("/dev/null", O_RDWR)) >= 0)
		dup2(si, 0);

	if ((so = open("/dev/null", O_RDWR)) >= 0)
		dup2(si, 1);

	if ((se = open("/dev/null", O_RDWR)) >= 0)
		dup2(si, 2);

	chdir(pcscCfg.baseDir);

}

void
ChkVersion()
{
	if (strcmp(PCSCLITE_VERSION_NUMBER, VERSION) != 0) {
		printf("BUILD ERROR: The release version "
		       "number PCSCLITE_VERSION_NUMBER\n");
		printf("  in pcsclite.h (%s) does not match "
		       "the release version number\n",
			PCSCLITE_VERSION_NUMBER);
		printf("  generated in config.h (%s) (see "
		       "configure.in).\n", VERSION);
		exit(EXIT_FAILURE);
	}
}

int
DoRunCheck()
{
	int rv;
	struct stat fStatBuf;
	/*
	 * Test the presence of file that flags that the daemon is running.
	 * Default for single instance server is /var/run/pcsc.pub
	 */
	rv = SYS_Stat(pcscCfg.netBindFile, &fStatBuf);

	if (SYS_Stat(pcscCfg.pcscdMemMappedFile, &fStatBuf) == 0)
	{
#ifdef USE_RUN_PID
/* pids are only 15 bits but 4294967296
 * (32 bits in case of a new system use it) is on 10 bytes
 */
#define PID_ASCII_SIZE 11

		/* Read pid file to get the old pid and test
		 * if the old pcscd is still running
		 */
		FILE *f;
		char pid_ascii[PID_ASCII_SIZE];
		int pid;

		if ((f = fopen(pcscCfg.pcscdPIDFile, "rb")) != NULL) {
			fgets(pid_ascii, PID_ASCII_SIZE, f);
			fclose(f);

			pid = atoi(pid_ascii);

			if (kill(pid, 0) == 0)  {
				Log3(PCSC_LOG_CRITICAL,
				     "File %s already exists.\nAnother"
				     "pcscd (pid: %d) seems to be running.",
				     pcscCfg.pcscdMemMappedFile, pid);
				return -1;
			} else
				CleanTempFiles();  //Prev pcscd is gone
		} else {
			char buf[LINEMAX];
			sprintf(buf,
			    "File %s already exists.\nMaybe another pcscd "
			    " is running?\nCan't read process pid from %s\n"
			    "Remove %s  %s\nif pcscd is not running, "
			    "to clear this message.",
				    NONULL(pcscCfg.pcscdMemMappedFile),
				    rv < 0 ? "" : NONULL(pcscCfg.netBindFile),
				    pcscCfg.pcscdMemMappedFile,
				    pcscCfg.pcscdPIDFile);
			Log2(PCSC_LOG_CRITICAL, "%s", buf);
			return -1;
		}
#else
		Log4(PCSC_LOG_CRITICAL,
		    "File %s already exists.\nMaybe another pcscd is "
		    "running?\nRemove %s   %s\nif pcscd is not running,"
		    "to clear this message.",
		       pcscCfg.pcscdMemMappedFile,
		       NONULL(pcscCfg.pcscdMemMappedFile),
		       rv < 0 ? "" : NONULL(pcscCfg.netBindFile));
		return -1;
#endif

	}
	return 0;
}

void
CFGSetupLogging()
{
	switch (pcscCfg.logType) {
	case STDERR:
		DebugLogSetLogType(DEBUGLOG_STDERR_DEBUG);
		break;
	case SYSLOG:
		DebugLogSetLogType(DEBUGLOG_SYSLOG_DEBUG);
		break;
	default:
		DebugLogSetLogType(DEBUGLOG_STDERR_DEBUG);

	}

	switch (pcscCfg.logLevel) {
	case DEBUG:
		DebugLogSetLevel(PCSC_LOG_DEBUG);
		break;
	case INFO:
		DebugLogSetLevel(PCSC_LOG_DEBUG);
		break;
	case ERROR:
		DebugLogSetLevel(PCSC_LOG_ERROR);
		break;
	case CRITICAL:
		DebugLogSetLevel(PCSC_LOG_CRITICAL);
		break;
	default:
		DebugLogSetLevel(PCSC_LOG_DEBUG);

	}
}

void
CFGStdOutErr(char *filename)
{
	if (filename != NULL && strlen(filename) > 0) {
		int fd;
		DebugLogSetLogType(DEBUGLOG_STDERR_DEBUG);
		if ((fd = open(filename, O_WRONLY | O_CREAT | O_APPEND | O_SYNC,
		    S_IRWXU)) < 0) {
			fprintf(stderr, "Error opening logfile %s: %s",
			    pcscCfg.logFile, strerror(errno));
		}
		dup2(fd, 1);
		dup2(fd, 2);
	}
}

/*
 * Cleans up messages still on the queue when a client dies
 */
void
SVCClientCleanup(psharedSegmentMsg msgStruct)
{
	/*
	 * May be implemented in future releases
	 */
}

void
at_exit(void)
{
	Log1(PCSC_LOG_DEBUG, "Cleaning per-instance files\n");
	CleanTempFiles();
}

void
CleanTempFiles(void)
{
	int rv;
#ifdef USE_RUN_PID
	if (pcscCfg.launchMode == LAUNCHER) {
		rv = CFGRmPath(pcscCfg.pcscdPIDFile);
		if (rv != CFG_SUCCESS) {
			Log3(PCSC_LOG_DEBUG, "Cannot unlink %s:\n%s",
			    pcscCfg.pcscdPIDFile, strerror(errno));
		}
	}
#endif

	/*
	 * Clean up the network binding file if
	 * the transport type indicates that one
	 * was required.
	 */
	switch(pcscCfg.transportType) {
	case SOCKET_UNIX:
		rv = CFGRmPath(pcscCfg.netBindFile);
		if (rv != CFG_SUCCESS) {
			Log3(PCSC_LOG_DEBUG, "Cannot unlink %s:\n%s",
			    pcscCfg.pcscdPIDFile, strerror(errno));
		}
		break;
	default:
		break;
	}

	if (pcscCfg.useMappedMemory) {
		rv = CFGRmPath(pcscCfg.pcscdMemMappedFile);
		if (rv != CFG_SUCCESS) {
			Log3(PCSC_LOG_DEBUG, "Cannot unlink %s:\n%s",
			    pcscCfg.pcscdPIDFile, strerror(errno));
		}
	}
}

void
signal_reload(int sig) {
	Log1(PCSC_LOG_DEBUG, "Reload serial configuration");
	HPReCheckSerialReaders();
}


void
signal_trap(int sig)
{
	/* Signal handler is called several times for the same Ctrl-C */
	if (AraKiri == FALSE)  {
		Log1(PCSC_LOG_DEBUG, "Preparing for suicide");
		AraKiri = TRUE;
		/* If still in the init/loading phase
		 * AraKiri flag won't be seen by main event loop
		 */
		if (Init) {
			Log1(PCSC_LOG_DEBUG, "Suicide during init");
			at_exit();
		}
	}
}

void
print_version (void)
{
	printf("%s version %s_%s.\n",  PACKAGE, VERSION, BUILD);
	printf("Copyright (C) 2007-2008 by Sun Microsystems, Inc.\n");
	printf("Copyright (C) 2003-2004 "
	       "by Damien Sauveron <sauveron@labri.fr>.\n");
	printf("Copyright (C) 2001-2005 "
	       "by Ludovic Rousseau <ludovic.rousseau@free.fr>.\n");
	printf("Copyright (C) 1999-2002 "
	       "by David Corcoran <corcoran@linuxnet.com>.\n");
//	printf("Report bugs to <sclinux@linuxnet.com>.\n");
}

char
*getLongOptName(int opt)
{
	int i;
	for (i = 0; longOpts[i].name != NULL; i++)
		if (longOpts[i].val == opt)
			return longOpts[i].name;
	return "";
}

void
usage(char const * const progname)
{
	int i;
	printf("\n Usage: %s options\n\n",
		(char *)SYS_Basename((char *)progname));

	ListInvocationModes();
	printf("   Options:\n\n");

#ifdef HAVE_GETOPT_LONG
	for (i = 0; usageMsgs[i].usage != NULL; i++)
		printf("       -%c   --%-14s   %s\n", usageMsgs[i].opt,
		   getLongOptName(usageMsgs[i].opt), usageMsgs[i].usage);

#else
	for (i = 0; usageMsgs[i].usage != NULL; i++)
		printf("       -%c   %s\n", usageMsgs[i].opt,
		   usageMsgs[i].usage);
#endif
	printf("\n");
}

/*
 * The function formats the usage arguments so that they will be displayed
 * well if the valid argument counts, names and values change.
 */
void
ListInvocationModes()
{
	char buf[LINEMAX], arg[10], *cp, *c2;
	int i, j, k, reqFlag = 0, loopedBack;
	for (i = 0; invocationModes[i].name != NULL; i++) {
		struct invocation *invoked = &invocationModes[i];
		column = 1;
		printWrap("   pcscd ");
		for (j = 0; invoked->optList[j] != 0; j++) {
			int opt = invoked->optList[j];
			bzero(buf, sizeof (buf));
			if (j > 0)
				strcat(buf, "  ");
			else if (opt > 0)
				strcat(buf, "    ");
			if (opt > 0) {
				reqFlag = 0;
				strcat(buf, "[ ");
			} else {
				reqFlag = 1;
				opt = -opt;
			}

			sprintf(arg, "-%c", opt);
			strcat(buf, arg);
			for (k = 0; paramDesc[k].opt != 0; k++) {
			     struct paramDescriptions *pd = &paramDesc[k];
			     if (pd->opt == opt) {
				     if (pd->text != NULL) {
					     strcat(buf, " ");
					     strcat(buf, pd->text);
				     } else if (pd->cfgvar != NULL) {
					     strcat(buf, " {");
					     cp = CFGListConstants(pd->cfgvar);
					     c2 = strtok(cp, ",");
					     loopedBack = 0;
					     while(c2 != NULL) {
						     if (loopedBack)
							 strcat(buf, " | ");
						     strcat(buf, c2);
						     printWrap(buf);
						     c2 = strtok(0, ",");
						     bzero(buf, sizeof (buf));
						     loopedBack = 1;
					     }
					     printWrap("}");
				     }
			     }
			}
			if (!reqFlag)
				strcat(buf, " ]");
			printWrap(buf);
		}
		printWrap("\n\n");
	}

}

void
printWrap(const char *fmt, ...) {
	char buf[LINEMAX], *cp;
	int len;
	va_list ap;

	va_start(ap, fmt);

#ifndef WIN32
	vsnprintf(buf, LINEMAX, fmt, ap);
#else
#if HAVE_VSNPRINTF
	vsnprintf(buf, LINEMAX, fmt, ap);
#else
	vsprintf(buf, fmt, argptr);
#endif
#endif
	va_end(ap);
	if ((cp = strrchr(buf, '\n')) != NULL)
		len = strlen(cp + 1);
	else
		len = strlen(buf);

	column += len;
	if (column > 55) {
		printf("\n           ");
		column = 13;
		if (*buf == ' ' && buf[1] == '|') {
			printf("     ...");
			column += 9;
		}
	}
	printf(buf);
}


