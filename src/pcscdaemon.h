/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *  Paul Klissner <paul.klissner@sun.com>
 *  Michael Bender <michael.bender@sun.com>
 *
 * <NEED TO FIX KEYWORDS>
 */


#ifndef	__pcscdaemon_h__
#define	__pcscdaemon_h__

#ifdef __cplusplus
extern "C"
{
#endif

#include "pcsc_config.h"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define NONULL(a) (a) ? (a) : ""
#define LINEMAX 256

#ifdef HAVE_GETOPT_LONG
#  define GETOPT(argc, argv, args, longopts, optindex) \
		getopt_long (argc, argv, args, longopts, &optindex)
#else
#  define GETOPT(argc, argv, args, longopts, optidx) \
		getopt(argc, argv, args)
#endif


void SVCServiceRunLoop(void);
void SVCClientCleanup();
void at_exit(void);
void CleanTempFiles(void);
void signal_reload(int sig);
void signal_trap(int);
void print_version (void);
void print_usage (char const * const);
void Launcher(int);
void ChkVersion();
void CFGSetupLogging();
void CFGStdOutErr(char *);
int  DoRunCheck();
void Daemonize();
void ListInvocationModes();
int  ChkArg(int, char *);
char *FmtValue(int opt, char *val);


/*
 * Command line options
 */

#define OPT_READERCFG  'r'
#define OPT_FOREGROUND 'f'
#define OPT_HELP       '?'
#define OPT_VERSION    'v'
#define OPT_APDU       'a'
#define OPT_LOGLEVEL   'd'
#define OPT_BASEDIR    'b'
#define OPT_IFDLIBDIR  'i'
#define OPT_PORT       'p'
#define OPT_DISPLAY    'x'
#define OPT_TRANSPORT  't'
#define OPT_CONFIG     'c'
#define OPT_USEAUTH    'A'
#define OPT_STOPINST   'k'
#define OPT_TIMEOUT    'T'
#define OPT_INSTANCE   'I'
#define OPT_LAUNCHER   'L'
#define OPT_MAPFILE    'm'
#define OPT_USEMAPPED  'M'
#define OPT_LOGFILE    'o'
#define OPT_LOGTYPE    'l'
#define OPT_VERBOSE    'V'
#define OPT_LAUNCHTHR  'R'
#define OPT_LAUNCHINT  'N'
#define OPT_FIFOTIME   'F'
#define OPT_PID	       'P'


/*
 * The struct defined by getopt_long() is also use
 * for automating building the valid argument
 * list and automating our usage function, so
 * if it isn't defined, we'll define it.
 */
#ifndef HAVE_GETOPT_LONG
struct option {
	char *name;
	int has_arg;
	int *flag;
	int val;

};
#endif

int optIndex = 0;
static struct option longOpts[] = {
    { "help",       0, 0, OPT_HELP       },
    { "version",    0, 0, OPT_VERSION    },
    { "foreground", 0, 0, OPT_FOREGROUND },
    { "apdu",       0, 0, OPT_APDU       },
    { "launcher",   0, 0, OPT_LAUNCHER   },
    { "instance",   0, 0, OPT_INSTANCE   },
    { "stop",       0, 0, OPT_STOPINST   },
    { "verbose",    0, 0, OPT_VERBOSE    },
    { "useauth",    0, 0, OPT_USEAUTH    },
    { "usemap",     0, 0, OPT_USEMAPPED  },
    { "loglevel",   1, 0, OPT_LOGLEVEL   },
    { "logtype",    1, 0, OPT_LOGTYPE    },
    { "logfile",    1, 0, OPT_LOGFILE    },
    { "reader",     1, 0, OPT_READERCFG  },
    { "basedir",    1, 0, OPT_BASEDIR    },
    { "ifd",        1, 0, OPT_IFDLIBDIR  },
    { "port",       1, 0, OPT_PORT       },
    { "display",    1, 0, OPT_DISPLAY    },
    { "transport",  1, 0, OPT_TRANSPORT  },
    { "config",     1, 0, OPT_CONFIG     },
    { "timeout",    1, 0, OPT_TIMEOUT    },
    { "mapfile",    1, 0, OPT_MAPFILE    },
    { "launchint",  1, 0, OPT_LAUNCHTHR  },
    { "launchthr",  1, 0, OPT_LAUNCHINT  },
    { "fifotime",   1, 0, OPT_FIFOTIME   },
    { "pid",        1, 0, OPT_PID        },
    { 0, 0, 0, 0}
};

struct {
	int opt;
	char *usage;
} usageMsgs[] = {
    { OPT_LAUNCHER,   "Run in launcher mode"                              },
    { OPT_INSTANCE,   "Run as instance (mode is used by launcher)"        },
    { OPT_STOPINST,   "Terminate instance handling specified display"     },
    { OPT_PID,        "PID of instance to stop"                           },
    { OPT_CONFIG,     "Specify hierarchical server config file location"  },
    { OPT_BASEDIR,    "Specify hierarchical server base dir location"     },
    { OPT_READERCFG,  "Specify abs. or relative reader conf. location"    },
    { OPT_FOREGROUND, "Run in foreground (no daemon)"                     },
    { OPT_IFDLIBDIR,  "Specify abs. or rel. IFD handler plugin path"      },
    { OPT_DISPLAY,    "X display that owns reader(s) of interest"         },
    { OPT_TRANSPORT,  "Specify IPC comm. transport type"                  },
    { OPT_PORT,       "Specify INETV4 port number to use"                 },
    { OPT_TIMEOUT,    "Specify Instance timeout"                          },
    { OPT_USEAUTH,    "Enable authentication"                             },
    { OPT_MAPFILE,    "Specify memory map file name"                      },
    { OPT_USEMAPPED,  "Enable memory-mapped reader state conveyance"      },
    { OPT_LOGLEVEL,   "Set logging minimum severity level"                },
    { OPT_LOGTYPE,    "Specify facility to send logging output to"        },
    { OPT_LOGFILE,    "Specify target of stderr"                          },
    { OPT_APDU,       "Log APDU commands and results"                     },
    { OPT_VERBOSE,    "Debug verbosity level"                             },
    { OPT_LAUNCHINT,  "Launched instance min time req. to assume success" },
    { OPT_LAUNCHTHR,  "Instance, max. allowed failed launches + retries"  },
    { OPT_FIFOTIME,   "Number of seconds to time out on fifo ping"    },
    { OPT_VERSION,    "Display the program version number"                },
    { OPT_HELP,       "Display usage information"                         },
    { 0, 0 }
};

struct paramDescriptions {
	int opt;
	char *text;
	void *cfgvar;
} paramDesc[] = {
    { OPT_LAUNCHER,   0,                    0 },
    { OPT_INSTANCE,   0,                    0 },
    { OPT_STOPINST,   0,                    0 },
    { OPT_BASEDIR,    "basedir",            0 },
    { OPT_IFDLIBDIR,  "ifd_plugin_dir",     0 },
    { OPT_CONFIG,     "config_file_path",   0 },
    { OPT_READERCFG,  "reader_config_path", 0 },
    { OPT_MAPFILE,    "mapfile_path",       0 },
    { OPT_LOGFILE,    "logfile",            0 },
    { OPT_TIMEOUT,    "timeout_seconds",    0 },
    { OPT_PORT,       "port_number",        0 },
    { OPT_DISPLAY,    ":display_number",    0 },
    { OPT_LAUNCHINT,  "time_secs",          0 },
    { OPT_LAUNCHTHR,  "time_secs",          0 },
    { OPT_FIFOTIME,   "timeout_secs",       0 },
    { OPT_PID,        "pid",                0 },
    { OPT_FOREGROUND, 0,                    0 },
    { OPT_USEAUTH,    0,                    0 },
    { OPT_USEMAPPED,  0,                    0 },
    { OPT_APDU,       0,                    0 },
    { OPT_VERSION,    0,                    0 },
    { OPT_VERBOSE,    0,                    0 },
    { OPT_HELP,       0,                    0 },
    { OPT_TRANSPORT,  0,                    &pcscCfg.transportType },
    { OPT_LOGTYPE,    0,                    &pcscCfg.logType },
    { OPT_LOGLEVEL,   0,                    &pcscCfg.logLevel },
    { 0, 0 }
};


/*
 * Describes valid combinations of options for various
 * invocation modes.  Required options for a mode should
 * be prefixed with '-' (ie. negated)
 */
#define MAXOPTS 32
struct invocation {
	char *name;
	int optList[MAXOPTS];
} invocationModes[] = {
	{
	  "Help on Usage",
		{ -OPT_HELP, 0  }

	}, {

	  "Display Version",
		{ -OPT_VERSION, 0  }
	}, {

	  "Stop Instance",
		{ -OPT_STOPINST, -OPT_DISPLAY, OPT_PID, 0 }
	}, {

	  "Launcher Mode",
		{
		  -OPT_LAUNCHER, OPT_CONFIG, OPT_BASEDIR, OPT_MAPFILE,
		   OPT_LOGFILE, OPT_USEAUTH, OPT_PORT, OPT_TRANSPORT,
		   OPT_FOREGROUND, OPT_USEMAPPED, OPT_LOGTYPE,
		   OPT_LOGLEVEL, OPT_APDU, OPT_LAUNCHINT, OPT_LAUNCHTHR,
		   OPT_FIFOTIME, OPT_VERBOSE, 0
		}
	}, {

	  "Instance Mode",
		{
		  -OPT_INSTANCE, OPT_DISPLAY, OPT_CONFIG, OPT_BASEDIR,
		   OPT_MAPFILE, OPT_IFDLIBDIR, OPT_READERCFG,
		   OPT_LOGFILE, OPT_USEAUTH, OPT_PORT, OPT_TRANSPORT,
		   OPT_FOREGROUND, OPT_USEMAPPED, OPT_LOGTYPE,
		   OPT_LOGLEVEL, OPT_APDU, OPT_VERBOSE, 0
		}
	}, {

	  "Server Mode",
		{
		   OPT_CONFIG, OPT_BASEDIR, OPT_MAPFILE,
		   OPT_IFDLIBDIR, OPT_READERCFG,
		   OPT_LOGFILE, OPT_USEAUTH, OPT_PORT, OPT_TRANSPORT,
		   OPT_FOREGROUND, OPT_USEMAPPED, OPT_LOGTYPE,
		   OPT_LOGLEVEL, OPT_APDU, OPT_VERBOSE, 0
		}
	},
	{ 0, 0 }
};


#ifdef __cplusplus
extern "C"
}
#endif

#endif
