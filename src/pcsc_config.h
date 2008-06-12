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


#ifndef	__pcsc_config_h__
#define	__pcsc_config_h__

#ifdef __cplusplus
extern "C"
{
#endif

#include <netdb.h>
#include <stdio.h>

/*
 * pcscd global configuration data
 * (Also referred to as the "Global Configuration Block")
 */
extern struct pcsc_cfg_data {
	int  consumer;			// Indicates who's using this data
	int  launchMode;		// Launcher, Instance or Client?
	int  runInForeground;		// Foreground mode state
	int  instanceTimeout;		// Max. instance inactivity in seconds
	int  transportType;		// Client / Instance comm. mode
	int  portNbr;			// Port No, if using TCP/IP
	int  dpyNbr;			// Client display number
	int  screenNbr;			// Client screen number (not used yet)
	in_addr_t xHostIp;		// Client IP address
	int  useMappedMemory;		// Memory mapped mode
	int  portNbrWild;		// Port numbering is wildcard based
	int  baseDirWild;		// Base directory is indexed
	char *baseDir;			// Root base directory
	char *instanceScript;		// Script to invoke when launching inst
	char *pcscConfigFile;		// Master configuration file
	char *validateConf;		// Validation plugin configuration file
	char *readerConfigFile;		// Reader conf file used by us
	char *pcscdMemMappedFile;	// Optional memory-mapped file
	char *pcscdPIDFile;		// PID file
	char *netBindFile;		// UNIX-domain socket file if applicable
	char *ifdPluginDir; 		// Where IFD handlers live
	char *logFile;			// Optional log file path
	char *argv0;			// Name of launched program
	int  apduDebug;			// APDU debugging mode
	int  verbose;			// Debug verbosity level
	int  useAuthentication;		// Are we using authentication?
	char *statusPollRate;		// How fast the daemon polls
	int logLevel;			// Logging level
	int logType;			// Logging type
	int pcscdExiting;		// Set when we receive exit-type signal
	int fifoPingTimeout;		// Time in seconds before ping times out
	int relaunchThreshold;		// Max. number instance relaunch tries
	int relaunchInterval;		// Sets when instance relaunch too fast
} pcscCfg, launcherCfg;

#define AUTHFAIL    "AUTHENTICATION FAILURE"
#define LAUNCHFAIL  "SERVER INSTANCE COULD NOT BE STARTED"
#define CONNECTOK   "CLIENT CONNECTED TO SERVER INSTANCE"

extern FILE *dbgFp;
void dbg(const char *, ...);
#define WINSCARD_CLNT 0
void dbg2(int, const char *, ...);
void d(const char *, ...);

#define DBG0(fmt) \
		(void) Log1(PCSC_LOG_DEBUG, fmt)
#define DBG1(fmt, d1) \
		(void) Log2(PCSC_LOG_DEBUG, fmt, d1)
#define DBG2(fmt, d1, d2) \
		(void) Log3(PCSC_LOG_DEBUG, fmt, d1, d2)
#define DBG3(fmt, d1, d2, d3) \
		(void) Log4(PCSC_LOG_DEBUG, fmt, d1, d2, d3)
#define DBG4(fmt, d1, d2, d3, d4) \
		(void) Log5(PCSC_LOG_DEBUG, fmt, d1, d2, d3, d4)

void CFGperror(int, char *);
char *CFGRetrofitPath(char *, char *);
int   CFGEnsurePathExists(char *);
int   CFGLoadConfigFile( const char *);
int   CFGProcessKvp(const char *, const char *, int);
int   CFGSetArg(const int opt, const char *, const char *, int);
int   CFGParseXdisplay(char *, int *, int *, in_addr_t *);
void  CFGErrChkCritical(int);
void  CFGErrChk(int, int);
void  CFGErrChkMsg(int, int, char *, ...);
char *CFGErrText(int);
void  CFGDefault(const char *, const char *);
int   CFGRmPath(char *);
void  CFGSetConfigConsumer(int);
int   CFGresolveWildcard(void *, void *);
void  CFGdumpCfg(FILE *);
char *CFGSubstitute(char *, char *, char *);
char *CFGListConstants(void *);
void  CFGdumpEventState(int);
void  CFGdumpReaderState(int);
int   CFGDoesFileExist(char *);


/*
 * All constant values used in parsing must be defined
 * as enums or macros
 */
enum llvl        { CRITICAL, ERROR, INFO, DEBUG };
enum ltype       { STDERR, SYSLOG };
enum nopFlag     { NORMAL = 0 };
enum consumer    { DEFAULT = 0, CLIENT, LAUNCHER, INSTANCE };
enum cliser      { SERVER, LIBRARY, MUTUAL };
enum boolean     { FALSE  = 0, TRUE };
enum provider    { USER, ENGINE };
enum wildcard    { X_DISPLAY_NUMBER };
enum visibility  { PARAM = 0, INTERN };
enum wildoffset  { WILD_DECREMENT, WILD_INCREMENT };
enum KVPtypes    { _CONSTANT = 1, _NUMERIC, _STRING, _BOOLEAN, _IPADDR };
enum transports  { SOCKET_UNIX, SOCKET_INETV4 };
enum pathTypes   { PATH_OPTIONAL, PATH_REQUIRED, DIR_PATH_REQUIRED,
		   FILE_PATH_REQUIRED };
enum validations { PARSE_CONST = 1, PARSE_RANGE, PARSE_NUMBER, PARSE_QUOTED,
		   PARSE_WILD, PARSE_PATH };
/*
 * The following Macros are used to initialize the struct array
 * for the tabularized parsing engine.  That struct array is configured
 * below.

 * The macros describe the data types and RHS (Right Hand Side) constraints
 * of different types of key value pairs (KVPs).  At least be one of these
 * Macros (initializers) must be provided for each KVP keyword in the table
 * below, even if it is just the EOL Macro.
 */
#define CONST(C)               { #C, PARSE_CONST,        0,    0,    0,  0, 0, 0, C, 0 }
#define RANGE(low, high)       { "", PARSE_RANGE,        0,  low, high,  0, 0, 0, 0, 0 }
#define INTWILD(typ, tok, trg) { "", PARSE_WILD,  _NUMERIC,  typ, tok, trg, 0, 0, 0, 0 }
#define STRWILD(typ, tok, trg) { "", PARSE_WILD,   _STRING,  typ, tok, trg, 0, 0, 0, 0 }
#define NUMBER(flags)          { "", PARSE_NUMBER,   flags,    0,   0,   0, 0, 0, 0, 0 }
#define QUOTED(flags)          { "", PARSE_QUOTED,   flags,    0,   0,   0, 0, 0, 0, 0 }
#define PATH(flags)            { "", PARSE_PATH,     flags,    0,   0,   0, 0, 0, 0, 0 }
#define EOL                    { "", 0, 0, 0, 0, 0, 0, 0, 0, 1 }

/* TABULARIZED PARSING ENGINE CONTROL TABLE
 *
 * Each of the struct arrays below, for example TRANSPORT[], LAUNCH_MODE[],
 * etc..., represents a valid keyword (L.H.S. of KVP).  The array contains an
 * arbitrary number of initializes, selected from the macros defined above.
 * These array initializers lists (which may otherwise be empty) must always
 * be terminated with the EOL initializer macro.
 *
 * For example if an array TRANSPORT[] is defined and initialized with
 * CONST(SOCKET_UNIX), CONST(SOCKET_INETV4), KVPs "TRANSPORT = SOCKET_UNIX"
 * and "TRANSPORT = SOCKET_INETV4" will be allowed in the main conf file.
 * are allowed in the configuration file.  A corresponding definition entry in
 * the main parsing tables indicates the TRANSPORT value updates the global
 * data struct pcscCfg.transport field (the value is translated according to
 * to the type indicated in the array initiaizer list).
 *
 * When a KVP like "LOG_LEVEL = INFO" is run through the KVP parser, the engine"
 * compares LOG_LEVEL to each key in the key list to find a match.  Each
 * validation step indicated by the list of macro initializers is performed
 * on the value.
 *
 * The most complicated parsing validatio type is wildcarding. For example,
 * for the BASE_DIR key, STRWILD specifies that the substring "$DISPLAY" is
 * the formal arg representing the wildcard portion of the RHS actual argument,
 * syntactically.  If a wildcard argument is found, a corresponding specified
 * flag is set  in the global data struct (pcscCfg).  Wildcard parsing is
 * handled in phases.  For example, at the time the conf file is parsed,
 * we don't know the display the $DISPLAY wildcard placeholder refers to yet,
 * so state is set up to complete the parsing later.
 *
 * Later, when the X Display # becomes known, if pcscCfg.baseDirWild is set,
 * CFGResolveWildcard() is called passing in the display number.  The state
 * tables will be used to determine how to complete the wildcard substittution
 * and where to store the final value.
 */

static struct kvpValidation {
	char *key;     /* Key name of this element */
	int process;   /* Additional validation processing category */
	int option;    /* Processing sub-category */
	void *arg1;    /* Option-dependent input param #1 */
	void *arg2;    /* Option-dependent input param #2 */
	void *arg3;    /* Option-dependent input param #3 */
	void *datum1;  /* Pre-process output parameter 1 */
	void *datum2;  /* Pre-process output parameter 2 */
	int constVal;  /* Value of constant if this defiens one */
	int eolFlag;   /* Set for last elem in list (if set ignore other fields) */

}  TRANSPORT[] = {
	CONST(SOCKET_UNIX),
	CONST(SOCKET_INETV4),
	EOL

}, LAUNCH_MODE[] = {
	CONST(LAUNCHER),
	CONST(INSTANCE),
	CONST(DEFAULT),
	EOL

}, LOG_LEVEL[] = {
	CONST(DEBUG),
	CONST(INFO),
	CONST(ERROR),
	CONST(CRITICAL),
	EOL

}, LOG_TYPE[] = {
	CONST(STDERR),
	CONST(SYSLOG),
	EOL

}, PORT_NUMBER[] = {
	RANGE("0", "65535"),    /* Enforce range limit on port number value */
	INTWILD(X_DISPLAY_NUMBER, "$DISPLAY", &pcscCfg.portNbrWild),
	EOL

}, BASE_DIR[] = {
	PATH(PATH_OPTIONAL),
	STRWILD(X_DISPLAY_NUMBER, "$DISPLAY", &pcscCfg.baseDirWild),
	EOL

}, IFD_PLUGIN_PATH[] = {
	PATH(PATH_OPTIONAL),    /* Can't validate presence during initial parsing  */
	EOL

}, READER_CONFIG_FILE[] = {
	PATH(PATH_OPTIONAL),    /* Can't validate presence during initial parsing */
	EOL

}, MEMORY_MAPPED_FILE[] = {
	PATH(PATH_OPTIONAL),    /* Can't validate presence during initial parsing */
	EOL

}, CONSUMER[] = {
	CONST(LAUNCHER),
	CONST(INSTANCE),
	CONST(DEFAULT),
	CONST(CLIENT),
	EOL

}, BASE_DIR_WILD[]          = { EOL },
   PORT_NUMBER_WILD[]       = { EOL },
   LOG_FILE[]               = { EOL },
   RUN_IN_FOREGROUND[]      = { EOL },
   VERBOSE[] 		    = { EOL },
   PCSCD_CONFIG_FILE[]      = { EOL },
   SCREEN_NUMBER[]          = { EOL },
   DISPLAY_NUMBER[]         = { EOL },
   PCSCD_PID_FILE[]         = { EOL },
   NET_BIND_FILE[]          = { EOL },
   USE_MAPPED_MEMORY[]      = { EOL },
   X_HOST_IP[]              = { EOL },
   USE_AUTHENTICATION[]     = { EOL },
   INSTANCE_TIMEOUT[]       = { EOL },
   HELPER_SCRIPT[]          = { EOL },
   STATUS_POLL_RATE[]       = { EOL },
   APDU_DEBUG[]             = { EOL },
   RELAUNCH_THRESHOLD[]     = { EOL },
   FIFO_PING_TIMEOUT[]      = { EOL },
   RELAUNCH_INTERVAL[]      = { EOL },
   ARGV0[]		    = { EOL };


/*
 * List of valid KVPs, indicating consumer, visibility,
 * validation method and data type for the RHS part.  Also indicates
 * for each KVP, the address at which to store the parsed result for
 * the KVP if the KVP is encountered during configuration processing.
 * These values are all conveniently stored in a global configuation
 * block (ie. a global struct) so that the configuation state can be
 * accessed from anywhere in the code.
 *
 * This table is used to determine the format of the data to
 * display.  The CFGdump() function matches the address of a
 * config block variable in this table to get the type.
 */

#define KVP(key, consumer, visibility, type, result) \
	  { #key, consumer, visibility, type, \
	    (struct kvpValidation *)&key, (void *)result }


static struct kvp {
	char *key;                        /* key name of this KVP */
	int  consumer;                    /* Who can access, client, server or both? */
	int  visibility;                  /* Is this a user or internal-only option? */
	int  type;                        /* What is the resultant data type */
	struct kvpValidation *validation; /* Optional validation processing for val */
	void *result;                     /* Where the parsed result is stored */
} kvps[] = {
	KVP(READER_CONFIG_FILE,     SERVER, PARAM,  _STRING,   &pcscCfg.readerConfigFile),
	KVP(IFD_PLUGIN_PATH,        SERVER, PARAM,  _STRING,   &pcscCfg.ifdPluginDir),
	KVP(APDU_DEBUG,             SERVER, PARAM,  _BOOLEAN,  &pcscCfg.apduDebug),
	KVP(PCSCD_PID_FILE,         SERVER, PARAM,  _STRING,   &pcscCfg.pcscdPIDFile),
	KVP(RUN_IN_FOREGROUND,      SERVER, PARAM,  _BOOLEAN,  &pcscCfg.runInForeground),
	KVP(INSTANCE_TIMEOUT,       SERVER, PARAM,  _NUMERIC,  &pcscCfg.instanceTimeout),
	KVP(PCSCD_CONFIG_FILE,      SERVER, INTERN, _STRING,   &pcscCfg.pcscConfigFile),
	KVP(ARGV0, 		    MUTUAL, INTERN, _STRING,   &pcscCfg.argv0),
	KVP(HELPER_SCRIPT,          SERVER, INTERN, _STRING,   &pcscCfg.instanceScript),
	KVP(STATUS_POLL_RATE,       SERVER, PARAM,  _NUMERIC,  &pcscCfg.statusPollRate),
	KVP(USE_AUTHENTICATION,     SERVER, PARAM,  _BOOLEAN,  &pcscCfg.useAuthentication),
	KVP(LOG_LEVEL,              SERVER, PARAM,  _CONSTANT, &pcscCfg.logLevel),
	KVP(LOG_TYPE,               SERVER, PARAM,  _CONSTANT, &pcscCfg.logType),
	KVP(FIFO_PING_TIMEOUT,      SERVER, PARAM,  _NUMERIC,  &pcscCfg.fifoPingTimeout),
	KVP(RELAUNCH_THRESHOLD,     SERVER, PARAM,  _NUMERIC,  &pcscCfg.relaunchThreshold),
	KVP(RELAUNCH_INTERVAL,      SERVER, PARAM,  _NUMERIC,  &pcscCfg.relaunchInterval),
	KVP(LOG_FILE,               MUTUAL, PARAM,  _STRING,   &pcscCfg.logFile),
	KVP(TRANSPORT,              MUTUAL, PARAM,  _CONSTANT, &pcscCfg.transportType),
	KVP(BASE_DIR_WILD,          MUTUAL, INTERN, _BOOLEAN,  &pcscCfg.baseDirWild),
	KVP(USE_MAPPED_MEMORY,      MUTUAL, PARAM,  _BOOLEAN,  &pcscCfg.useMappedMemory),
	KVP(PORT_NUMBER,            MUTUAL, PARAM,  _NUMERIC,  &pcscCfg.portNbr),
	KVP(PORT_NUMBER_WILD,       MUTUAL, INTERN, _BOOLEAN,  &pcscCfg.portNbrWild),
	KVP(MEMORY_MAPPED_FILE,     MUTUAL, PARAM,  _STRING,   &pcscCfg.pcscdMemMappedFile),
	KVP(X_HOST_IP,              MUTUAL, PARAM,  _IPADDR,   &pcscCfg.xHostIp),
	KVP(DISPLAY_NUMBER,         MUTUAL, PARAM,  _NUMERIC,  &pcscCfg.dpyNbr),
	KVP(SCREEN_NUMBER,          MUTUAL, PARAM,  _NUMERIC,  &pcscCfg.screenNbr),
	KVP(NET_BIND_FILE,          MUTUAL, INTERN, _STRING,   &pcscCfg.netBindFile),
	KVP(CONSUMER,               MUTUAL, INTERN, _CONSTANT, &pcscCfg.consumer),
	KVP(BASE_DIR,               MUTUAL, PARAM,  _STRING,   &pcscCfg.baseDir),
	KVP(LAUNCH_MODE,            MUTUAL, PARAM,  _CONSTANT, &pcscCfg.launchMode),
	KVP(VERBOSE,                MUTUAL, PARAM,  _NUMERIC,  &pcscCfg.verbose),
};


enum CFGerrors {
	CFG_SUCCESS = 0,
	CFG_NULL_POINTER = -3000,
	CFG_OUT_OF_MEMORY,
	CFG_SYNTAX_ERROR,
	CFG_FILE_NOT_FOUND,
	CFG_NON_INTEGER,
	CFG_UNRECOGNIZED_CONSTANT,
	CFG_MISSING_VALUE,
	CFG_BAD_PARAM,
	CFG_DISALLOWED_PARAM,
	CFG_ILLEGAL_OPTION,
	CFG_VALUE_OUT_OF_RANGE,
	CFG_UNRECOGNIZED_KEY,
	CFG_UNTERMINATED_QUOTE,
	CFG_MISSING_DELIMITER,
	CFG_INVALID_PATH,
	CFG_INVALID_FILE_PATH,
	CFG_INVALID_DIR_PATH,
	CFG_FILE_CREATION_ERROR,
	CFG_DIR_CREATION_ERROR,
	CFG_CANNOT_REMOVE_PATH,
	CFG_BAD_DISPLAY_VALUE,
	CFG_UNDEFINED_DISPLAY,
	CFG_TABLE_ERROR,
	CFG_INTERNAL_ERROR,
	CFG_UNDEFINED_PORT,
	CFG_BAD_WILDCARD_OFFSET,
};

#ifdef __cplusplus
extern "C"
}
#endif

#endif

