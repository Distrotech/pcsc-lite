 /*
  * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
  * Use is subject to license terms.
  *
  *  Paul Klissner <paul.klissner@sun.com>
  *  Michael Bender <michael.bender@sun.com>
  */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdarg.h>
#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "debuglog.h"
#include "pcsclite.h"
#include "pcsc_config.h"
#include "sys_generic.h"
#include "pcsclite.h"
#include "config.h"


#define LINEMAX         256
#define KVMAXLEN        128

#ifndef NONULL
#define NONULL(a) (a) ? (a) : "<null>"
#endif

#define USE_SYSTEM_MKDIR

void dbg(const char *, ...);
void cfgitem(FILE *, char *, void *);

int  validateInt(const char *, struct kvpValidation *);
int  validateString(const char *, struct kvpValidation *);
int  processKvp(const char *, const char *, int, int, char *);
static char *retrofitPath(char *, char *, char *);


/*
 * Specifies the consumer of this configuration module
 */
void
CFGSetConfigConsumer(int consumer) {
	pcscCfg.consumer = consumer;
}



/*
 * Load and parse configuration file into global array.
 * If an error occurs, displays brief definitive message
 * which includes filename and line number and aborts
 * the daemon.
 */
int
CFGLoadConfigFile(const char *cfgFile)
{
	FILE *fp = NULL;
	char *cp, line[LINEMAX], temp[LINEMAX];
	char key[KVMAXLEN], val[KVMAXLEN];
	int i, j, rv, lineNbr;

	if ((fp = fopen(cfgFile, "r")) == NULL)
		return CFG_FILE_NOT_FOUND;

	for (lineNbr = 1; fgets(temp, 256, fp) != NULL; ++lineNbr) {

		memset(key,  0, sizeof (key));
		memset(val,  0, sizeof (val));
		memset(line, 0, sizeof(line));

		if ((cp = strchr(temp, '\n')) != NULL)
		    *cp = '\0';

		if (strncmp(temp, "#", 1) == 0)  /* Discard comments */
		       continue;

		if ((cp = strchr(temp, '#')) != NULL) {
		}
		/* Get rid of whitespace and quote marks */
		for (j = 0, i = 0; i < strlen(temp); i++)
			if (temp[i] != ' ' && temp[i] != '\t' && temp[i] != '"')
				line[j++] = temp[i];

		/* Discard empty lines or lines with only whitespace */
		if (j == 0)
			continue;

		/* Find '=' delimiter, error out if missing */
		if ((cp = strchr(line, '=')) == NULL) {
			Log3(PCSC_LOG_CRITICAL,
			     "Missing delimiter in cfg file %s line %d\n",
			     cfgFile, lineNbr);
			fclose(fp);
			return CFG_MISSING_DELIMITER;

		} else
			*cp = '\0';  /* Divide line into two strings */

		/* Extract val */
		if (cp >= line + strlen(line))
			strcpy(val, cp + 1);

		/* Extract key */
		strcpy(key, line);


		/* Parse value into it's respective variable */
		rv = CFGProcessKvp(key, val, USER);
		if (rv != CFG_SUCCESS) {
			Log3(PCSC_LOG_CRITICAL,
			     "Error in cfg file %s line %d\n",
			     cfgFile, lineNbr);
			fclose(fp);
			return rv;
		}
	}
	fclose(fp);
	return CFG_SUCCESS;
}


/*
 * Set command line option in the form of a KVP
 */

int
CFGSetArg(const int opt, const char *key, const char *val,
	  const int provider) {

	if (CFGProcessKvp(key, val, ENGINE) != CFG_SUCCESS)
		Log4(PCSC_LOG_CRITICAL,
		     "Error setting cmdline arg: -%c, %s = %s",
		     opt, NONULL(key), NONULL(val));

       return CFG_SUCCESS;

}

/*
 * Set a default value.  If error, log message and
 * exit daemon.
 */
void
CFGDefault(const char *key, const char *val)
{
	if (CFGProcessKvp(key, val, ENGINE) != CFG_SUCCESS)
		 Log3(PCSC_LOG_CRITICAL,  "Error setting default: %s = %s",
		      NONULL(key), NONULL(val));
}

/*
 * Validate key / value pair according to the grammar rules
 * parsing tables, storing literal or represented value in
 * specified  target storage location.
 */
int
CFGProcessKvp(const char *key, const char *val, const int provider)
{
	int i, j, rv;
	static char env[LINEMAX];

	if (key == NULL)
		return (CFG_NULL_POINTER);
	if (val == NULL)
		return (CFG_NULL_POINTER);

	/*
	 * Allow environment variables to be set from conf file.
	 * Keywords that begin with '$' are assumed to be
	 * environment variables to be set for the process
	 * that is loading the configuration file
	 *
	 * Example:
	 *     $VAR = VAL
	 * Sets the environment variable VAR to equal "VAL".
	 */
	 if (*key == '$') {
		setenv(key + 1, val, 0);
		return CFG_SUCCESS;
	 }
	 for (i = 0; i < sizeof (kvps) / sizeof (struct kvp); i++) {
		if (strcasecmp(kvps[i].key, key) == 0) {
		      /*
		       * Client and server can share the same config
		       * file ... this allows the client to ignore server parameters
		       */
		       if (pcscCfg.consumer == CLIENT &&
			  (kvps[i].consumer != CLIENT &&
			   kvps[i].consumer != MUTUAL)) {
			      return CFG_SUCCESS;
		       }

		      /*
		       * Ensure internal variables cannot be configured
		       * from the command line or config file.
		       */
		      if (kvps[i].visibility == INTERN  && provider == USER)
			      return CFG_DISALLOWED_PARAM;

		      switch(kvps[i].type) {
			/*
			 * Find grammar constant named in value,
			 * substitute in constant's equivalent integer
			 * for storage in target location.
			 */
			 case _CONSTANT: {
			      int *result = kvps[i].result;
			      for (j = 0; !kvps[i].validation[j].eolFlag; j++) {
				  if (strcasecmp(kvps[i].validation[j].key, val) == 0) {
					*result = kvps[i].validation[j].constVal;
					return CFG_SUCCESS;
				  }
			      }
			      return CFG_UNRECOGNIZED_CONSTANT;
			 }
			 /*
			  * Pass value through all range checks specified
			  * in the grammar, storing validated value in
			  * specified target location.
			  */
			 case _NUMERIC: {
			       int v = atoi(val);
			       int *result = kvps[i].result;
			       rv = validateInt(val, kvps[i].validation);
			       if (rv != CFG_SUCCESS)
				       return rv;
			       *result = (int)v;
			       return CFG_SUCCESS;
			 }
			 /*
			  * Validate the value as T/F, TRUE/FALSE, Y/N or
			  * YES/NO and set the result to 1 or 0, accordingly
			  */
			 case _BOOLEAN: {
				 int *result = kvps[i].result;
				 if (strcmp(val, "T") == 0 ||
				     strcmp(val, "TRUE") == 0 ||
				     strcmp(val, "Y") == 0 ||
				     strcmp(val, "YES") == 0) {
					 *result = 1;
					 return CFG_SUCCESS;
				 }
				 if (strcmp(val, "F") == 0 ||
				     strcmp(val, "FALSE") == 0 ||
				     strcmp(val, "N") == 0 ||
				     strcmp(val, "NO") == 0) {
					 *result = 0;
					 return CFG_SUCCESS;
				 }
				 return CFG_UNRECOGNIZED_CONSTANT;
			 }
			 /*
			  *
			  * Duplicate the string, perform optional validation
			  * processing on it and store pointer to new string
			  * in specified result area.
			  */
			 case _STRING: {
			      char **result = kvps[i].result;
			      rv = validateString(
				      (const char *)val, kvps[i].validation);
			      if (rv != CFG_SUCCESS)
				      return rv;
			      *result = strdup(val);
			      return CFG_SUCCESS;
			 }
		      default:
			      return CFG_TABLE_ERROR;
		      }
		}
	}
	return CFG_UNRECOGNIZED_KEY;
}


/*
 * Given an X Display string value in standard $DISPLAY format
 * parse it's components into global configuration array.
 *
 * Return values:
 *      SUCCESS
 *      BAD_DISPLAY_VALUE
 */
int
CFGParseXdisplay(char *display, int *dpyNbr, int *screenNbr, in_addr_t *xHostIp)
{
	int i, len, ipFlag = 0;
	struct hostent *pHostEnt;
	struct in_addr sia;
	char token[MAXHOSTNAMELEN + 1];

	*dpyNbr = -1;
	*screenNbr = -1;
	*xHostIp = -1;

	if (display != NULL)  {
		char *pDot = strrchr(display, '.');
		char *pColon = strchr(display, ':');

		if (pColon == NULL) {
			return CFG_SYNTAX_ERROR;
		} else {
			/*
			 * Extract Display and, if present sub-display numbers
			 */
			if (pDot != NULL && pDot > pColon) {
				len = pDot - pColon - 1;
				strncpy(token, pColon + 1, len);
				token[len] = '\0';

				for (i = 0; i < strlen(token); i++)
					if (!isdigit(token[i]))
						return CFG_BAD_DISPLAY_VALUE;

				for (i = 0; i < strlen(pDot + 1); i++)
					if (!isdigit(*(pDot + i + 1)))
						return CFG_BAD_DISPLAY_VALUE;

				*dpyNbr = atoi(token);
				*screenNbr = atoi(pDot + 1);
			} else {
				for (i = 0; i < strlen(pColon + 1); i++)
					if (!isdigit(*(pColon + i + 1)))
					    return -1;
				*dpyNbr = atoi(pColon + 1);
				*screenNbr = 0;
			}

			if (*dpyNbr < 0 || *dpyNbr > 65535)
				return CFG_BAD_DISPLAY_VALUE;

			if (*screenNbr < 0 || *screenNbr > 65535)
				return CFG_BAD_DISPLAY_VALUE;
			/*
			 * Extract and validate hostname, if any, if none
			 * specified use "localhost"
			 */
			if ((len = pColon - display) == 0) {
				strcpy(token, "localhost");
			} else {
				strncpy(token, display, len);
				token[len] = '\0';
			}
			/*
			 * Try to resolve the IP address
			 *
			 */
			if ((sia.s_addr = inet_addr(token)) == (in_addr_t) -1) {
				if ((pHostEnt = gethostbyname(token)) != NULL) {
				       in_addr_t **iap =
					   (in_addr_t **) pHostEnt->h_addr_list;
				       sia = * (struct in_addr *) *iap;
				       ipFlag = 1;
				}
			} else {
				ipFlag = 1;
			}
			if (!ipFlag)
				return CFG_BAD_DISPLAY_VALUE;
			*xHostIp = sia.s_addr;
		}
		return CFG_SUCCESS;
	}
	return CFG_UNDEFINED_DISPLAY;
}


/*
 * Wraps retrofitPath
 */
char *
CFGRetrofitPath(char *inpath, char *relpath)
{
	return retrofitPath(pcscCfg.baseDir, inpath, relpath);
}

/*
 * Conditionally substitutes another path to the base file indicated by
 * inpath such that it becomes relative to basePath, using the following
 * decision rules:
 *
 *   If basePath == NULL, return inpath unchanged
 *   if inpath starts with "/" return inpath unchanged
 *   If relpath == NULL, return <baspath>/<inpath>
 *   If relpath != NULL, return path = <basepath>/<relpath>/<basename inpath>
 *
 * (Leading and trailing '/' characters on basedir and relpath are optional
 *  and ignored)
 *
 * Side effects:
 *      Caller must free() returned string.
 */

static char *
retrofitPath(char *basePath, char *inpath, char *relpath)
{
	char *cp, *base, *rel, *tmp;
	char newpath[LINEMAX];

	if (basePath == NULL || inpath[0] == '/')
		return inpath;

	if (inpath == NULL || strlen(inpath) < 1 ||
	    strlen(basePath) < 1 || *basePath != '/') {
		return NULL;
	}

	/* Remove leading and trailing '/' characters */
	base = strdup(basePath + strspn(basePath, "/"));

	if (relpath == NULL) {
		tmp = SYS_Dirname(inpath);
		rel  = strdup(tmp + strspn(tmp, "/"));
		free(tmp);
	} else
		rel  = strdup(relpath + strspn(relpath, "/"));

	while ((cp = strrchr(base, '/')) == base + strlen(base) - 1)
		*cp = '\0';

	while ((cp = strrchr(rel, '/')) == rel + strlen(rel) - 1)
		*cp = '\0';

	/* Construct path from prepared components */
	strcpy(newpath, "/");
	strcat(newpath, base);
	strcat(newpath, "/");
	if (rel != NULL && *rel != '.' && *rel != '/') {
		strcat(newpath, rel);
		strcat(newpath, "/");
	}
	strcat(newpath, SYS_Basename(inpath));

	free(base);
	free(rel);
	return (strdup(newpath));
}

int
CFGDoesFileExist(char *path)
{
       struct stat statbuf;
       if (SYS_Stat(path, &statbuf) < 0)
	       return 0;
       return 1;
       }
/*
 * Create any missing directories in the *absolute* path specified.
 * If the path is fully populated with existing
 * directories, or null pointer or empty string is passed
 * this function is effectively a NOP.
 */
int
CFGEnsurePathExists(char *path)
{
#ifdef USE_SYSTEM_MKDIR
	char buf[256];
	sprintf(buf, "mkdir -p %s", path);
	system(buf);
#else
	int mode = S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO;
	char newpath[LINEMAX], *elem = 0, *wrk = 0;
	struct stat statbuf;

	if (path == NULL || strlen(path) == 0)
		return CFG_SUCCESS;

	bzero(newpath, LINEMAX);

	wrk = strdup(path);

	if ((elem = strtok(wrk, "/")) == NULL) {
		free(wrk);
		return;
	}

	do {
		strcat(newpath, "/");
		strcat(newpath, elem);
		if (SYS_Stat(newpath, &statbuf) < 0) {
			switch(errno) {
			case ENOENT:
				if (SYS_Mkdir(newpath, mode) < 0) {
					free(wrk);
					return CFG_DIR_CREATION_ERROR;
				}
				break;
			default:
				free(wrk);
				return CFG_DIR_CREATION_ERROR;
			}
		}
		elem = strtok(NULL, "/");
	} while (elem != NULL);

	free(wrk);
#endif
	return CFG_SUCCESS;
}

/*
 * Remove path
 */
int
CFGRmPath(char *path) {
	if (path != NULL)
		if (SYS_Unlink(path) != 0)
			return CFG_CANNOT_REMOVE_PATH;
	return CFG_SUCCESS;
}


/*
 * Do dynamic substring replacement.
 */
char *
CFGSubstitute(char *src, char *tag, char *repl) {
	char buf[256];
	char *cp;
	bzero(buf, sizeof (buf));
	strcpy(buf, src);
	if (repl == NULL || (cp = strstr(buf, tag)) == NULL)
		return (src);
	*cp = '\0';
	strcat(buf, repl);
	cp = strstr(src, tag) + strlen(tag);
	strcat(buf, cp);
	return (strdup(buf));
}
/*
 * Passed the address of a wildcarded configuration target variable,
 * and value to replace wildcard with, update variable's wildcarded
 * portion of contents with replacement value
 */
int
CFGresolveWildcard(void *kvpTargAddr, void *v) {
	int i, j;
	char wrk[LINEMAX];
	bzero(wrk, LINEMAX);
	for (i = 0; i < sizeof (kvps) / sizeof (struct kvp); i++) {
	    struct kvpValidation *validation;
	    struct kvpValidation *validationList = kvps[i].validation;
	    if (kvps[i].result == kvpTargAddr) {
		    for (j = 0; !validationList[j].eolFlag; j++) {
			 validation = &validationList[j];
			 if (validation->process == PARSE_WILD) {
				 switch(validation->option) {
				 case _NUMERIC: {
				      int  *result = (int *)kvpTargAddr;
				      switch((int)validation->datum1) {
				      case WILD_INCREMENT:
					      *result += (int)v;
					      break;
				      case WILD_DECREMENT:
					      *result -= (int)v;
					      break;
				      }
				      return CFG_SUCCESS;
				    }
				 case _STRING: {
				      char **result = (char **)kvpTargAddr;
				      int offset  = (int)validation->datum1;
				      int wildlen = (int)validation->datum2;
				      char *sfxcp= *result + offset + wildlen;
				      strncpy(wrk, *result, offset);
				      strcat(wrk, (char *)v);
				      strcat(wrk, sfxcp);
				      *result = strdup(wrk);
				      return CFG_SUCCESS;
				    }
				 }
			 }
		    }
		    return CFG_TABLE_ERROR;
	    }
	}
	return CFG_TABLE_ERROR;
}

/*
 * Apply further validation checking/processing to the value
 * based on validation options in parsing definition tables.
 */
int
validateInt(const char *val, struct kvpValidation *validationList) {
	struct kvpValidation *validation;
	int j;
	for (j = 0; !validationList[j].eolFlag; j++) {
		validation = &validationList[j];
		switch(validation->process) {
		/*
		 * Pre-process wildcard by locating token, and if present
		 * require that a + or - be located to indicate if the
		 * value substuted for the token is ultimately added
		 * or subtracted from the original int.
		 * It is not an error if the specified token isn't found in
		 * the R.H.S. of the KVP (passed in as val), since the
		 * validation list only indicates wildcarding is an option.
		 */
		case PARSE_WILD: {
			char *tok = (char *)validation->arg2;
			int *flg = (int *)validation->arg3;
			if (strstr(val, tok) == NULL) /* allowed, not req'd */
				return CFG_SUCCESS;
			if (strchr(val, '+') != 0)
				validation->datum1 = (void *)WILD_INCREMENT;
			else if (strchr(val, '-') != 0)
				validation->datum1 = (void *)WILD_DECREMENT;
			else
				return CFG_BAD_WILDCARD_OFFSET;
			*flg = TRUE;
			break;
		  }
		 case PARSE_RANGE: {
			int v  = atoi(val);
			int lo = atoi((char *)validation->arg1);
			int hi = atoi((char *)validation->arg2);
			if (v >= lo && v <= hi)
				break;
			return CFG_VALUE_OUT_OF_RANGE;
		  }
		 default:
			return CFG_TABLE_ERROR;
		 }
	}
	return CFG_SUCCESS;
}

/*
 * Apply further validation checking/processing to the value
 * based on validation options in parsing definition tables.
 */
int
validateString(const char *val, struct kvpValidation *validationList)
{
	struct kvpValidation *validation;
	struct stat statBuf;
	int j;

	for (j = 0; !validationList[j].eolFlag; j++) {

		validation = &validationList[j];

		switch(validation->process) {
		/*
		 * Pre-process wildcard by locating token, such as %X in
		 * string argument, and save addr and loc of token for later
		 * when token substitution occurs. It is not an error if the
		 * specified token isn't found in the R.H.S. of the KVP
		 * (passed in as val), since the validation list only indicates
		 * wildcarding is an option.
		 */
		case PARSE_WILD: {
			char *cp, *tok = (char *)validation->arg2;
			int *flg = (int *)validation->arg3;
			if ((cp = strstr(val, tok)) == NULL) /* Allowed not req'd */
				return CFG_SUCCESS;
			validation->datum1 = (void *)(cp - val); /* Stash offset */
			validation->datum2 = (void *)strlen(tok); /* and length  */
			*flg = TRUE;
			return CFG_SUCCESS;
		   }
		case PARSE_PATH:
			  switch(validation->option) {
			  case PATH_OPTIONAL:
				  break;

			  case PATH_REQUIRED:
				  return SYS_Stat((char *)val, &statBuf) < 0 ?
				       CFG_INVALID_PATH : CFG_SUCCESS;

			  case DIR_PATH_REQUIRED:
				  return (SYS_Stat((char *)val, &statBuf) < 0 ||
				      !(statBuf.st_mode & S_IFDIR)) ?
				       CFG_INVALID_DIR_PATH : CFG_SUCCESS;

			  case FILE_PATH_REQUIRED:
				  return (SYS_Stat((char *)val, &statBuf) < 0 ||
				      (statBuf.st_mode & S_IFDIR)) ?
				       CFG_INVALID_FILE_PATH : CFG_SUCCESS;

			  }
			  break;
		}
	}
	return CFG_SUCCESS;
}

void
CFGperror(int errCode, char *msg) {
	static char buf[256];
	sprintf(buf, "%s: %s", msg, CFGErrText(errCode));
	Log2(PCSC_LOG_ERROR, "%s", buf);
}
/*
 * Check errCode. If no err is detected, do nothing,
 * otherwise, log error along with file name and line #
 */
char *
CFGErrText(int errCode)
{
	switch(errCode) {
	case CFG_SUCCESS:
		return "SUCCESS";

	case CFG_SYNTAX_ERROR:
		return "SYNTAX ERROR";

	case CFG_UNRECOGNIZED_CONSTANT:
		return "UNRECOCNIZED CONSTANT";

	case CFG_TABLE_ERROR:
		return "BAD INTERNAL CFG TABLES ";

	case CFG_INTERNAL_ERROR:
		return "INTERNAL ERROR";

	case CFG_VALUE_OUT_OF_RANGE:
		return "VALUE OUT OF RANGE";

	case CFG_UNRECOGNIZED_KEY:
		return "UNRECOGNIZED KEY";

	case CFG_UNTERMINATED_QUOTE:
		return "UNTERMINATED QUOTE";

	case CFG_MISSING_DELIMITER:
		return "MISSING DELIMITER";

	case CFG_NON_INTEGER:
		return "NON-INTEGER";

	case CFG_OUT_OF_MEMORY:
		return "OUT OF MEMORY";

	case CFG_INVALID_PATH:
		return "NON-EXISTANT/INACCESSIBLE PATH";

	case CFG_INVALID_DIR_PATH:
		return "NON-EXISTANT/INACCESSIBLE PATH, OR NOT DIRECTORY";

	case CFG_INVALID_FILE_PATH:
		return "NON-EXISTANT/INACCESSIBLE PATH, OR IS DIRECTORY";

	case CFG_FILE_NOT_FOUND:
		return "CANNOT OPEN FILE";

	case CFG_FILE_CREATION_ERROR:
		return "CANNOT CREATE FILE";

	case CFG_DIR_CREATION_ERROR:
		return "CANNOT CREATE DIR";

	case CFG_CANNOT_REMOVE_PATH:
		return "CANNOT REMOVE PATH";

	case CFG_BAD_DISPLAY_VALUE:
		return "ILLEGAL X DISPLAY VALUE";

	case CFG_UNDEFINED_DISPLAY:
		return "X DISPLAY UNDEFINED";

	case CFG_NULL_POINTER:
		return "NULL POINTER";

	case CFG_ILLEGAL_OPTION:
		return "ILLEGAL OPTION OR OPTION COMBINATION";

	case CFG_UNDEFINED_PORT:
		return "PORT NUMBER UNDEFINED";

	case CFG_BAD_WILDCARD_OFFSET:
		return "BAD NUMERIC WILDCARD OFFSET (+ or - req'd)";

	case CFG_DISALLOWED_PARAM:
		return "DISALLOWED PARAMEMTER";
	}
	return "UNKNOWN ERROR";
}

/*
 * Do formatted dump of the global configuration struct
 * and it's elements.
 */
void
CFGdumpCfg(FILE *fp) {
	cfgitem(fp, "launchMode............ ", &pcscCfg.launchMode);
	cfgitem(fp, "logLevel ............. ", &pcscCfg.logLevel);
	cfgitem(fp, "logType .............. ", &pcscCfg.logType);
	cfgitem(fp, "logFile .............. ", &pcscCfg.logFile);
	cfgitem(fp, "baseDir .............. ", &pcscCfg.baseDir);
	cfgitem(fp, "instanceScript........ ", &pcscCfg.instanceScript);
	cfgitem(fp, "ifdPluginDir ......... ", &pcscCfg.ifdPluginDir);
	cfgitem(fp, "pcscdPIDFile ......... ", &pcscCfg.pcscdPIDFile);
	cfgitem(fp, "pcscConfigFile........ ", &pcscCfg.pcscConfigFile);
	cfgitem(fp, "readerConfigFile...... ", &pcscCfg.readerConfigFile);
	cfgitem(fp, "netBindFile .......... ", &pcscCfg.netBindFile);
	cfgitem(fp, "pcscdMemMappedFile.... ", &pcscCfg.pcscdMemMappedFile);
	cfgitem(fp, "argv0 ................ ", &pcscCfg.argv0);
	cfgitem(fp, "transportType ........ ", &pcscCfg.transportType);
	cfgitem(fp, "portNbr .............. ", &pcscCfg.portNbr);
	cfgitem(fp, "dpyNbr ............... ", &pcscCfg.dpyNbr);
	cfgitem(fp, "screenNbr ............ ", &pcscCfg.screenNbr);
	cfgitem(fp, "xHostIp .............. ", &pcscCfg.xHostIp);
	cfgitem(fp, "useMappedMemory....... ", &pcscCfg.useMappedMemory);
	cfgitem(fp, "runInForeground ...... ", &pcscCfg.runInForeground);
	cfgitem(fp, "apduDebug ............ ", &pcscCfg.apduDebug);
	cfgitem(fp, "verbose .............. ", &pcscCfg.verbose);
	cfgitem(fp, "portNbrWild .......... ", &pcscCfg.portNbrWild);
	cfgitem(fp, "baseDirWild .......... ", &pcscCfg.baseDirWild);
	cfgitem(fp, "useAuthentication..... ", &pcscCfg.useAuthentication);
	cfgitem(fp, "instanceTimeout ...... ", &pcscCfg.instanceTimeout);
	cfgitem(fp, "statusPollRate ....... ", &pcscCfg.statusPollRate);
	cfgitem(fp, "fifoPingTimeout ...... ", &pcscCfg.fifoPingTimeout);
	cfgitem(fp, "relaunchThreshold .... ", &pcscCfg.relaunchThreshold);
	cfgitem(fp, "relaunchInterval ..... ", &pcscCfg.relaunchInterval);
}

/*
 * Given the address of a variable in the global configuration
 * array, represent it's value optimally according to the type of parameter
 */
void
cfgitem(FILE *fp, char *desc, void *v) {
	static char buf[256];
	int i, j;

	bzero(buf, sizeof (buf));

	if (desc == NULL || v == NULL) {
		if (fp == NULL)
			Log1(PCSC_LOG_DEBUG, "");
		else
			fprintf(fp, "\n");
		return;
	}

	for (i = 0; i < sizeof (kvps) / sizeof (struct kvp); i++) {
		struct kvpValidation *validated = kvps[i].validation;
		if (kvps[i].result == v) {
			if (pcscCfg.consumer == CLIENT) {
				if (kvps[i].consumer != CLIENT &&
				    kvps[i].consumer != MUTUAL)
					return;
			}
			switch(kvps[i].type) {
			case _CONSTANT:
				for (j = 0; !validated[j].eolFlag; j++)
					if (validated[j].constVal == *(int *)v)
					     sprintf(buf, "%s%s",
						  desc, validated[j].key);
				break;
			case _BOOLEAN:
				sprintf(buf, "%s%s",
				     desc, *(int *)v ? "TRUE" : "FALSE");
				break;
			case _NUMERIC:
				sprintf(buf, "%s%d", desc, *(int *)v);
				break;
			case _STRING:
				sprintf(buf, "%s%s", desc, NONULL(*(char **)v));
				break;
			case _IPADDR:
				sprintf(buf, "%s%s",
				    desc, inet_ntoa(*(struct in_addr *)v));
				break;
			default:
				sprintf(buf, "BAD TYPE: %s", desc);
				break;
			}
			if (fp == NULL)
				Log2(PCSC_LOG_DEBUG, "%s", buf);
			else
				fprintf(fp, "%s\n", buf);
			return;
		}
	}
}


/*
 * Given the address of a variable in the global configuration
 * array, represent it's value optimally according to the type of parameter
 */
char *
CFGListConstants(void *v)
{
	static char buf[LINEMAX];

	int i, j;

	if (v == NULL)
		return "";

	bzero(buf, sizeof (buf));

	for (i = 0; i < sizeof (kvps) / sizeof (struct kvp); i++) {
		struct kvpValidation *validated = kvps[i].validation;
		if (kvps[i].result == v) {
			switch(kvps[i].type) {
			case _CONSTANT:
				for (j = 0; !validated[j].eolFlag; j++) {
					if (j > 0)
						strcat(buf, ",");
					strcat(buf, validated[j].key);
				}
				break;
			case _BOOLEAN:
				strcat(buf, "TRUE,FALSE");
				break;
			}

		}
	}
	return strdup(buf);
}


