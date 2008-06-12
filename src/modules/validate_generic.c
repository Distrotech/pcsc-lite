#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include "pcsclite.h"
#include "pcscd-validate.h"
#include "debuglog.h"
#define LINEMAX 256

static char *lookupTag(int, char **, void **);
static char *xservers_file;
static void *resource;
static int dbgFlag = 0;
static int startDpyNbr = -1;
static int endDpyNbr = -1;
static int alwaysInvalidate = 0;
static int rangeCheck = 0;


/*
 * Usage:
 *
 * -s <dpy#>	Specifies starting display # of the recognized range.
 *              If -s is specified, -e must also be specified.
 *
 * -e <dpy#>    Specified the ending display # of the range.
 *              If -e is specified, -s must also be specified.
 *
 * -n           If specified the plugin always returns NULL when
 *              getDisplayTag() or getDisplayResource() are called.
 *              (ie. invalidates all access to the display)
 *
 * -d           Switches on debug logging.
 *
 */
int
initValidate(int argc, char **argv) {

	int i, c;
	while ((c = getopt(argc, argv, ":x:s:e:nd")) != -1) {
		switch(c) {
		case 's':
			rangeCheck = 1;
			startDpyNbr = atoi(optarg);
			break;
		case 'e':
			rangeCheck = 1;
			endDpyNbr = atoi(optarg);
			break;
		case 'n':
			alwaysInvalidate = 1;
			break;
		case 'd':
			dbgFlag = 1;
			break;
		case 'x':
			xservers_file = optarg;
			break;
		default:
		case '?':
			Log1(PCSC_LOG_DEBUG,
			       "bad flag passed.  valid options are:\n"
			       "-s <startdpy#> -e <enddpy#> -d -n\n"
			       "-d = debug, -n = always invalidate\n");
			return 0;
		}
	}

	if (rangeCheck & (startDpyNbr < 0 || endDpyNbr < 0)) {
		Log1(PCSC_LOG_ERROR,
			"-s can only be specified with -e option & vice versa");
		return 0;
	}

	if (dbgFlag) {
		Log1(PCSC_LOG_DEBUG, "initValidate() called with args:");
		for (i = 0; i < argc; i++)
			Log3(PCSC_LOG_DEBUG, "   argv[%d] = %s", i, argv[i]);
	}
	return 1;
}

/*
 * This function looks up the display # in the Xservers file.  If it is
 * defined, the corresponding display tag name is returned.
 */
char *
getDisplayTag(int dpyNbr, char **facilityTag)
{
	void *resource;
	if (dbgFlag)
		Log2(PCSC_LOG_DEBUG, "getDisplayTag(%d) called", dpyNbr);
	if (alwaysInvalidate)
		*facilityTag = NULL;
	else
		lookupTag(dpyNbr, facilityTag, &resource);
	return *facilityTag;
}


/*
 * This function retured the resource defined for the display.  For this
 * plugin the exact text of the line that defined the display in the Xservers
 * file is returned.
 */
void *
getDisplayResource(int dpyNbr, void **resource)
{
	char *facilityTag = NULL;
	if (dbgFlag)
		Log2(PCSC_LOG_DEBUG,"getDisplayResource(%d) called", dpyNbr);
	if (alwaysInvalidate)
		*resource = NULL;
	else
		lookupTag(dpyNbr, &facilityTag, resource);
	return *resource;
}

int
getDisplayStatus(int dpyNbr, unsigned int *flags)
{
	char *facilityTag;
	if (getDisplayTag(dpyNbr, &facilityTag) == NULL)
		return DISPLAY_NOT_VALID;
	free(facilityTag);
	*flags = 0;
	return DISPLAY_IS_VALID;
}


static char *
lookupTag(int dpyNbr, char **facilityTag, void **resource) {
	int i;
	char readbuf[LINEMAX];
	char chkTag[10];
	char *cp1, *cp2;
	char *xServerTag = NULL;
	FILE *fp;

	if (rangeCheck && (dpyNbr < startDpyNbr || dpyNbr > endDpyNbr)) {
		Log4(PCSC_LOG_ERROR,
			"lookupTag(): Failed display range check :%d (%d,%d)",
			dpyNbr, startDpyNbr, endDpyNbr);
		goto err_exit;
	}

	/*
	 * Attempt to open Xservers file.  If it wasn't specified as an argument
	 * to the plugin, use the one specified at build time (ie. the default
	 * for the platform).  The plugin gives the administrator the ability
	 * to override the default Xservers placement for the architecture.
	 *
	 * Since this is the generic module, we don't return an error,
	 * but instead return the tag "Local", if the XServers file can't be
	 * accessed in the specified location, because it might be a system
	 * where X hasn't been installed, but access to the Smart Card reader is
	 * still required.
	 */
	if (xservers_file == NULL)
		xservers_file = XSERVERS_FILE;
	if ((fp = fopen(xservers_file, "r")) == NULL) {
		Log4(PCSC_LOG_DEBUG,
		    "Can't open Xservers file %s: errno:%d = %s",
		     xservers_file, errno, strerror(errno));
		*facilityTag = strdup("Local");
		*resource = strdup("");
		return *facilityTag;
	}

	/*
	 * Look up display tag name in Xservers file
	 */
	if (resource != NULL)
		*resource = NULL;
	xServerTag = NULL;
	sprintf(chkTag, ":%d", dpyNbr);
	while (fgets(cp1 = readbuf, LINEMAX, fp) != NULL) {
		while (*cp1 == ' ' || *cp1 == '\t')
			++cp1;
		if (strncmp(cp1, chkTag, strlen (chkTag)) == 0 &&
		    (cp1[strlen(chkTag)] == ' ' ||
		     cp1[strlen(chkTag)] == '\t')) {
			cp1 += strlen(chkTag);
			cp1 += strspn(cp1, " \t");
			cp2 = cp1;
			while(*cp2 != '\0' && *cp2 != ' ' && *cp2 != '\t')
			     cp2++;
			*cp2 = '\0';
			fclose(fp);
			if (resource != NULL) {
				if (dbgFlag)
					Log2(PCSC_LOG_DEBUG,
						"display resource: %s\n",
						(char *)readbuf);
				*resource = strdup(readbuf);
			}
			if (dbgFlag)
				Log3(PCSC_LOG_DEBUG,
					"Tag \"%s\" located for dpy :%d",
					cp1, dpyNbr);
			if (facilityTag) {
				*facilityTag = strdup(cp1);
				return *facilityTag;
			}
			goto err_exit;
		}
	}
	fclose(fp);

err_exit:
	if (facilityTag)
		*facilityTag = NULL;
	return NULL;
}

