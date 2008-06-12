#include "pcsclite.h"
#include "clientcred.h"
#include "ifd-auth.h"
#include "debuglog.h"

int dbgFlag = 0;
int allowRootAlways = 0;

/*
 * 
 * This function initializes this ifd handler authentication plugin, and 
 * recognizes the following two KVP keys (each set to true or false):
 *
 *      DEBUG:		If true debug logging is enabled.
 *
 *      ALLOW_ROOT:	If true, root is automatically authorized to access
 *                      the ifd handler bypassing the normal authentication
 *                      steps.
 */
int
init(kvp_t *kvps) {
	dbgFlag = isKeyValueTrue(kvps, "debug");
	allowRootAlways = isKeyValueTrue(kvps, "allow_root");

	if (dbgFlag) {
		Log2(PCSC_LOG_DEBUG, "initDaemonAuth(): debug = %d", dbgFlag);
		Log2(PCSC_LOG_DEBUG, "initDaemonAuth(): allow_root = %d", dbgFlag);
	}
	return 1;
}

/*
 * Functionality is T.B.D.  Currently access is always granted to all 
 * readers on the console.
 */
int
isAuthorized(PCSCLITE_CRED_T *cred, 
    const char *ifdHandlerName, const void *resource) {

	if (dbgFlag)
		Log4(PCSC_LOG_DEBUG, "isAuthorizedForIfd():"
		       "euid:%d, dpy:%d, ifd:%s", 
		        cred->euid, cred->dpyNbr, ifdHandlerName);
	
	return 1;
}
