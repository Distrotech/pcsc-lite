/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2005
 *  David Corcoran <corcoran@linuxnet.com>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 */

/**
 * @file
 * @brief This keeps a list of defines shared between the driver and the application
 */

#ifndef __ifd_auth_h__
#define __ifd_auth_h__

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

#ifndef __kvp_definition__
#define __kvp_definition__

#define MAX_KEY_LEN 64

typedef struct kvp_list {
	struct kvp_list *next;
	char *key;
	char *val;
} kvp_t;

#endif //__kvp_definition__

/*
 * Plugin entry points (plugin developer must implement these):
 *
 *  initIfdAuth() 
 *
 *      This function is called by the pcscd daemon with a list of keys as
 *      the argument so the plugin can do self-setup.  The key list is valid
 *      only in the scope of this function, so if the values need to be 
 *      accessed afterwards a local copy or representation must be made.
 *
 *      NOTE: This function can be called more than once. Code accordingly!
 *
 *      Return values: 
 *		SUCCESS  = 1
 *		FAIL	 = 0
 *
 *  isAuthorizedForIfd()
 *
 *      This function determes whether the client is authorized to access
 *      the specific ifd handler.  The display #, as well as the credentials of 
 *      the client are passed in the cred structure.
 *
 *      The resource argument is the AUTHSERVICE argument defined in the
 *      reader configuration file that associated the reader with the 
 *      ifd handler whose access is being authenticated here.
 * 
 *      Return values:
 *              SUCCESS = 1
 *              FAIL    = 0
 */
int init(kvp_t *kvps);
int isAuthorized(PCSCLITE_CRED_T *cred, 
	const char *ifdHandlerName, const void *resource);



/* Convenience functions:
 *
 *  findValueForKey()
 * 
 *       Optionally called by plugin to lookup specified key in a case
 *       insensitive way.  The list of key-value pairs must be passed thru
 *       the kvps argument.  The function returns the corresponding value
 *       if the key is located, otherwise it returns NULL.
 *
 *  isKeyValueTrue()
 *  
 *       Optionally called by plugin to lookup a key and determine
 *       if its corresponding value is one of the following strings:
 *       "TRUE", "true", "YES", "yes", "ON", "on", or "1".
 *
 *       The function returns status 1 (boolean TRUE) if the key is defined 
 *       and the key's value is set to one of the aforemrentioned strings,
 *       otherwise the function returns 0 (boolean FALSE).
 */
char *findValueForKey(const kvp_t *kvps, const char *key);
int isKeyValueTrue(const kvp_t *kvps, const char *key);

#ifdef __cplusplus
extern "C"
}
#endif //__cplusplus

#endif //__ifd_auth_h___
