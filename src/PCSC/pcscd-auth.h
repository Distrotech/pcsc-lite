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

#ifndef __pcscd_auth_h__
#define __pcscd_auth_h__

#ifdef __cplusplus
extern "C"
{
#endif

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
 *  init(kvp_t *kvps) 
 *
 *      This function is called by the pcscd daemon with a list of keys as
 *      the argument so the plugin can do self-setup.  The key list is valid
 *      only in the scope of this function, so if the values need to be 
 *      accessed afterwards a local copy or representation must be made.
 *
 *      NOTE: This function can be called more than once. Code accordingly!
 *
 *      Function arguments:
 *      	kvps		keys value pairs passed from pcscd to plugin
 *
 *      Return values: 
 *		SUCCESS  = 1
 *		FAIL	 = 0
 *
 *  isAuthorized(PCSCLITE_CRED_T *cred, const void *resource)
 *
 *      This function determes whether the client is authorized to access
 *      the pcscd daemon.  The display #, as well as the credentials of the
 *      client are passed in the cred structure.
 *
 *      The resource argument is a determined by the plugin that validated
 *      the display prior to this authentication plugin being called, and 
 *      can be NULL.
 *
 *      Function arguments:
 * 		cred		client cred struct from pcscd to plugin
 *		resource	display resource from pcscd to plugin
 *
 *      Return values:
 *              SUCCESS = 1
 *              FAIL    = 0
 */
int init(kvp_t *kvps);
int isAuthorized(PCSCLITE_CRED_T *cred, const void *resource);


/* Convenience functions:
 *
 *  findValueForKey(const kvp_t *kvps, const char *key)
 * 
 *       Optionally called by plugin to lookup specified key in a case
 *       insensitive way.  The list of key-value pairs must be passed thru
 *       the kvps argument.  The function returns the corresponding value
 *       if the key is located, otherwise it returns NULL.
 *
 *      Function arguments:
 *		kvps		key value pairs from plugin to pcscd
 *		key		key to find, plugin to pcscd
 *
 *  isKeyValueTrue(const kvp_t *kvps, const char *key)
 *  
 *       Optionally called by plugin to lookup a key and determine
 *       if its corresponding value is one of the following strings:
 *       "TRUE", "true", "YES", "yes", "ON", "on", or "1".
 *
 *      Function arguments:
 *		kvps		key value pairs from plugin to pcscd
 *		key		key to evaluation, plugin to pcscd
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

#endif //__pcscd_auth_h___
