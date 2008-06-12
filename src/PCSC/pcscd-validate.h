/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2005
 *  David Corcoran <corcoran@linuxnet.com>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 */

/**
 * @file
 * @brief This keeps a list of defines shared between the driver and the application
 */

#ifndef __pcscd_validate_h__
#define __pcscd_validate_h__

#ifdef __cplusplus
extern "C"
{
#endif

typedef int (*initValidate_t)(int, char **);
typedef char *(*getDisplayTag_t)(int, char **);
typedef void *(*getDisplayResource_t)(int, void **);
typedef int (*getDisplayStatus_t)(int dpyNbr, unsigned int *flags);

/*
 * 
 * Plugin entry points (plugin developer must implement these)
 *
 *   initValidation(int argc, char **argv, int *errnop):
 *
 *      This function is called by the pcscd daemon with argc, argv, in the
 *      same manner that main() is called by UNIX-like OSes, and may be parsed
 *      using getopt().  This function's job is to do whatever setup is 
 *      necessary in order to use the validation functions also defined
 *      plugin.
 *
 *      NOTE: This function can be called more than once. Code accordingly!
 *
 *      Function Arguments:
 *
 *              argc           Argument count
 *              argv           Argument vector
 *              errno          Pointer to errno (so plugin uses correct one)
 *
 *      Return values: 
 *		SUCCESS  = 1
 *		FAIL	 = 0
 *
 *   getDisplayTag(int dpyNbr, char **facilityTag):
 *
 *      This function returns the platform-specific name of the facility that
 *      the display belongs to. For example, it could be the 'tag' value that
 *      is defined for the dispaly in the Xservers file.
 *
 *      Function arguments:
 *             dpyNbr          Passed from pcscd to plugin
 *             **facilityTag   Ptr to bufptr passed to plugin to return tag into
 * 		  	       The caller must free the buffer;
 *
 *      Return values:
 *             Same value returned to *facilityTag;
 * 
 *
 *   getDisplayResource(int dpyNbr, void **resource):
 *
 *      This function returns the platform-specific resource associated with
 *      the display.  For example, it could be the whole entry that defines
 *      the display in the Xservers file, or something else.   It is up to
 *      the platform to decide.  This resource argument will be passed to
 *      the authentication plugin during daemon access authentication.
 *
 *      Function arguments:
 *      	dpyNbr         Passed from pcscd to plugin
 *      	resource       Ptr to bufptr passed to plugin to return res into
 *			       The caller must free the buffer.
 *
 *      Return values:
 *		Same value returned to *resource
 * 
 * 
 *    getDisplayStatus(int dpyNbr, unsigned int *flags):
 *
 *       This function returns whether or not a display is recognized
 *       and valid, and returns flags providing extra information 
 *       about the display pcscd will use to make decisions about
 *       controlling access.
 *
 *       Function arguments:
 *              dpyNbr        Passed from pcscd to plugin
 *      	flags         Flags returned from plugin to pcscd:
 *   
 *       Return values:
 *               DISPLAY_IS_VALID
 *		 DISPLAY_NOT_VALID
 *
 *       
 */
#define DISPLAY_NOT_VALID	-1
#define DISPLAY_IS_VALID	0

/* 
 * Bitmask values for getDisplayStatus flags argument.
 */
#define DISPLAY_HAS_NEW_PROVIDER 1	/* New session / owner for display */

int initValidate(int argc, char **argv);
char *getDisplayTag(int dpyNbr, char **facilityTag);
void *getDisplayResource(int dpyNbr, void **resource);
int getDisplayStatus(int dpyNbr, unsigned int *flags);


#ifdef __cplusplus
extern "C"
}
#endif

#endif
