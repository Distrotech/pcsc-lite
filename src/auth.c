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

/**
 * @file
 * @brief This handles thread function abstraction.
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ucred.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <thread.h>
#include <synch.h>
#include <debuglog.h>
#include <syslog.h>
#include <unistd.h>
#include "clientcred.h"
#include "pcsc_config.h"
#include "pcsclite.h"
#include "auth.h"
#if 0
#include "pcscd-auth.h"
#include "ifd-auth.h"
#endif
#include "util.h"

#define AUTHORIZED 		1
#define SUCCESS			0
#define PLUGIN_NOT_FOUND 	-1
#define PLUGIN_NOT_VALID	-2
#define NOT_AUTHORIZED 		-3
#define RELOAD_ABORTED		-4
#define PATH_MAX 		256
#define LINEMAX			256
#define KVMAXLEN		256
#define IFD_PLUGIN		0
#define DAEMON_PLUGIN		1

#define NONULL(s) s ? s : "<null>"

#define MAX_KEY_LEN 64

typedef struct kvp_list {
	struct kvp_list *next;
	char *key;
	char *val;
} kvp_t;

typedef struct authPlugin {
	struct authPlugin *nx;
	struct authPlugin *pv;
	void *handle;
	char *path;
	char *cfgFilePath;
	char *tag;
	char *resource;
	int refcnt;
	mutex_t refcnt_lock;
	mutex_t unload_lock;
	kvp_t *kvps;
	time_t ctime;
	time_t cfg_ctime;
	int (*initFunc)();
	int (*authFunc)();
} plugin_t;

static void freeKvp(kvp_t *);
static void freeKvps(kvp_t *);
static int loadPlugin(plugin_t **, const char *, char *, const char *, int);
static int reloadPlugin(plugin_t **, int);
static time_t getFileCtime(char *);
static plugin_t *acquirePluginAccess(const char *, int);
static plugin_t *releasePluginAccess(const char *, int);
static int loadCfgFile(const char *, const char *, kvp_t **);
static int invokeAuthPlugin(const char *, PCSCLITE_CRED_T *,
    const char *, const void *, int);
static plugin_t *findPluginByTag(const char *, int);

static plugin_t plist, ilist;
static time_t conf_ctime;

#define NONULL(n) n ? n : "<null>"

/**
 * @brief Get client credentials from socket.
 *
 * Returns 0 if successful and populates euid & egid params
 * Otherwise returns -1, and stores -1 in euid and egid params
 *
 * *** CURRENTLY SOLARIS ONLY... need to know how to check
 * how feature works or OS and return in platform indep. way.
 */
int
AUTHGetClientCreds(int fd, PCSCLITE_CRED_T *cred)
{
	ucred_t *ucred = NULL;
	struct sockaddr_in s;
	int rv, len;
	/* For security purposed, assume it will fail */
	cred->euid = -1;
	cred->egid = -1;
	cred->pid  = -1;
	cred->solaris.ruid = -1;
	cred->solaris.rgid = -1;

	/* Calculate size of INETV4 type sockaddr struct */
	memset(&s, 0, sizeof (s));
	s.sin_family = AF_INET;
	len = sizeof(s);

	/* Attempt to get client IP address */
	if ((rv = getpeername(fd, (struct sockaddr *)&s, &len)) != -1)
		cred->clientIP = (in_addr_t)s.sin_addr.s_addr;

	/* Attempt to get client credentials */
	if ((rv = getpeerucred(fd, &ucred)) < 0)
		return -1;

	cred->euid = ucred_geteuid(ucred);
	cred->egid = ucred_getegid(ucred);
	cred->pid  = ucred_getpid(ucred);
	cred->solaris.ruid = ucred_getruid(ucred);
	cred->solaris.rgid = ucred_getrgid(ucred);

	ucred_free(ucred);
	return 0;
}


int
AUTHCheckDaemon(const char *facilityTag, PCSCLITE_CRED_T *cred,
			const char *resource)
{
	plugin_t *pp;

	if (plist.nx == NULL)
		LIST_INIT(&plist);

	pp = acquirePluginAccess(facilityTag, DAEMON_PLUGIN);
	/* Invoke the facility-specific module */
	switch(invokeAuthPlugin(facilityTag, cred, "", resource, DAEMON_PLUGIN)) {
	case AUTHORIZED:
		if (pp)
			releasePluginAccess(facilityTag, DAEMON_PLUGIN);
		return 0;
	case NOT_AUTHORIZED:
		if (pp)
			releasePluginAccess(facilityTag, DAEMON_PLUGIN);
		return -1;
	case PLUGIN_NOT_VALID:
	case PLUGIN_NOT_FOUND:
		/* Try again using the generic module */
		switch(invokeAuthPlugin(NULL, cred, "", resource, DAEMON_PLUGIN)) {
		case AUTHORIZED:
			if (pp)
				releasePluginAccess(facilityTag, DAEMON_PLUGIN);
			return 0;
		case NOT_AUTHORIZED:
		case PLUGIN_NOT_VALID:
		case PLUGIN_NOT_FOUND:
			if (pp)
				releasePluginAccess(facilityTag, DAEMON_PLUGIN);
			return -1;
		}
	}
	if (pp)
		releasePluginAccess(facilityTag, DAEMON_PLUGIN);
	return 0;
}

int
AUTHCheckIfd(const char *facilityTag, PCSCLITE_CRED_T *cred,
		 const char *ifdHandlerName, const char *resource)
{
	plugin_t *pp;

	if (ilist.nx == NULL)
		LIST_INIT(&ilist);

	pp = acquirePluginAccess(facilityTag, IFD_PLUGIN);
	/* Invoke the facility-specific module */
	switch(invokeAuthPlugin(facilityTag, cred,
	    ifdHandlerName, resource, IFD_PLUGIN)) {
	case AUTHORIZED:
		if (pp)
			releasePluginAccess(facilityTag, IFD_PLUGIN);
		return 0;
	case NOT_AUTHORIZED:
		if (pp)
			releasePluginAccess(facilityTag, IFD_PLUGIN);
		return -1;
	case PLUGIN_NOT_VALID:
	case PLUGIN_NOT_FOUND:
		/* Try again using the generic module */
		switch(invokeAuthPlugin(NULL, cred,
		   ifdHandlerName, resource, IFD_PLUGIN)) {
		case AUTHORIZED:
			if (pp)
				releasePluginAccess(facilityTag, IFD_PLUGIN);
			return 0;
		case NOT_AUTHORIZED:
		case PLUGIN_NOT_VALID:
		case PLUGIN_NOT_FOUND:
			if (pp)
				releasePluginAccess(facilityTag, IFD_PLUGIN);
			return -1;
		}
	}
	if (pp)
		releasePluginAccess(facilityTag, IFD_PLUGIN);
	return 0;
}

static int
invokeAuthPlugin(const char *facilityTag, PCSCLITE_CRED_T *cred,
	 const char *ifdHandlerName, const void *resource, int type)
{
	char cfgFilePath[PATH_MAX], *tag;
	void *pluginHandle = NULL;
	int rv;
	plugin_t *pp, *listhead;

	/*
	 * See if we've already loaded the plugin
	 */
	listhead = (type == DAEMON_PLUGIN) ? &plist : &ilist;
	LIST_FOREACH(pp, listhead) {
		if (strcmp(pp->tag, facilityTag) == 0) {
			pluginHandle = pp->handle;
			break;
		}
	}
	/*
	 * If plugin isn't loaded, or the plugin or configuration file changed
	 * on disk load (or refresh) the plugin.
	 */
	 if (pluginHandle == NULL) {
		pp = NULL;
		if (loadPlugin(&pp, facilityTag, cfgFilePath, resource, type) ==
		    PLUGIN_NOT_VALID)
			return 0;
		LIST_INSERT_LAST(pp, listhead);
	} else if (getFileCtime(pp->path) != pp->ctime ||
		   getFileCtime(pp->cfgFilePath) != pp->cfg_ctime) {

		if ((rv = reloadPlugin(&pp, type)) == PLUGIN_NOT_VALID)
			return 0;
		LIST_INSERT_LAST(pp, listhead);
	}
	/*
	 * Call plugin authorization check function
	 */
	switch(type) {
	case DAEMON_PLUGIN:
		rv = pp->authFunc(cred, resource);
		break;
	case IFD_PLUGIN:
		rv = pp->authFunc(cred, ifdHandlerName, resource);
		break;
	}
	return rv;
}

static int
loadPlugin(plugin_t **plugin, const char *facilityTag,
    char *cfgFilePath, const char *resource, int type)
{
	char pluginPath[PATH_MAX];
	plugin_t *pp;


	if (*plugin != NULL) {
		pp = *plugin;
	} else {
		if ((pp = malloc(sizeof (plugin_t))) == NULL) {
			Log1(PCSC_LOG_CRITICAL, "Out of Memory");
			return PLUGIN_NOT_VALID;
		}
		if (facilityTag == NULL) {
			sprintf(pluginPath,  "%s/%sAuth.so.1",
			    PCSCLITE_LIB_DIR, type == DAEMON_PLUGIN ? "pcscd" : "ifd");
			sprintf(cfgFilePath, "%s/%sAuth.conf",
			    PCSCLITE_LIB_DIR, type == DAEMON_PLUGIN ? "pcscd" : "ifd");
		} else {
			sprintf(pluginPath,  "%s/%sAuth-%s.so.1",
			    PCSCLITE_LIB_DIR, type == DAEMON_PLUGIN ? "pcscd" : "ifd",
			    facilityTag);
			sprintf(cfgFilePath, "%s/%sAuth-%s.conf",
			    PCSCLITE_LIB_DIR, type == DAEMON_PLUGIN ? "pcscd" : "ifd",
			    facilityTag);
		}
		bzero(pp, sizeof (plugin_t));
		pp->path = strdup(pluginPath);
		pp->tag = strdup(facilityTag);
		pp->cfgFilePath = strdup(cfgFilePath);
		pp->resource = strdup(resource);
	}

	pp->ctime = getFileCtime(pluginPath);
	pp->cfg_ctime = getFileCtime(cfgFilePath);
	if (pp->kvps != NULL) {
		freeKvps(pp->kvps);
		pp->kvps = NULL;
	}

	if ((pp->handle = dlopen(pp->path,
	    RTLD_GLOBAL | RTLD_PARENT | RTLD_LAZY)) == NULL) {
		Log3(PCSC_LOG_CRITICAL,
			"Err opening Auth plugin: %s:\n%s\n\n",
			NONULL(pluginPath), dlerror());
		free(pp);
		return PLUGIN_NOT_FOUND;
	}
	if ((pp->initFunc = (int(*)())dlsym(pp->handle,  "init")) == NULL) {
		Log3(PCSC_LOG_CRITICAL,
		    "Err finding symbol 'init' in %s:\n%s\n\n",
		    NONULL(pluginPath), dlerror());
		dlclose(pp->handle);
		free(pp);
		return PLUGIN_NOT_VALID;
	}
	if ((pp->authFunc = (int(*)())dlsym(pp->handle, "isAuthorized")) == NULL) {
		Log3(PCSC_LOG_CRITICAL,
		    "Err finding symbol 'isAuthorized' in %s:\n%s\n\n",
		     NONULL(pluginPath), dlerror());
		dlclose(pp->handle);
		free(pp);
		return PLUGIN_NOT_VALID;
	}
	(void) loadCfgFile(cfgFilePath, resource, &pp->kvps);

	/* Initialize the plugin */
	if (pp->initFunc(pp->kvps) < 0) {
		Log2(PCSC_LOG_CRITICAL,
		    "Error initializing plugin: %s\n",
		    NONULL(pluginPath));
		freeKvps(pp->kvps);
		dlclose(pp->handle);
		free(pp);
		return PLUGIN_NOT_VALID;
	}

	*plugin = pp;
	return SUCCESS;
}
static int
reloadPlugin(plugin_t **pp, int type)
{
	int rv;

	/*
	 * If the plugin is being unloaded by another thread
	 * just return so we don't deadlock via the refcnt test
	 */
	if (mutex_trylock(&(*pp)->unload_lock) == EBUSY)
		return PLUGIN_NOT_VALID;

	/*
	 * Wait for plugin accesses already in progess to complete
	 */
	for(;;) {
		mutex_lock(&(*pp)->refcnt_lock);
		if ((*pp)->refcnt == 1) {
			// We unload when refcnt is 1 because that's us
			mutex_unlock(&(*pp)->refcnt_lock);
			break;
		}
		mutex_unlock(&(*pp)->refcnt_lock);
		usleep(50000);
	}
	/*
	 * Now have exclusive access to plugin.  Unload it.
	 */
	dlclose((*pp)->handle);
	rv = loadPlugin(pp, NULL, NULL, NULL, NULL);
	mutex_unlock(&(*pp)->unload_lock);
	return rv;

}

/*
 * Load and parse configuration file into global array.
 * If an error occurs, displays brief definitive message
 * which includes filename and line number and aborts
 * the daemon.
 */
static int
loadCfgFile(const char *path, const char *resource, kvp_t **kvps)
{
	FILE *fp = NULL;
	char *cp, line[LINEMAX], temp[LINEMAX];
	char key[KVMAXLEN], val[KVMAXLEN];
	int i, j, rv, lineNbr;
	kvp_t *new_kvp, *kvpp;
	kvp_t *kvp_list = NULL;

	if ((fp = fopen(path, "r")) == NULL)
		return SUCCESS; // this conf file is optional

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
			     path, lineNbr);
			fclose(fp);
			return PLUGIN_NOT_VALID;

		} else
			*cp = '\0';  /* Divide line into two strings */

		/* Extract val */
		if (cp >= line + strlen(line))
			strcpy(val, cp + 1);

		/* Extract key */
		strcpy(key, line);

		new_kvp = malloc(sizeof (struct kvp_list));
		new_kvp->next = NULL;
		new_kvp->key = strdup(key);
		new_kvp->val = strdup(val);
		if (kvp_list == NULL)
			kvp_list = new_kvp;
		else {
			for (kvpp = kvp_list; kvpp->next != NULL; kvpp = kvpp->next);
			kvpp->next = new_kvp;
		}
	}
	fclose(fp);
	*kvps = kvp_list;
	return SUCCESS;
}

static plugin_t *
acquirePluginAccess(const char *tag, int type) {
	plugin_t *pp, *listhead, *plugin = NULL;

	if ((plugin = findPluginByTag(tag, type)) == NULL)
		return NULL;
	/*
	 * Acquire/immedidate release intentional in order to deny access to
	 * the plugin while reloadPlugin() is active. If, due to bad timing,
	 * this brief acquisition causes the mutex_trylock() to abort
	 * reloadPlugin(), statistics ensure the plugin will get reloaded
	 * at a subsequent access, as the cached plugin file timestamp will
	 * remain out of sync with the one in the filesystem.
	 */
	mutex_lock(&plugin->unload_lock);
	mutex_unlock(&plugin->unload_lock);
	mutex_lock(&plugin->refcnt_lock);
	++plugin->refcnt;
	mutex_unlock(&plugin->refcnt_lock);
	return plugin;
}

static plugin_t *
releasePluginAccess(const char *tag, int type) {
	plugin_t *pp, *listhead, *plugin = NULL;

	if ((plugin = findPluginByTag(tag, type)) == NULL)
		return NULL;

	mutex_lock(&plugin->refcnt_lock);
	--plugin->refcnt;
	mutex_unlock(&plugin->refcnt_lock);
	return plugin;
}


static plugin_t *
findPluginByTag(const char *tag, int type) {
	plugin_t *pp, *listhead;

	switch (type) {
	case IFD_PLUGIN:
		listhead = &ilist;
		break;
	case DAEMON_PLUGIN:
		listhead = &plist;
		break;
	}

	LIST_FOREACH(pp, listhead)
		if (strcmp(pp->tag, tag) == 0)
			return pp;

	return NULL;
}

static void
freeKvps(kvp_t *kvpp) {
	kvp_t *saveptr;
	while (kvpp != NULL) {
		if (kvpp->key != NULL)
			free(kvpp->key);
		if (kvpp->val != NULL)
			free(kvpp->val);
		saveptr = kvpp;
		kvpp = kvpp->next;
		free(saveptr);
	}
}

static void
freeKvp(kvp_t *kvpp)
{
	if (kvpp == NULL)
		return;
	if (kvpp->key != NULL)
		free(kvpp->key);
	if (kvpp->val != NULL)
		free(kvpp->val);
	free(kvpp);
}

static time_t
getFileCtime(char *path)
{
	struct stat statbuf;
	if (stat(path, &statbuf) < 0)
		return 0;
	return statbuf.st_ctime;
}


char *
findValueForKey(const kvp_t *kvps, const char *key)
{
	kvp_t *kvp;
	int len;

	if (kvps == NULL || key == NULL)
		return NULL;
	len = strlen(key);
	if (len < 1 || len > MAX_KEY_LEN)
		return NULL;
	for(kvp = (kvp_t *)kvps; kvp != NULL; kvp = kvp->next) {
		if (strncasecmp(key, kvp->key, len) == 0)
			return kvp->val;
	}
	return NULL;
}

int
isKeyValueTrue(const kvp_t *kvps, const char *key)
{
	char *val = findValueForKey(kvps, key);

	if (val == NULL)
		return 0;
	if (strcasecmp(val, "TRUE") == 0)
		return 1;
	if (strcasecmp(val, "1") == 0)
		return 1;
	if (strcasecmp(val, "YES") == 0)
		return 1;
	if (strcasecmp(val, "ON") == 0)
		return 1;
	return 0;
}
