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

#include <ucred.h>
#include <string.h>
#include <dlfcn.h>
#include <thread.h>
#include <synch.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <link.h>
#include "auth.h"
#include <errno.h>
#include <stdlib.h>
#include "pcsclite.h"
#include "validate.h"
#include "pcscd-validate.h"
#include "clientcred.h"
#include "debuglog.h"
#include "pcsc_config.h"
#include "util.h"

#define LINEMAX 256
#define MAXARGS 100
#define NONULL(s) (s ? s : "<null>")

static time_t getFileCtime(char *);
static int havPluginsChanged();
static void reloadPlugins();
static void acquirePluginsAccess();
static void releasePluginsAccess();
static void initArgv(char **);
static void freeArgv(char **);

typedef struct validatePlugin {
	struct validatePlugin *nx;
	struct validatePlugin *pv;
	void *handle;
	char *path;
	char *tag;
	time_t ctime;
	initValidate_t initValidate;
	getDisplayResource_t getDisplayResource;
	getDisplayStatus_t getDisplayStatus;
	getDisplayTag_t getDisplayTag;
} plugin_t;

static plugin_t plist;
static mutex_t plugins_lock;
static mutex_t plugins_refcnt_lock;
static int pluginsRefCnt;
static time_t conf_ctime;

char *
VALgetDisplayTag(int dpyNbr, void *ctx, char **facilityTag)
{
	plugin_t *pp = (plugin_t *)ctx;
	acquirePluginsAccess();
	if (pp->getDisplayTag(dpyNbr, facilityTag) != NULL) {
		releasePluginsAccess();
		return *facilityTag;
	}
	releasePluginsAccess();
	return NULL;
}
void *
VALgetDisplayResource(int dpyNbr, void *ctx, void **resource)
{
	plugin_t *pp = (plugin_t *)ctx;
	acquirePluginsAccess();
	if (pp->getDisplayResource(dpyNbr, resource) != NULL) {
		releasePluginsAccess();
		return *resource;
	}
	releasePluginsAccess();
	return NULL;
}
int
VALgetDisplayStatus(int dpyNbr, void **ctx, unsigned int *flags)
{
	plugin_t *pp;
	acquirePluginsAccess();
	LIST_FOREACH(pp, &plist) {
		if (pp->getDisplayStatus(dpyNbr, flags) == DISPLAY_IS_VALID) {
			releasePluginsAccess();
			*ctx = (void *)pp;
			return DISPLAY_IS_VALID;
		}
	}
	*ctx = NULL;
	releasePluginsAccess();
	return DISPLAY_NOT_VALID;
}
int
VALfindInstanceFiles(int dpyNbr, char **configFile, char **instanceScript) {
	char buf[LINEMAX];
	char *facilityTag;
	void *ctx;
	unsigned int flags;

	if (VALgetDisplayStatus(dpyNbr, &ctx, &flags) != DISPLAY_IS_VALID ||
	    VALgetDisplayTag(dpyNbr, ctx, &facilityTag) == NULL) {
		Log2(PCSC_LOG_CRITICAL,
			"Can't find tag for dpy :%d in Xservers file",
		     pcscCfg.dpyNbr);
		return -1;
	}
	sprintf(buf, "%s/pcscd-%s.conf", PCSCLITE_CONFIG_DIR, facilityTag);
	*configFile = strdup(buf);
	sprintf(buf, "%s/pcscd-%s", PCSCLITE_LIB_DIR, facilityTag);
	*instanceScript = strdup(buf);
	if (facilityTag != NULL)
		free(facilityTag);
	return 0;
}

void
VALloadPlugins()
{
	FILE *fp = NULL;
	char pluginPath[MAXPATHLEN];
	char pluginTag[32], *cp2;
	char *cp, *argp, *argv[MAXARGS], line[LINEMAX], temp[LINEMAX];
	void *pluginHandle = NULL;
	int i, j, argc;
	plugin_t *pp;

	LIST_INIT(&plist);

	if ((fp = fopen(pcscCfg.validateConf, "r")) == NULL) {
		Log3(PCSC_LOG_CRITICAL,	"Opening %s FAILED: %s\n",
		   pcscCfg.validateConf, strerror(errno));
		return;
	}
	conf_ctime = getFileCtime(pcscCfg.validateConf);

	initArgv(argv);
	while (fgets(temp, 256, fp) != NULL) {

		memset(line, 0, sizeof(line));
		if ((cp = strchr(temp, '\n')) != NULL)
		    *cp = '\0';

		freeArgv(argv);

		if (strlen(temp) == 0 ||
		    strncmp(temp, "#", 1) == 0)  /* Discard comments */
			continue;

		optind = 1; // Need to reset since main() called getopt()
		argc = 0;
		argp = temp;
		while((cp = strtok(argp, " \t")) != NULL && argc < MAXARGS) {
			argv[argc++] = strdup(cp);
			argp = NULL;
		}
		argv[argc] = 0;
		Log3(PCSC_LOG_DEBUG, "PCSCLITE_LIB_DIR=%s, argv[0]:%s",
	PCSCLITE_LIB_DIR, argv[0]);

		sprintf(pluginPath, "%s/%s", PCSCLITE_LIB_DIR, argv[0]);

		if ((pluginHandle = dlopen(pluginPath,
		    RTLD_LOCAL | RTLD_PARENT | RTLD_LAZY)) == NULL) {
			Log2(PCSC_LOG_CRITICAL,
				"Error opening plugin %s\n", pluginPath);
			Log2(PCSC_LOG_CRITICAL,
				"Error was: %s\n", dlerror());
			freeArgv(argv);
			continue;
		}

		if ((cp = strchr(argv[0], '-')) == NULL)
			cp = "";
		else {
			++cp;
			if ((cp2 = strchr(pluginTag, '.')) != NULL)
				*cp2 = '\0';
		}

		if ((pp = malloc(sizeof (plugin_t))) == NULL) {
			Log1(PCSC_LOG_CRITICAL, "Out of Memory");
			return;
		}
		bzero(pp, sizeof (plugin_t));
		pp->handle = pluginHandle;
		pp->path = strdup(pluginPath);
		pp->ctime = getFileCtime(pluginPath);
		pp->tag = strdup(cp);

		if ((pp->initValidate = (initValidate_t)dlsym(pluginHandle,
			"initValidate")) == NULL) {
			Log2(PCSC_LOG_CRITICAL,
			    "Error finding init() in plugin %s\n",
			    pluginPath);
			Log2(PCSC_LOG_CRITICAL, "Error was: %s\n", dlerror());
			dlclose(pluginHandle);
			freeArgv(argv);
			free(pp);
			continue;
		}
		if ((pp->getDisplayTag = (getDisplayTag_t)dlsym(pluginHandle,
			"getDisplayTag")) == NULL) {
			Log2(PCSC_LOG_CRITICAL,
			    "Error finding getDisplayTag() in plugin %s\n",
			    pluginPath);
			Log2(PCSC_LOG_CRITICAL, "Error was: %s\n", dlerror());
			dlclose(pluginHandle);
			freeArgv(argv);
			free(pp);
			continue;
		}
		if ((pp->getDisplayResource = (getDisplayResource_t)dlsym(pluginHandle,
			"getDisplayResource")) == NULL) {
			Log2(PCSC_LOG_CRITICAL,
			    "Error finding getDisplayResource() in plugin %s\n",
			    pluginPath);
			Log2(PCSC_LOG_CRITICAL, "Error was: %s\n", dlerror());
			dlclose(pluginHandle);
			free(pp);
			freeArgv(argv);
			continue;
		}
		if ((pp->getDisplayStatus = (getDisplayStatus_t)dlsym(pluginHandle,
			"getDisplayStatus")) == NULL) {
			Log2(PCSC_LOG_CRITICAL,
			    "Error finding getDisplayStatus() in plugin %s\n",
			    pluginPath);
			Log2(PCSC_LOG_CRITICAL, "Error was: %s\n", dlerror());
			dlclose(pluginHandle);
			freeArgv(argv);
			free(pp);
			continue;
		}

		if (pp->initValidate(argc, argv) < 0) {
			Log2(PCSC_LOG_CRITICAL,
			    "Initialization failure for plugin %s\n",
			    pluginPath);
			dlclose(pluginHandle);
			freeArgv(argv);
			free(pp);
			continue;
		}

		LIST_INSERT_LAST(pp, &plist);
	}
	fclose(fp);
	freeArgv(argv);
}

static time_t
getFileCtime(char *path)
{
	struct stat statbuf;
	if (stat(path, &statbuf) < 0) {
		Log2(PCSC_LOG_DEBUG, "Error stat()'ing %s", path);
		return 0;
	}
	return statbuf.st_ctime;
}

static int
havePluginsChanged()
{
	plugin_t *pp;
	if (getFileCtime(pcscCfg.validateConf) != conf_ctime)
		return 1;

	LIST_FOREACH(pp, &plist)   {
		if (getFileCtime(pp->path) != pp->ctime)
			return 1;
	}

	return 0;
}

static void
reloadPlugins()
{
	plugin_t *pp;

	/*
	 * Block new attempts to access plugin
	 */
	mutex_lock(&plugins_lock);
	/*
	 * Wait for any plugin access in progess to complete
	 */
	for(;;) {
		mutex_lock(&plugins_refcnt_lock);
		if (pluginsRefCnt == 0) {
			mutex_unlock(&plugins_refcnt_lock);
			break;
		}
		mutex_unlock(&plugins_refcnt_lock);
		usleep(10000);
	}
	/*
	 * We now have exclusive access to plugins.
	 * Unload all plugins
	 */
	LIST_FOREACH(pp, &plist) {
		dlclose(pp->handle);
		if (pp->path)
			free(pp->path);
		if (pp->tag)
			free(pp->tag);
		LIST_REMOVE(pp);
		free(pp);
	}
	/*
	 * Load all plugins to get refreshed data
	 */
	VALloadPlugins();
	/*
	 * Allow plugins access again
	 */
	mutex_unlock(&plugins_lock);

}

static void
acquirePluginsAccess() {
	plugin_t *pp;
	int rv;
	if (havePluginsChanged())
		reloadPlugins();
	/*
	 * Acquire/release lock immediately.  Goal is to wait
	 * but not to block others.
	 */
	mutex_lock(&plugins_lock);
	mutex_unlock(&plugins_lock);
	mutex_lock(&plugins_refcnt_lock);
	++pluginsRefCnt;
	mutex_unlock(&plugins_refcnt_lock);
}

static void
releasePluginsAccess() {
	mutex_lock(&plugins_refcnt_lock);
	--pluginsRefCnt;
	mutex_unlock(&plugins_refcnt_lock);
}

void
initArgv(char **argv)
{
	int i;
	for (i = 0; i < MAXARGS; i++)
		argv[i] = NULL;
}

void
freeArgv(char **argv)
{
	int i;
	for (i = 0; i < MAXARGS; i++) {
		if (argv[i] != NULL) {
			free(argv[i]);
			argv[i] = NULL;
		}
	}
}

