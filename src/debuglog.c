/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2002
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 1999-2005
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id$
 */

/**
 * @file
 * @brief This handles debugging for pcscd.
 */

#include "config.h"
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/types.h>
#include <fcntl.h>

#include "pcsclite.h"
#include "misc.h"
#include "debuglog.h"
#include "sys_generic.h"
#include <sys/time.h>
#include "strlcpycat.h"

/**
 * Max string size when dumping a 256 bytes longs APDU
 * Should be bigger than 256*3+30
 */
#define DEBUG_BUF_SIZE 2048

static char LogSuppress = DEBUGLOG_LOG_ENTRIES;
static char LogMsgType = DEBUGLOG_NO_DEBUG;
static char LogCategory = DEBUG_CATEGORY_NOTHING;

/* default level is a bit verbose to be backward compatible */
static int LogLevel = PCSC_LOG_INFO;

static signed char LogDoColor = 0;	/* no color by default */

void log_msg(const int priority, const char *fmt, ...)
{
	char *wrkbuf, *printbuf;
	va_list argptr;
	static int init_flag;
	time_t clock = time(0);
	struct tm *curtime = 0;
	unsigned long ms;


	if ((LogSuppress != DEBUGLOG_LOG_ENTRIES)
		|| (priority < LogLevel) /* log priority lower than threshold? */
		|| (DEBUGLOG_NO_DEBUG == LogMsgType))
		return;

	curtime = localtime(&clock);
	printbuf = malloc(DEBUG_BUF_SIZE);
	if (printbuf == NULL) {
		syslog(LOG_ERR, "Out of Memory");
		return;
	}

	bzero(printbuf, DEBUG_BUF_SIZE);
	wrkbuf = malloc(DEBUG_BUF_SIZE);
	if (wrkbuf == NULL) {
		syslog(LOG_ERR, "Out of Memory");
		free(printbuf);
		return;
	}
	bzero(wrkbuf, DEBUG_BUF_SIZE);

	va_start(argptr, fmt);
#ifndef WIN32
	vsnprintf(wrkbuf, DEBUG_BUF_SIZE, fmt, argptr);
#else
#if HAVE_VSNPRINTF
	vsnprintf(wrkbuf, DEBUG_BUF_SIZE, fmt, argptr);
#else
	vsprintf(wrkbuf, fmt, argptr);
#endif
#endif
	va_end(argptr);

	ms  = (unsigned long)
		((gethrtime() / (unsigned long long)100000) % 10000);

	sprintf(printbuf, "%2d:%2.2d:%2.2d.%4.4d ",
		curtime->tm_hour, curtime->tm_min, curtime->tm_sec, ms);

	strlcat(printbuf, wrkbuf, DEBUG_BUF_SIZE);

#ifndef WIN32
	if (DEBUGLOG_SYSLOG_DEBUG == LogMsgType) {
#if HAVE_SYSLOG_H
		syslog(LOG_INFO, "%s", wrkbuf);
#endif
	} else {
		if (priority == PCSC_LOG_CRITICAL)
			syslog(LOG_ERR, "%s", wrkbuf);

		if (LogDoColor)
		{
			const char *color_pfx = "", *color_sfx = "\33[0m";

			switch (priority)
			{
				case PCSC_LOG_CRITICAL:
					color_pfx = "\33[01;31m"; /* bright + Red */
					break;

				case PCSC_LOG_ERROR:
					color_pfx = "\33[35m"; /* Magenta */
					break;

				case PCSC_LOG_INFO:
					color_pfx = "\33[34m"; /* Blue */
					break;

				case PCSC_LOG_DEBUG:
					color_pfx = ""; /* normal (black) */
					color_sfx = "";
					break;
			}
			fprintf(stderr, "%s%s%s\n", color_pfx, wrkbuf, color_sfx);
		}
		else {
			write(2, printbuf, strlen(printbuf));
			write(2, "\n", 1);
		}
	}
#else
		write(2, printbuf, strlen(printbuf));
		write(2, "\n", 1);
#endif
	free(printbuf);
	free(wrkbuf);
} /* log_msg */

int init_flag = 0;
void log_xxd(const int priority, const char *msg, const unsigned char *buffer,
	const int len)
{
	static char wrkbuf[DEBUG_BUF_SIZE];
	int i;
	char *c;
	char *debug_buf_end;
	time_t clock = time(0);
	struct tm *curtime = localtime(&clock);

	/*
	 * Set stderr to non-blocking
	 */
	if (init_flag) {
		init_flag = 1;
		fcntl(2, F_SETFL, O_NDELAY);
	}

	if ((LogSuppress != DEBUGLOG_LOG_ENTRIES)
		|| (priority < LogLevel) /* log priority lower than threshold? */
		|| (DEBUGLOG_NO_DEBUG == LogMsgType))
		return;

	debug_buf_end = wrkbuf + DEBUG_BUF_SIZE - 5;

	sprintf(wrkbuf, "%d:%d ", curtime->tm_hour, curtime->tm_min);
	strlcat(wrkbuf, msg, sizeof(wrkbuf));
	c = wrkbuf + strlen(wrkbuf);

	for (i = 0; (i < len) && (c < debug_buf_end); ++i)
	{
		sprintf(c, "%02X ", buffer[i]);
		c += 3;
	}

	/* the buffer is too small so end it with "..." */
	if ((c >= debug_buf_end) && (i < len))
		c[-3] = c[-2] = c[-1] = '.';

#ifndef WIN32
	if (DEBUGLOG_SYSLOG_DEBUG == LogMsgType)
		syslog(LOG_INFO, "%s", wrkbuf);
	else {
#endif
		write(2, wrkbuf, strlen(wrkbuf));
		write(2, "\n", 1);
	}
} /* log_xxd */

#ifdef PCSCD
void DebugLogSuppress(const int lSType)
{
	LogSuppress = lSType;
}
#endif

void DebugLogSetLogType(const int dbgtype)
{
	switch (dbgtype)
	{
		case DEBUGLOG_NO_DEBUG:
		case DEBUGLOG_SYSLOG_DEBUG:
		case DEBUGLOG_STDERR_DEBUG:
			LogMsgType = dbgtype;
			break;
		default:
			Log2(PCSC_LOG_CRITICAL, "unknown log type (%d), using stderr",
				dbgtype);
			LogMsgType = DEBUGLOG_STDERR_DEBUG;
	}

	/* no color under Windows */
#ifndef WIN32
	/* log to stderr and stderr is a tty? */
	if (DEBUGLOG_STDERR_DEBUG == LogMsgType && isatty(fileno(stderr)))
	{
		const char *terms[] = { "linux", "xterm", "xterm-color", "Eterm", "rxvt", "rxvt-unicode" };
		char *term;

		term = getenv("TERM");
		if (term)
		{
			int i;

			/* for each known color terminal */
			for (i = 0; i < sizeof(terms) / sizeof(terms[0]); i++)
			{
				/* we found a supported term? */
				if (0 == strcmp(terms[i], term))
				{
					LogDoColor = 1;
					break;
				}
			}
		}
	}
#endif
}

void DebugLogSetLevel(const int level)
{
	if (LogLevel == level)
		return;

	switch (level)	{
		case PCSC_LOG_CRITICAL:
			break;

		case PCSC_LOG_ERROR:
			break;

		case PCSC_LOG_INFO:
			Log1(PCSC_LOG_INFO, "debug level notice");
			break;

		case PCSC_LOG_DEBUG:
			Log1(PCSC_LOG_DEBUG, "debug level debug");
			break;

		default:
			LogLevel = PCSC_LOG_INFO;
			Log2(PCSC_LOG_CRITICAL, "unknown level (%d), using level=notice",
				level);
	}
	LogLevel = level;
}

INTERNAL int DebugLogSetCategory(const int dbginfo)
{
#define DEBUG_INFO_LENGTH 80
	char text[DEBUG_INFO_LENGTH];

	/* use a negative number to UNset
	 * typically use ~DEBUG_CATEGORY_APDU
	 */
	if (dbginfo < 0)
		LogCategory &= dbginfo;
	else
		LogCategory |= dbginfo;

	/* set to empty string */
	text[0] = '\0';

	if (LogCategory & DEBUG_CATEGORY_APDU)
		strlcat(text, " APDU", sizeof(text));

	Log2(PCSC_LOG_INFO, "Debug options:%s", text);

	return LogCategory;
}

INTERNAL void DebugLogCategory(const int category, const unsigned char *buffer,
	const int len)
{
	if ((category & DEBUG_CATEGORY_APDU)
		&& (LogCategory & DEBUG_CATEGORY_APDU))
		log_xxd(PCSC_LOG_INFO, "APDU: ", (const unsigned char *)buffer, len);

	if ((category & DEBUG_CATEGORY_SW)
		&& (LogCategory & DEBUG_CATEGORY_APDU))
		log_xxd(PCSC_LOG_INFO, "SW: ", (const unsigned char *)buffer, len);
}

/*
 * old function supported for backward object code compatibility
 * defined only for pcscd
 */
#ifdef PCSCD
void debug_msg(const char *fmt, ...)
{
	char wrkbuf[DEBUG_BUF_SIZE];
	va_list argptr;

	if ((LogSuppress != DEBUGLOG_LOG_ENTRIES)
		|| (DEBUGLOG_NO_DEBUG == LogMsgType))
		return;

	va_start(argptr, fmt);
#ifndef WIN32
	vsnprintf(wrkbuf, DEBUG_BUF_SIZE, fmt, argptr);
#else
#if HAVE_VSNPRINTF
	vsnprintf(wrkbuf, DEBUG_BUF_SIZE, fmt, argptr);
#else
	vsprintf(wrkbuf, fmt, argptr);
#endif
#endif
	va_end(argptr);

#ifndef WIN32
	if (DEBUGLOG_SYSLOG_DEBUG == LogMsgType)
		syslog(LOG_INFO, "%s", wrkbuf);
	else
#endif
		fprintf(stderr, "%s\n", wrkbuf);
} /* debug_msg */

void debug_xxd(const char *msg, const unsigned char *buffer, const int len)
{
	log_xxd(PCSC_LOG_ERROR, msg, buffer, len);
} /* debug_xxd */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <thread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAXBUF  ( 256 * 256 )

/*
 * Display stack traceback of specified thread (0 = current thread)
 * on stdout.
 */
void
traceback(int thr)
{
	int pfds[2], tid;

	pipe(pfds);
	tid = (thr == 0) ? thr_self() : thr;

	if (fork() == 0) {
		char buf[MAXBUF], cmp[20], line[256], *cp, *lb, *lp;
		int triggered = 0, bufsize = 0, n;
		printf("------------- Thread# %d "
		       "Traceback --------------\n", tid);
		if ((n = read(pfds[0], buf + bufsize, MAXBUF)) >= 0)
			bufsize += n;
		lb = buf + bufsize;
		for(cp = buf; cp < lb;) {
			bzero(lp = line, sizeof (line));
			while (*cp++ != '\n' && cp < lb)
				*lp++ = *cp;
			*--lp = '\0';
			if (!triggered) {
			    sprintf(cmp, "thread# %d", tid);
			    if (strstr(line, cmp) == NULL)
				continue;
			    triggered = 1;
			    continue;
			}
			if (triggered && *line == '-') {
				printf("------------------------"
				       "------------------------\n");
				return;
			}
			puts(line);
		}
		printf("------------------------"
		       "------------------------\n");
		exit(0);
	} else {
		char cmd[15];
		int out = dup(1);
		sprintf(cmd, "/bin/pstack %d", getpid());
		dup2(pfds[1], 1);
		system(cmd);
		dup2(out, 1);
	}
}

