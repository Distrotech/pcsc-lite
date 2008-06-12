/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2002
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 1999-2005
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: debuglog.c 1953 2006-03-21 13:46:28Z rousseau $
 */

/**
 * @file
 * @brief This handles debugging for libpcsclite.
 */

#include "config.h"
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "debug.h"
#include "strlcpycat.h"


#define DEBUG_BUF_SIZE 2048

/* default level is a bit verbose to be backward compatible */
static int LogLevel = PCSC_LOG_CRITICAL;

static signed char LogDoColor = 0;	/* no color by default */

void log_init(void)
{
	char *e;

#ifdef LIBPCSCLITE
	e = getenv("PCSCLITE_DEBUG");
#else
	e = getenv("MUSCLECARD_DEBUG");
#endif
	if (e)
		LogLevel = atoi(e);

	/* no color under Windows */
#ifndef WIN32
	/* log to stderr and stderr is a tty? */
	if (isatty(fileno(stderr)))
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
} /* log_init */

void log_msg(const int priority, const char *fmt, ...)
{
	char DebugBuffer[DEBUG_BUF_SIZE];
	char printBuf[DEBUG_BUF_SIZE];

	va_list argptr;
	static int is_initialized = 0;
	time_t clock = time(0);
	struct tm *curtime = localtime(&clock);
	unsigned long ms;

	if (!is_initialized)
	{
		log_init();
		is_initialized = 1;
	}

	if (priority < LogLevel) /* log priority lower than threshold? */
		return;


	va_start(argptr, fmt);
#ifndef WIN32
	vsnprintf(DebugBuffer, DEBUG_BUF_SIZE, fmt, argptr);
#else
#if HAVE_VSNPRINTF
	vsnprintf(DebugBuffer, DEBUG_BUF_SIZE, fmt, argptr);
#else
	vsprintf(DebugBuffer, fmt, argptr);
#endif
#endif
	va_end(argptr);

	ms  = (unsigned long)
		((gethrtime() / (unsigned long long)100000) % 10000);

	sprintf(printBuf, "%2d:%2.2d:%2.2d.%4.4d ",
		curtime->tm_hour, curtime->tm_min, curtime->tm_sec, ms);
	strlcat(printBuf, DebugBuffer, DEBUG_BUF_SIZE);

#ifndef WIN32
	{
#ifdef HAVE_SYSLOG_H
		if (priority == PCSC_LOG_CRITICAL)
			syslog(LOG_ERR, "%s", DebugBuffer);
#endif
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
			fprintf(stderr, "%s%s%s\n", color_pfx, printBuf, color_sfx);
		}
		else
			fprintf(stderr, "%s\n", printBuf);
	}
#else
	fprintf(stderr, "%s\n", printBuf);
#endif
} /* log_msg */

void log_xxd(const int priority, const char *msg, const unsigned char *buffer,
	const int len)
{
	char DebugBuffer[DEBUG_BUF_SIZE];
	int i;
	char *c;
	char *debug_buf_end;
	time_t clock = time(0);
	struct tm *curtime = localtime(&clock);

	if (priority < LogLevel) /* log priority lower than threshold? */
		return;

	debug_buf_end = DebugBuffer + DEBUG_BUF_SIZE - 5;

	sprintf(DebugBuffer, "%d:%d ", curtime->tm_hour, curtime->tm_min);
	strlcat(DebugBuffer, msg, sizeof(DebugBuffer));
	c = DebugBuffer + strlen(DebugBuffer);

	for (i = 0; (i < len) && (c < debug_buf_end); ++i)
	{
		sprintf(c, "%02X ", buffer[i]);
		c += strlen(c);
	}

	fprintf(stderr, "%s\n", DebugBuffer);
} /* log_xxd */

/*** PKK REMOVE ***/

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

