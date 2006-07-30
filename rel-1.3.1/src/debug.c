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
 * @brief This handles debugging.
 */
 
#include "config.h"
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "debug.h"
#include "strlcpycat.h"

#define DEBUG_BUF_SIZE 2048

/* default level is a bit verbose to be backward compatible */
static char LogLevel = PCSC_LOG_ERROR;

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
	{
		LogLevel = atoi(e);
		printf("pouet %d\n", LogLevel);
	}

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
	va_list argptr;
	static int is_initialized = 0;

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

#ifndef WIN32
	{
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
			fprintf(stderr, "%s%s%s\n", color_pfx, DebugBuffer, color_sfx);
		}
		else
			fprintf(stderr, "%s\n", DebugBuffer);
	}
#else
	fprintf(stderr, "%s\n", DebugBuffer);
#endif
} /* log_msg */

void log_xxd(const int priority, const char *msg, const unsigned char *buffer,
	const int len)
{
	char DebugBuffer[DEBUG_BUF_SIZE];
	int i;
	char *c;
	char *debug_buf_end;

	if (priority < LogLevel) /* log priority lower than threshold? */
		return;

	debug_buf_end = DebugBuffer + DEBUG_BUF_SIZE - 5;

	strlcpy(DebugBuffer, msg, sizeof(DebugBuffer));
	c = DebugBuffer + strlen(DebugBuffer);

	for (i = 0; (i < len) && (c < debug_buf_end); ++i)
	{
		sprintf(c, "%02X ", buffer[i]);
		c += strlen(c);
	}

	fprintf(stderr, "%s\n", DebugBuffer);
} /* log_xxd */

