/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2006-2007
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id: pcscdaemon.c 2377 2007-02-05 13:13:56Z rousseau $
 */

/**
 * @file
 * @brief utility functions
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "debug.h"
#include "config.h"
#include "utils.h"
#include "pcscd.h"

pid_t GetDaemonPid(void)
{
	FILE *f;
	pid_t pid;

	/* pids are only 15 bits but 4294967296
	 * (32 bits in case of a new system use it) is on 10 bytes
	 */
	if ((f = fopen(PCSCLITE_RUN_PID, "rb")) != NULL)
	{
		char pid_ascii[PID_ASCII_SIZE];

		fgets(pid_ascii, PID_ASCII_SIZE, f);
		fclose(f);

		pid = atoi(pid_ascii);
	}
	else
	{
		Log2(PCSC_LOG_CRITICAL, "Can't open " PCSCLITE_RUN_PID ": %s",
			strerror(errno));
		return -1;
	}

	return pid;
} /* GetDaemonPid */

int SendHotplugSignal(void)
{
	pid_t pid;

	pid = GetDaemonPid();

	if (pid != -1)
	{
		Log2(PCSC_LOG_INFO, "Send hotplug signal to pcscd (pid=%d)", pid);
		if (kill(pid, SIGUSR1) < 0)
		{
			Log3(PCSC_LOG_CRITICAL, "Can't signal pcscd (pid=%d): %s",
				pid, strerror(errno));
			return EXIT_FAILURE ;
		}
	}

	return EXIT_SUCCESS;
} /* SendHotplugSignal */

