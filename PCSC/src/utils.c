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
#include <dirent.h>
#include <fcntl.h>

#include "debug.h"
#include "config.h"
#include "utils.h"
#include "pcscd.h"
#include "sys_generic.h"

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

/**
 * Sends an asynchronous event to any waiting client
 *
 * Just write 1 byte to any fifo in PCSCLITE_EVENTS_DIR and remove the file
 *
 * This function must be secured since the files are created by the library
 * or any non privileged process. We must not follow symlinks for example
 */
int StatSynchronize(struct pubReaderStatesList *readerState)
{
	DIR *dir_fd;
	struct dirent *dir;

	if (readerState)
		SYS_MMapSynchronize((void *)readerState, SYS_GetPageSize() );

	dir_fd = opendir(PCSCLITE_EVENTS_DIR);
	while ((dir = readdir(dir_fd)) != NULL)
	{
		char filename[FILENAME_MAX];
		int fd;
		char buf[] = { '\0' };
		struct stat fstat_buf;

		if ('.' == dir->d_name[0])
			continue;

		snprintf(filename, sizeof(filename), "%s/%s", PCSCLITE_EVENTS_DIR,
			dir->d_name);
		Log2(PCSC_LOG_DEBUG, "status file: %s", filename);

		fd = SYS_OpenFile(filename, O_WRONLY | O_APPEND | O_NONBLOCK, 0);
		if (fd < 0)
		{
			Log3(PCSC_LOG_ERROR, "Can't open %s: %s", filename,
				strerror(errno));
		}
		else
		{
			if (fstat(fd, &fstat_buf))
			{
				Log3(PCSC_LOG_ERROR, "Can't fstat %s: %s", filename,
					strerror(errno));
			}
			else
			{
				/* check that the file is a FIFO */
				if (!(fstat_buf.st_mode & S_IFIFO))
					Log2(PCSC_LOG_ERROR, "%s is not a fifo", filename);
				else
					SYS_WriteFile(fd, buf, sizeof(buf));
			}

			SYS_CloseFile(fd);
		}

		if (unlink(filename))
			Log3(PCSC_LOG_ERROR, "Can't remove %s: %s", filename,
			strerror(errno));
	}
	closedir(dir_fd);

	return 0;
} /* StatSynchronize */

