#undef DO_PROFILE
#ifdef DO_PROFILE

#define PROFILE_FILE "/tmp/pcsc_profile"
#include <stdio.h>
#include <sys/time.h>



struct timeval profile_time_start;
FILE *fd;
char profile_tty;

#define PROFILE_START profile_start(__FUNCTION__);
#define PROFILE_END profile_end(__FUNCTION__);

static void profile_start(const char *f)
{
	static char initialized = FALSE;

	if (!initialized)
	{
		initialized = TRUE;
		fd = fopen(PROFILE_FILE, "a+");
		if (NULL == fd)
		{
			fprintf(stderr, "\33[01;31mCan't open %s: %s\33[0m\n",
				PROFILE_FILE, strerror(errno));
			exit(-1);
		}
		fprintf(fd, "\nStart a new profile\n");

		if (isatty(fileno(stderr)))
			profile_tty = TRUE;
		else
			profile_tty = FALSE;
	}

	gettimeofday(&profile_time_start, NULL);
} /* profile_start */

/* r = a - b */
static long int time_sub(struct timeval *a, struct timeval *b)
{
	struct timeval r;
	r.tv_sec = a -> tv_sec - b -> tv_sec;
	r.tv_usec = a -> tv_usec - b -> tv_usec;
	if (r.tv_usec < 0)
	{
		r.tv_sec--;
		r.tv_usec += 1000000;
	}

	return r.tv_sec * 1000000 + r.tv_usec;
} /* time_sub */
	

static void profile_end(const char *f)
{
	struct timeval profile_time_end;
	long d;

	gettimeofday(&profile_time_end, NULL);
	d = time_sub(&profile_time_end, &profile_time_start);

	if (profile_tty)
		fprintf(stderr, "\33[01;31mRESULT %s \33[35m%ld\33[0m\n", f, d);
	fprintf(fd, "%s %ld\n", f, d);
} /* profile_end */

#else
#define PROFILE_START
#define PROFILE_END
#endif

