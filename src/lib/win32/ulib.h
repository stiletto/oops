/*
Copyright (C) 1999, 2000 Igor Khasilev, igor@paco.net
Copyright (C) 2000 Andrey Igoshin, ai@vsu.ru

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#if	!defined(ULIB_H)
#define	ULIB_H		1


/* types.h */
typedef unsigned long gid_t;
typedef unsigned long mode_t;
typedef unsigned long nlink_t;
typedef          long pid_t;
typedef unsigned long uid_t;
typedef          long off_t;


/* dlfcn.h */
#define	RTLD_NOW	2

extern	void	*dlopen(const char *, int);
extern	void	*dlsym(void *, const char *);
extern	int	dlclose(void *);
extern	char	*dlerror(void);


/* fcntl.h */
#define	F_GETFL		4
#define	F_SETFL		5
#define	F_SETLK		6
#define	F_WRLCK		3
#define	O_NONBLOCK	0x1000
#define	O_BLOCK		0x2000

struct flock
{
    short l_type;		/* F_RDLCK, F_WRLCK, or F_UNLCK         */
    short l_whence;		/* flag for starting offset             */
    off_t l_start;		/* relative offset in bytes             */
    off_t l_len;		/* size; if 0 then until EOF            */
    pid_t l_pid;		/* pid of process holding the lock      */
};

typedef	struct	flock	flock_t;
extern	int	fcntl(int, int, ...);


/* glob.h */
typedef struct {
        int gl_pathc;           /* Count of total paths so far.			*/
        int gl_matchc;          /* Count of paths matching pattern.		*/
        int gl_offs;            /* Reserved at beginning of gl_pathv.		*/
        int gl_flags;           /* Copy of flags parameter to glob.		*/
        char **gl_pathv;        /* List of paths matching pattern.		*/
} glob_t;

#define GLOB_APPEND	0x0001	/* Append to output from previous call.		*/
#define GLOB_DOOFFS	0x0002	/* Use gl_offs.					*/
#define GLOB_ERR	0x0004	/* Return on error.				*/
#define GLOB_MARK	0x0008	/* Append / to matching directories.		*/
#define GLOB_NOCHECK	0x0010	/* Return pattern itself if nothing matches.	*/
#define GLOB_NOSORT	0x0020	/* Don't sort.					*/
#define GLOB_MAGCHAR	0x0100	/* Pattern had globbing characters.		*/
#define GLOB_NOSPACE    (-1)    /* Malloc call failed.				*/
#define GLOB_ABEND      (-2)    /* Unignored error.				*/

extern	int	glob(const char *, int, int (*)(const char *, int), glob_t *);
extern	void	globfree(glob_t *);


/* signal.h */
#define	SIGHUP		1
#define	SIGPIPE		13
#define	SIGWINCH	28
#ifndef	NSIG
#define	NSIG		29		/* maximum signal number + 1 */
#endif

typedef	unsigned long	sigset_t;

extern	int	sigaddset(sigset_t *, int);
extern	int	sigemptyset(sigset_t *);


/* stat.h */
#ifndef	S_IFMT
#define	S_IFMT		0770000
#endif
#define	S_IRUSR		0400
#define	S_IWUSR		0200
#define	S_IRGRP		040

#define	S_ISREG(m)	( ((m) & S_IFMT) == S_IFREG )


/* string.h */
extern	char	*strtok_r(char *, const char *, char **);


/* time.h */
#ifndef _TIMESPEC_DEFINED
#define _TIMESPEC_DEFINED       1
struct timespec {
    int tv_sec;
    int tv_nsec;
};
#endif

struct timezone
{
    int tz_minuteswest; 		/* minutes west of Greenwich */
    int tz_dsttime;     		/* type of dst correction */
};

extern	int	gettimeofday(struct timeval *, struct timezone *);


/* unistd.h */
extern	long	pread(fd_t, void *, size_t, off_t);
extern	long	pwrite(fd_t, void *, size_t, off_t);

#endif /* !ULIB_H */
