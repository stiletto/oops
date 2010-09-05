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

#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<stdarg.h>
#include	<string.h>
#include	<strings.h>
#include	<netdb.h>
#include	<unistd.h>
#include	<pwd.h>
#include	<dlfcn.h>
#include	<glob.h>
#include	<ctype.h>
#include	<signal.h>
#include	<locale.h>
#include	<time.h>
#include	<assert.h>
#include	<locale.h>

#if	defined(HAVE_CRYPT_H)
#include	<crypt.h>
#endif
#if	defined(HAVE_GETOPT_H)
#include	<getopt.h>
#elif	!defined(HAVE_GETOPT)
#include	"getopt.h"
#endif

#if	defined(HAVE_ZLIB)
  #include	<zlib.h>
#endif

#if	defined(SOLARIS)
extern		int	getdomainname(char *, int);
#include	<thread.h>
#endif
#include	<pthread.h>
#if	!defined(HAVE_PTHREAD_RWLOCK_INIT)
#include	"rwlock.h"
#endif

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/file.h>
#include	<sys/time.h>
#include	<sys/resource.h>
#include        <sys/un.h>
#include        <sys/wait.h>

#if	defined(_AIX)
#define pthread_sigmask sigthreadmask
#include	<sys/ioctl.h>
#include	<sys/devinfo.h>
#include	<sys/lvdd.h>
extern		int	getdomainname(char *, int);
extern		int	setegid(gid_t);
extern		int	seteuid(uid_t);
#if	defined(_LARGE_FILE_API) && defined(WITH_LARGE_FILES)
#define		O_SUPPL		O_LARGEFILE
#endif	/* _LARGE_FILE_API && WITH_LARGE_FILES */
#else
#if	!defined(TRUE)
#define		TRUE		(1)
#endif
#if	!defined(FALSE)
#define		FALSE		(0)
#endif
#define		O_SUPPL		 0
#endif	/* _AIX */

#if	defined(BSDOS) || defined(FREEBSD)
#include	<sys/disklabel.h>
#include	<sys/ioctl.h>
#include	<sys/stat.h>
#endif

#if	defined(LINUX)
#ifdef		WNOHANG
#undef		WNOHANG
#endif
#ifdef		WUNTRACED
#undef		WUNTRACED
#endif
#include	<sys/ioctl.h>
#include	<sys/mount.h>
#endif

#if	defined(HAVE_POLL) && !defined(LINUX) && !defined(FREEBSD)
#include	<sys/poll.h>
#endif                     

#include	<netinet/in.h>
#if	defined(SOLARIS) || defined(LINUX)
#include	<netinet/tcp.h>
#endif

#include	<arpa/inet.h>

typedef		time_t		utime_t;
typedef		int		fd_t;

#define		CLOSE(so)		close(so)
#define		close_storage(fd)	close(fd)
#define		open_storage(n,m)	open(n,m)
#define		RENAME(o, n)		rename(o, n)
#define		ERRNO			errno
#define		set_errno(e)		/* nothing */

#if	!defined(HAVE_SOCKLEN_T)
#if	defined(_AIX)
typedef		size_t		socklen_t;
#else
typedef		int		socklen_t;
#endif
#endif	/* !HAVE_SOCKLEN_T */

#if	!defined(_PATH_DEVNULL)
#define		_PATH_DEVNULL	"/dev/null"
#endif	/* _PATH_DEVNULL */

#if	!defined(HAVE_SYSERRLIST)
extern	const char	*const sys_errlist[];
extern	const int	sys_nerr;
#endif
