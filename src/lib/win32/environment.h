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

#include	<assert.h>
#include	<ctype.h>
#include	<errno.h>
#include	<fcntl.h>
#include	<io.h>
#include	<locale.h>
#include	<process.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<string.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<time.h>

/* #define		FD_SETSIZE	OPEN_FILES_MAXIMUM */

#include	<winsock2.h>

#include	<sys/stat.h>

#include	"getopt.h"

typedef		long		utime_t;
typedef		HANDLE		fd_t;

#define		O_SUPPL			0

#define		CLOSE(so)		closesocket(so)
#define		close_storage(fd)	CloseHandle(fd)
extern	fd_t	open_storage(const char *, int, /* mode_t */...);
#define		RENAME(o, n)		{ unlink(n); rename(o, n); }
#define		ERRNO			WSAGetLastError()
#define		set_errno(e)		WSASetLastError(e)

#if     !defined(HAVE_SYSERRLIST)
extern  const char      *const sys_errlist[];
extern  const int       sys_nerr;
#endif

#define REGEX_H         <regex.h>

#include	"lib/win32/ulib.h"
#include	"lib/win32/db.h"
#include	"lib/win32/pthread.h"

#define		strcasecmp	stricmp
#define		strncasecmp	strnicmp

#define		socklen_t	int

extern	int	winsock_init(void);
extern	int	winsock_shutdown(void);

#define ctime_r( _clock, _buf ) \
	( strcpy( (_buf), ctime( (_clock) ) ), (_buf) )

#define gmtime_r( _clock, _result ) \
	( *(_result) = *gmtime( (_clock) ), (_result) )

#define localtime_r( _clock, _result ) \
	( *(_result) = *localtime( (_clock) ), (_result) )

#ifndef		MAXPATHLEN
#define		MAXPATHLEN	MAX_PATH
#endif

#if	defined(EAGAIN)
#undef		EAGAIN
#endif
#define		EAGAIN		WSAEWOULDBLOCK

#if	defined(EWOULDBLOCK)
#undef		EWOULDBLOCK
#endif
#define		EWOULDBLOCK	WSAEWOULDBLOCK

#if	defined(EINTR)
#undef		EINTR
#endif
#define		EINTR		WSAEINTR

#if	defined(EINPROGRESS)
#undef		EINPROGRESS
#endif
#define		EINPROGRESS	WSAEINPROGRESS

#define		_PATH_DEVNULL	"nul"

#define		PERR(a)\
	{\
	    if ( ERRNO > 0 )\
		my_xlog(LOG_SEVERE, "%s: ERRNO = (%d)\n", a, ERRNO);\
	}

/*
#define		THREAD_STACK	1024*1024

#define		pthread_create(h, a, f, arg) \
		_beginthread(f, NULL, THREAD_STACK, arg)
*/
