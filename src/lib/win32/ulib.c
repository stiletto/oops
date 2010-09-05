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

#include	"oops.h"

#define		SIGTOMASK(sig)	(1<<((sig) - signal_shift_subtract))
unsigned int	signal_shift_subtract;

#define		FACTOR		(0x19db1ded53ea710LL)
#define		NSPERSEC	10000000LL

extern	int	winsock_shutdown(void);


int
fcntl(int fd, int cmd, ...)
{
va_list		args;
int		arg = 0;
int		res;

    switch(cmd) {
    case F_GETFL:
	res = 0;
	my_xlog(LOG_DBG, "fcntl(F_GETFL): fd = %d, res = %d\n", fd, res);
	goto done;

    case F_SETFL:
	va_start(args, cmd);
	arg = va_arg(args, int);
	va_end(args);

	if (arg & O_NONBLOCK) {
	    unsigned long	nonb = 1;
	    if ( (res = ioctlsocket(fd, FIONBIO, &nonb)) != 0 ) {
		my_xlog(LOG_SEVERE, "fcntl(F_SETFL): ioctlsocket(fd = %d, O_NONBLOCK): res = %d, nonb = %d, %m\n",
			fd, res, nonb);
		res = -1;
		goto done;
	    }
	    my_xlog(LOG_DBG, "fcntl(F_SETFL): ioctlsocket(fd = %d, O_NONBLOCK): res = %d, nonb = %d\n",
		    fd, res, nonb);
	    goto done;
	}
	if (arg & O_BLOCK) {
	    unsigned long	nonb = 0;
	    if ( (res = ioctlsocket(fd, FIONBIO, &nonb)) != 0 ) {
		my_xlog(LOG_SEVERE, "fcntl(F_SETFL): ioctlsocket(fd = %d, O_BLOCK): res = %d, nonb = %d, %m\n",
			fd, res, nonb);
		res = -1;
		goto done;
	    }
	    my_xlog(LOG_DBG, "fcntl(F_SETFL): ioctlsocket(fd = %d, O_BLOCK): res = %d, nonb = %d\n",
		    fd, res, nonb);
	    goto done;
	}
	set_errno(ERROR_NOT_SUPPORTED);
	res = -1;
	my_xlog(LOG_DBG, "fcntl(F_SETFL): ioctlsocket(fd = %d, %d): res = %d, %m\n",
		fd, arg, res);
	goto done;

    default:
	set_errno(ERROR_NOT_SUPPORTED);
	res = -1;
	my_xlog(LOG_DBG, "fcntl(%d): fd = %d, res = %d, %m\n", cmd, fd, res);
	goto done;
    }

done:

    return res;
}

void *
dlopen(const char *name, int flags)
{
void	*rc = 0;

    if (!name)
	rc = (void *)GetModuleHandle(0);
    else
	rc = (void *)LoadLibrary(name);

    return rc;
}

void *
dlsym(void *handle, const char *name)
{
void	*rc = (void *)GetProcAddress((HMODULE)handle, name);

    return rc;
}

int
dlclose(void *handle)
{
int	rc = -1;

    if ( FreeLibrary((HMODULE)handle) )
	rc = 0;

    return rc;
}

char *
dlerror()
{
static char	errbuf[256];

    return(STRERROR_R(ERRNO, errbuf, sizeof(errbuf)-1));
}

int
gettimeofday(struct timeval *p, struct timezone *z)
{
int		res = 0;

    if ( p != NULL ) {
	SYSTEMTIME		t;
	FILETIME		f;
	long long		x;
	unsigned long long	total;

	GetSystemTime (&t);
	if ( SystemTimeToFileTime(&t, &f) == 0 )
	    res = -1;

	total = ((unsigned long long)f.dwHighDateTime << 32) +
		((unsigned)f.dwLowDateTime);
	total -= FACTOR; total /= (unsigned long long) (NSPERSEC / CLOCKS_PER_SEC);

	x = total;
	x *= (int) (1e6) / CLOCKS_PER_SEC;
	p->tv_usec = x % (long long) (1e6);
	p->tv_sec =  x / (long long) (1e6);
    }

    if (z != NULL) {
	tzset();
	z->tz_minuteswest = _timezone / 60;
	z->tz_dsttime = _daylight;
    }

    return res;
}

static void
g_Ctoc(const char *str, char *buf)
{
char	*dc;

    for (dc = buf; (*dc++ = *str++) != '\0';)
	continue;
}

static int
globextend(const char *path, glob_t *pglob)
{
char		**pathv;
int		i;
u_int		newsize;
char		*copy;
const char	*p;

    newsize = sizeof(*pathv) * (2 + pglob->gl_pathc + pglob->gl_offs);
    pathv = pglob->gl_pathv ?
		realloc((char *)pglob->gl_pathv, newsize) :
		malloc(newsize);
    if ( pathv == NULL )
	return(GLOB_NOSPACE);

    if ( pglob->gl_pathv == NULL && pglob->gl_offs > 0 ) {
	pathv += pglob->gl_offs;
	for (i = pglob->gl_offs; --i >= 0; )
	    *--pathv = NULL;
    }
    pglob->gl_pathv = pathv;

    for (p = path; *p++;)
	continue;
    if ( (copy = malloc(p - path) ) != NULL ) {
	g_Ctoc(path, copy);
	pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
    }
    pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;
    return(copy == NULL ? GLOB_NOSPACE : 0);
}

int
glob(const char *pattern, int flags,
     int (*errfunc)(const char *, int), glob_t *pglob)
{
HANDLE			fHandle;
WIN32_FIND_DATA		fData;
int			l, rc;
char			fullpath[MAX_PATH+1], *p;

    pglob->gl_pathc  = 0;
    pglob->gl_pathv  = NULL;
    pglob->gl_offs   = 0;
    pglob->gl_matchc = 0;

    if ( (p = strrchr(pattern, '/')) != 0 ) {
	char	*n = fullpath;

	l = p - pattern + 1;
	strncpy(fullpath, pattern, l);
/*
	for(;*n;*n++ ) if ( *n == '/' ) *n = '\\';
*/
    }

    if ( (fHandle = FindFirstFile(pattern, &fData)) == INVALID_HANDLE_VALUE )
	return(GLOB_ERR);

    if ( globextend(strncat(fullpath,
			    fData.cFileName,
			    MAX_PATH-strlen(fullpath)),
			    pglob) ) {
	rc = GLOB_NOSPACE;
	goto done;
    }

    *(fullpath + l) = '\0';

    forever() {
	if ( (FindNextFile(fHandle, &fData) == 0) ||
	     (ERRNO == ERROR_NO_MORE_FILES) ) {
	    rc = 0;
	    goto done;
	}

	if ( globextend(strncat(fullpath,
				fData.cFileName,
				MAX_PATH-strlen(fullpath)),
				pglob) ) {
	    rc = GLOB_NOSPACE;
	    goto done;
	}

	*(fullpath + l) = '\0';
    }

done:
    FindClose(fHandle);
    return(rc);
}

void
globfree(glob_t *pglob)
{
int	i;
char	**pp;

    if ( pglob->gl_pathv != NULL ) {
	pp = pglob->gl_pathv + pglob->gl_offs;
	for (i = pglob->gl_pathc; i--; ++pp)
	    if ( *pp ) free(*pp);
	free(pglob->gl_pathv);
    }
}

BOOL WINAPI
KillHandler(DWORD dwCtrlType)
{
extern	int	killed;

    killed = 1;
    winsock_shutdown();
    return(TRUE);
}

HANDLE
open_storage(const char *path, int oflag, /* mode_t mode */...)
{
HANDLE			fHandle;
DWORD			DesiredAccess = 0;
SECURITY_ATTRIBUTES	SecurityAttributes;
DWORD			CreationDistribution = OPEN_EXISTING;

    if ( oflag & O_CREAT )
	CreationDistribution = OPEN_ALWAYS;

    if ( oflag & O_RDONLY )
	DesiredAccess = GENERIC_READ;

    if ( oflag & O_RDWR )
	DesiredAccess = GENERIC_READ|GENERIC_WRITE;

    SecurityAttributes.lpSecurityDescriptor = NULL;
    SecurityAttributes.bInheritHandle	    = TRUE;

    if ( (fHandle = CreateFile(path,
			       DesiredAccess,
			       FILE_SHARE_READ|FILE_SHARE_WRITE,
			       &SecurityAttributes,
			       CreationDistribution,
			       FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED,
/*			       FILE_FLAG_WRITE_THROUGH,*/
/*			       FILE_FLAG_NO_BUFFERING  */
/*			       FILE_FLAG_RANDOM_ACCESS */
			       NULL)) == INVALID_HANDLE_VALUE ) {
	my_xlog(LOG_SEVERE, "open_storage(): CreateFile(): ERRNO = (%d): %m\n", ERRNO);
	return((HANDLE)-1);
    }

    return(fHandle);
}

long
pread(HANDLE fh, void *buf, size_t nbyte, off_t offset)
{
DWORD		NumberOfBytesRead;
OVERLAPPED	Overlapped;

    if ( nbyte == 0 ) return 0;

    Overlapped.Offset     = offset;
    Overlapped.OffsetHigh = 0;
    Overlapped.hEvent     = NULL;

    if ( ReadFile(fh, buf, (DWORD)nbyte,
		  &NumberOfBytesRead, &Overlapped) == 0 ) {
	if ( ERRNO == ERROR_IO_PENDING ) {
	    if ( GetOverlappedResult(fh, &Overlapped,
				     &NumberOfBytesRead, TRUE) == 0 )
		goto err;
	} else
	    goto err;

    }

done:
    set_errno(0);
    return(NumberOfBytesRead);

err:
    if ( ERRNO == ERROR_HANDLE_EOF )
	goto done;

    my_xlog(LOG_SEVERE, "pread(): ReadFile(): ERRNO = (%d): %m\n", ERRNO);
    return(-1);
}

long
pwrite(HANDLE fh, void *buf, size_t nbyte, off_t offset)
{
DWORD		NumberOfBytesWrite;
OVERLAPPED	Overlapped;

    Overlapped.Offset     = offset;
    Overlapped.OffsetHigh = 0;
    Overlapped.hEvent     = NULL;

    if ( WriteFile((HANDLE)fh, buf, (DWORD)nbyte,
		  &NumberOfBytesWrite, &Overlapped) == 0 ) {
	if ( ERRNO == ERROR_IO_PENDING ) {
	    if ( GetOverlappedResult(fh, &Overlapped,
				     &NumberOfBytesWrite, TRUE) == 0 )
		goto err;
	} else
	    goto err;
    }

done:
    set_errno(0);
    return(NumberOfBytesWrite);

err:
    my_xlog(LOG_SEVERE, "pwrite(): WriteFile(): ERRNO = (%d): %m\n", ERRNO);
    return(-1);
}

int
sigaddset(sigset_t *set, int sig)
{
    if (sig <= 0 || sig >= NSIG) {
	/* errno = EINVAL; */
	return -1;
    }

    *set |= SIGTOMASK(sig);
    return 0;
}

int
sigemptyset(sigset_t *set)
{
    *set = (sigset_t) 0;
    return 0;
}

int
strerror_r(int err, char *errbuf, size_t lerrbuf)
{
LPTSTR	lpszMsgBuf = NULL;
char	b[80];

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		  FORMAT_MESSAGE_FROM_SYSTEM |
		  FORMAT_MESSAGE_IGNORE_INSERTS,
		  NULL, (DWORD)err,
		  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&lpszMsgBuf, 0, NULL);

    if ( lpszMsgBuf == NULL ) {
	sprintf(b, "Error: (%d)", err);
	if ( lerrbuf > 0 ) strncpy(errbuf, b, lerrbuf-1);
	return(-1);

    }

    strncpy(errbuf, lpszMsgBuf, MIN(lerrbuf-1, strlen(lpszMsgBuf)-1));
    LocalFree(lpszMsgBuf);
    return(0);
}

int
winsock_init(void)
{
WORD	wVersionRequested;
WSADATA	wsaData;
int	rc;

    wVersionRequested = MAKEWORD(2, 0);
    if ( (rc = WSAStartup(wVersionRequested, &wsaData)) != 0 ) {
	my_xlog(LOG_SEVERE, "winsock_init(): Can't init WinSock environment: %d", rc);
	return(-1);
    }

    if ( LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
	 HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested) ) {
	my_xlog(LOG_SEVERE, "winsock_init(): Current WinSock version is %d.%d. Version %d.%d required.",
		LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion),
		LOBYTE(wVersionRequested), HIBYTE(wVersionRequested));
	WSACleanup();
	return(-1);
    }

    my_xlog(LOG_PRINT, "winsock_init(): %s %s\n",
	    wsaData.szDescription, wsaData.szSystemStatus);

    return(0);
}

int
winsock_shutdown(void)
{
int	rc;

    if ( (rc = WSACleanup()) != 0 ) {
	my_xlog(LOG_SEVERE, "winsock_shutdown(): Can't shutdown WinSock environment: %d\n", rc);
	return(-1);
    }
    return(0);
}

int
yywrap(void)
{
    return(1);
}
