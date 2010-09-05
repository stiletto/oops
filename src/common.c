/*
	addrd common code for client and sever
	$Id: common.c,v 1.2 1996/11/28 10:24:01 igor Exp igor $
*/

#include	<stdio.h>
#include	<unistd.h>
#include	<errno.h>
#include	<strings.h>
#include	<sys/time.h>
#include	<sys/types.h>


#define		FALSE	0
#define		TRUE	1

int
readn(int so, char* buf, int len, int tmo)
{
int		to_read = len, sr, readed = 0, got;
char		*p = buf;
fd_set		fdr;
struct	timeval tv;
time_t		start, now;

	if ( so < 0 ) return(0);
	if ( len <= 0 ) return(0);
	start = time(NULL);
rl1:
	now = time(NULL);
	FD_ZERO(&fdr);
	FD_SET(so, &fdr);
	tv.tv_sec  = tmo - (start-now);
	tv.tv_usec = 0;
	sr = select(so+1, &fdr, NULL, NULL, &tv);
	if ( sr < 0 ) {
		if ( errno == EINTR ) return(readed);
		return(sr);
	}
	if ( sr == 0 ) {
		/* timeot */
		return(readed);
	}
	/* have somethng to read	*/
	got = read(so, p, to_read);
	if ( got == 0 )
		return(readed);
	if ( got <  0 ) {
		return(got);
	}
	p	+= got;
	readed	+= got;
	to_read -= got;
	if ( to_read == 0 ) return readed;
	goto rl1;
}

/* read with timeout */
int
readt(int so, char* buf, int len, int tmo)
{
int		to_read = len, sr, readed = 0, got;
char		*p = buf;
fd_set		fdr;
struct	timeval tv;

	if ( so < 0 ) return(0);
	if ( len <= 0 ) return(0);

	FD_ZERO(&fdr);
	FD_SET(so, &fdr);
	tv.tv_sec  = tmo;
	tv.tv_usec = 0;
	sr = select(so+1, &fdr, NULL, NULL, &tv);
	if ( sr < 0 ) {
		if ( errno == EINTR ) return(readed);
		return(sr);
	}
	if ( sr == 0 ) {
		/* timeout */
		return(-2);
	}
	/* have somethng to read	*/
	got = read(so, p, to_read);
	return(got);
}

int
wait_for_read(int so, int tmo_m)
{
fd_set		fdr;
struct	timeval tv;
int		sr;

	if ( so < 0 ) return(FALSE);
	FD_ZERO(&fdr);
	FD_SET(so, &fdr);
	tv.tv_sec  =  tmo_m/1000;
	tv.tv_usec = (tmo_m*1000)%1000000;
	sr = select(so+1, &fdr, NULL, NULL, &tv);
	if ( sr <= 0 )
		return(FALSE);
	return(TRUE);
}

int
writen(int so, char* buf, int len)
{
int	towrite = len, written;
char	*p = buf;

	if ( so < 0 ) return(0);

	while (towrite) {
		written = write(so, p, towrite);
		if ( written < 0 ) return(written);
		towrite -= written;
		p += written;
	}
	return(len);
}

int
sendstr(int so, char * str)
{

    if ( so < 0 ) return(0);
    return(writen(so, str, strlen(str)));
}

int
writet(int so, char* buf, int len, int tmo)
{
int		to_write = len, sr, got, sent=0;
char		*p = buf;
fd_set		fdw;
struct	timeval tv;
time_t		start, now;

    if ( so < 0 ) return(-1);
    if ( len <= 0 ) return(0);
    now = start = time(NULL);

    while(to_write > 0) {
	if ( now - start > tmo )
		return(-1);
	FD_ZERO(&fdw);
	FD_SET(so, &fdw);
	tv.tv_sec  = tmo - (start-now);
	tv.tv_usec = 0;
	sr = select(so+1, NULL, &fdw, NULL, &tv);
	if ( sr < 0 ) {
	    return(sr);
	}
	if ( sr == 0 ) {
	   /* timeot */
	   return(-1);
	}
	/* have somethng to write	*/
	got = write(so, p, to_write);
	if ( got > 0 ) {
	    to_write -= got;
	    sent += got;
	    if ( to_write>0 ) {
	        p += got;
	        now = time(NULL);
	        continue;
	    }
	    return(sent);
	}
	return(got);
    }
    return(0);
}

