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

#include	<pthread.h>
#include        <sys/param.h>
#include        <sys/socket.h>
#include        <sys/types.h>
#include        <sys/stat.h>
#include        <sys/file.h>
#include        <sys/time.h>

#include        <netinet/in.h>

#include	<db.h>

#include	"oops.h"


int
readn(int so, char* buf, int len, int tmo)
{
int		to_read = len, sr, readed = 0, got;
char		*p = buf;
time_t		start, now;
struct	pollarg	pa;

	if ( so < 0 ) return(0);
	if ( len <= 0 ) return(0);
	start = time(NULL);
rl1:
	now = time(NULL);
	pa.fd = so;
	pa.request = FD_POLL_RD;
	sr = poll_descriptors(1, &pa, (tmo - (start-now))*1000);
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
struct	pollarg	pollarg;

	if ( so < 0 ) return(0);
	if ( len <= 0 ) return(0);

	pollarg.fd = so;
	pollarg.request = FD_POLL_RD;
	sr = poll_descriptors(1, &pollarg, tmo*1000);
	if ( sr < 0 ) {
		if ( errno == EINTR ) return(readed);
		return(sr);
	}
	if ( sr == 0 ) {
		/* timeout */
		return(-2);
	}
	/* have somethng to read	*/
	got = recv(so, p, to_read, 0);
	return(got);
}

int
wait_for_read(int so, int tmo_m)
{
struct	timeval tv;
int		sr;
struct	pollarg	pollarg;

	if ( so < 0 ) return(FALSE);
	tv.tv_sec  =  tmo_m/1000;
	tv.tv_usec = (tmo_m*1000)%1000000;
	pollarg.fd = so;
	pollarg.request = FD_POLL_RD;
	sr = poll_descriptors(1, &pollarg, tmo_m);
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
    return(writet(so, str, strlen(str), READ_ANSW_TIMEOUT));
}

int
writet(int so, char* buf, int len, int tmo)
{
int		to_write = len, sr, got, sent=0;
char		*p = buf;
struct	timeval tv;
time_t		start, now;
struct pollarg	pollarg;

    if ( so < 0 ) return(-1);
    if ( len <= 0 ) return(0);
    now = start = global_sec_timer;

    while(to_write > 0) {
	if ( now - start > tmo )
		return(-1);
	tv.tv_sec  = tmo - (start-now);
	tv.tv_usec = 0;
	pollarg.fd = so;
	pollarg.request = FD_POLL_WR;
	sr = poll_descriptors(1, &pollarg, (tmo - (start-now))*1000);
	if ( sr < 0 ) {
	    return(sr);
	}
	if ( sr == 0 ) {
	   /* timeot */
	   return(-1);
	}
	/* have somethng to write	*/
	got = send(so, p, to_write, 0);
	if ( got > 0 ) {
	    to_write -= got;
	    sent += got;
	    if ( to_write>0 ) {
	        p += got;
	        now = global_sec_timer;
	        continue;
	    }
	    return(sent);
	}
	return(got);
    }
    return(0);
}

int
writet_cv_cs(int so, char* buf, int len, int tmo, char *table, int escapes)
{
int		to_write = len, sr, got, sent=0;
char		*p, *recoded = NULL, *d;
struct	timeval tv;
time_t		start, now;
struct pollarg	pollarg;
u_char		*s;

    if ( so < 0 ) return(-1);
    if ( len <= 0 ) return(0);
    recoded = malloc(len);
    if ( !recoded )
	return(-1);
    s = (u_char*)buf; d = recoded;
    while ( (s-(u_char*)buf) < len ) {
	u_char	c, cd;
	if ( escapes && (*s == '%' && isxdigit(*(s+1)) && isxdigit(*(s+2))) ) {
	    if ( isdigit(*(s+1)) ) {
		c = 16 * (*(s+1)-'0');
	    } else
		c = 16 * (toupper(*(s+1)) - 'A' + 10 );
	    if ( isdigit(*(s+2)) ) {
		c += (*(s+2)-'0');
	    } else
		c += (toupper(*(s+2)) - 'A' + 10 );
	    if ( c >= 128 ) {
		cd = table[c-128];
		s += 3;
		*d = '%';
		sprintf(d, "%%%02X", cd);
		d+=3;
	    } else {
		s += 3;
		*d = '%';
		sprintf(d, "%%%02X", c);
		d+=3;
	    }
	    continue;
	}
	if ( *s > 128 )
	    *d = table[(*s)-128];
	  else
	    *d = *s;
	s++;d++;
    }
    p = recoded;
    now = start = global_sec_timer;

    while(to_write > 0) {
	if ( now - start > tmo ) {
	    free(recoded);
	    return(-1);
	}
	tv.tv_sec  = tmo - (start-now);
	tv.tv_usec = 0;
	pollarg.fd = so;
	pollarg.request = FD_POLL_WR;
	sr = poll_descriptors(1, &pollarg, (tmo - (start-now))*1000);
	if ( sr < 0 ) {
	    free(recoded);
	    return(sr);
	}
	if ( sr == 0 ) {
	   /* timeot */
	    free(recoded);
	    return(-1);
	}
	/* have somethng to write	*/
	got = send(so, p, to_write, 0);
	if ( got > 0 ) {
	    to_write -= got;
	    sent += got;
	    if ( to_write>0 ) {
	        p += got;
	        now = global_sec_timer;
	        continue;
	    }
	    free(recoded);
	    return(sent);
	}
	free(recoded);
	return(got);
    }
    free(recoded);
    return(0);
}

