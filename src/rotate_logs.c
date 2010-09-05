/*
Copyright (C) 1999 Igor Khasilev, igor@paco.net

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
#include	<unistd.h>
#include	<errno.h>
#include	<strings.h>
#include	<stdarg.h>
#include	<netdb.h>
#include	<ctype.h>

#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/socketvar.h>
#include	<sys/resource.h>

#include	<netinet/in.h>

#include	<arpa/inet.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"

void	rotate_file(char * name, FILE **f, int num);

void
rotate_log_file(void)
{
struct	stat	stat;
int		r;

    if ( !logf ) return;
    r = fstat(fileno(logf), &stat);
    if ( !S_ISREG(stat.st_mode) )
	return;
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "rotate_log_file(): Rotate File %s\n", logfile);
    rwl_wrlock(&log_lock);
    rotate_file(logfile,&logf,log_num);
    if ( logf && !logfile_buffered )
	    setbuf(logf, NULL);
    rwl_unlock(&log_lock);
}

void
rotate_accesslog_file(void)
{
struct	stat	stat;
int		r;

    if ( !accesslogf ) return;
    r = fstat(fileno(accesslogf), &stat);
    if ( !S_ISREG(stat.st_mode) )
	return;
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "rotate_accesslog_file(): Rotate File %s\n", accesslog);
    pthread_mutex_lock(&accesslog_lock);
    rotate_file(accesslog,&accesslogf,accesslog_num);
    if ( accesslogf && !accesslog_buffered )
	setbuf(accesslogf, NULL);
    pthread_mutex_unlock(&accesslog_lock);
}
void*
rotate_logs(void *arg)
{
/* rotate log and accesslog files if need */
struct stat	statb;
int		r;

    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "rotate_logs(): Log rotator started.\n");
    while( 1 ) {
	RDLOCK_CONFIG ;
	if ( logf && log_num ) {
	    r = fstat(fileno(logf), &statb) ;
	    if ( !r && (statb.st_mode & S_IFREG) && log_size && (ftell(logf) > log_size) ) {
		my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "rotate_logs(): r: %d, statb.st_mode: %x, log_size: %d, ftell: %d\n",
	    		r, statb.st_mode, log_size, ftell(logf));
		rotate_log_file();
	    } else {
		my_xlog(LOG_DBG|LOG_INFORM, "rotate_logs(): r: %d, statb.st_mode: %x, log_size: %d, ftell: %d\n",
	    		r, statb.st_mode, log_size, ftell(logf));
		my_xlog(LOG_DBG|LOG_INFORM, "rotate_logs(): No need to rotate %s\n", logfile);
	    }
	}
	if ( accesslogf && accesslog_num ) {
	    r = fstat(fileno(accesslogf), &statb) ;
	    if ( !r && (statb.st_mode & S_IFREG) && accesslog_size && (ftell(accesslogf) > accesslog_size) ) {
		my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "rotate_logs(): r: %d, statb.st_mode: %x, log_size: %d, ftell: %d\n",
	    		r, statb.st_mode, accesslog_size, ftell(accesslogf));
		rotate_accesslog_file();
	    } else {
		my_xlog(LOG_DBG|LOG_INFORM, "rotate_logs(): r: %d, statb.st_mode: %x, log_size: %d, ftell: %d\n",
	    		r, statb.st_mode, accesslog_size, ftell(accesslogf));
		my_xlog(LOG_DBG|LOG_INFORM, "rotate_logs(): No need to rotate %s\n", accesslog);
	    }
	}
	UNLOCK_CONFIG ;
	my_sleep(30);
    }
}

void
rotate_file(char *name, FILE **f, int num)
{
int	last, i;
char	tname[MAXPATHLEN+16], tname1[MAXPATHLEN+16];

    if ( !num ) {
	/* if no number of logs configured just reopen file */
	fclose(*f);
	*f = fopen(name, "a");
	return;
    }

    /* rename old files */
    last = num - 1;
    sprintf(tname, "%s.%d", name, last);
    unlink(tname);
    /* now rotate */
    for(i=last;i>0;i--) {
	sprintf(tname,  "%s.%d", name, i-1);	/* newer version */
	sprintf(tname1, "%s.%d", name, i);	/* older version */
	unlink(tname1);				/* unlink older	 */
	link(tname, tname1);			/* rename newer to older */
    }
    sprintf(tname1, "%s.0", name);
    unlink(tname1);
    link(name, tname1);
    fclose(*f);
    unlink(name);
    *f = fopen(name, "a");
}
