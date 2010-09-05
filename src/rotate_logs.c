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

static	void	rotate_file(char * name, FILE **f, int num);

static void
rotate_names(char *name, filebuff_t *fb, int num)
{
int	last, i;
char	tname[MAXPATHLEN+16], tname1[MAXPATHLEN+16];

    if ( fb == NULL || name == NULL ) return;
    if ( !num ) {
	/* if no number of logs configured just reopen file */
	close(fb->fd);
	fb->fd = open(name, O_WRONLY|O_APPEND|O_CREAT, 0660);
	return;

    }

    /* rename old files */
    last = num - 1;
    /* now rotate */
    for(i=last;i>0;i--) {
	snprintf(tname,  sizeof(tname)-1,  "%s.%d", name, i-1);	/* newer version */
	snprintf(tname1, sizeof(tname1)-1, "%s.%d", name, i);	/* older version */
	RENAME(tname, tname1);					/* rename newer to older */
    }
    if ( fb->fd != -1 ) close(fb->fd);
    RENAME(name, tname);
    fb->fd = open(name, O_WRONLY|O_APPEND|O_CREAT, 0660);
}

void
rotate_logbuff(void)
{
struct	stat	stat;
int		r;
filebuff_t 	*fb = &logbuff;

    flushout_fb(fb);
    pthread_mutex_lock(&fb->lock);
    if ( fb->fd != -1 ) {
	r = fstat(fb->fd, &stat);
	if ( !S_ISREG(stat.st_mode) ) {
	    pthread_mutex_unlock(&fb->lock);
	    return;
	}
	rotate_names(logfile, fb, log_num);
	pthread_mutex_unlock(&fb->lock);
	return;
    }
    pthread_mutex_unlock(&fb->lock);
}

void
rotate_accesslogbuff(void)
{
struct	stat	stat;
int		r;
filebuff_t 	*fb = &accesslogbuff;

    flushout_fb(fb);
    pthread_mutex_lock(&fb->lock);
    if ( fb->fd != -1 ) {
	r = fstat(fb->fd, &stat);
	if ( !S_ISREG(stat.st_mode) ) {
	    pthread_mutex_unlock(&fb->lock);
	    return;
	}
	rotate_names(accesslog, fb, accesslog_num);
	pthread_mutex_unlock(&fb->lock);
	return;
    }
    pthread_mutex_unlock(&fb->lock);
}

void *
rotate_logs(void *arg)
{
/* rotate log and accesslog files if need */
struct stat	statb;
int		r;

    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "Log rotator started.\n");
    if ( arg ) return (void *)0;
    forever() {
	RDLOCK_CONFIG ;
	if ( log_num && (logbuff.fd != -1) ) {
	    r = fstat(logbuff.fd, &statb) ;
	    if ( !r && (statb.st_mode & S_IFREG)
	    	    && log_size
	    	    && (lseek(logbuff.fd,0,SEEK_END) > log_size) ) {
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "rotate_logs(): r: %d, statb.st_mode: %x, log_size: %d, ftell: %d\n",
	    		r, statb.st_mode, log_size, lseek(logbuff.fd,0,SEEK_END));
		rotate_logbuff();
	    } else {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "rotate_logs(): r: %d, statb.st_mode: %x, log_size: %d, ftell: %d\n",
	    		r, statb.st_mode, log_size, lseek(logbuff.fd,0,SEEK_END));
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "rotate_logs(): No need to rotate %s\n", logfile);
	    }
	}
	if ( accesslog_num && (accesslogbuff.fd != -1) ) {
	    r = fstat(accesslogbuff.fd, &statb) ;
	    if ( !r && (statb.st_mode & S_IFREG)
		    && accesslog_size
		    && (lseek(accesslogbuff.fd,0,SEEK_END) > accesslog_size) ) {
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "rotate_logs(): r: %d, statb.st_mode: %x, log_size: %d, ftell: %d\n",
	    		r, statb.st_mode, accesslog_size, lseek(accesslogbuff.fd,0,SEEK_END));
		rotate_accesslogbuff();
	    } else {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "rotate_logs(): r: %d, statb.st_mode: %x, log_size: %d, ftell: %d\n",
	    		r, statb.st_mode, accesslog_size, lseek(accesslogbuff.fd,0,SEEK_END));
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "rotate_logs(): No need to rotate %s\n", accesslog);
	    }
	}
	UNLOCK_CONFIG ;
	my_sleep(30);
    }
}

static void
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
    /* now rotate */
    for(i=last;i>0;i--) {
	snprintf(tname,  sizeof(tname)-1,  "%s.%d", name, i-1);	/* newer version */
	snprintf(tname1, sizeof(tname1)-1, "%s.%d", name, i);	/* older version */
	RENAME(tname, tname1);					/* rename newer to older */
    }
    fclose(*f);
    RENAME(name, tname);
    *f = fopen(name, "a");
}
