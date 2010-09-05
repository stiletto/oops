#include        <stdio.h>
#include        <stdlib.h>
#include        <unistd.h>
#include        <errno.h>
#include        <strings.h>
#include        <stdarg.h>
#include        <netdb.h>
#include        <ctype.h>

#include        <sys/stat.h>
#include        <sys/param.h>
#include        <sys/socket.h>
#include        <sys/socketvar.h>
#include        <sys/resource.h>
#include        <fcntl.h>

#include        <netinet/in.h>

#include        <arpa/inet.h>

#include        <pthread.h>

#include        <db.h>

#include        "oops.h"

#include	"dataq.h"

dataq_t	wq;

void
worker(void *arg)
{
work_t		*work;
int		so;
void*		(*processor)(void*);

    arg = arg;
    printf("New worker started\n");

    while(1) {
	dataq_dequeue_special(&wq, (void**)&work);
	so =	    work->so;
	processor = work->f;
	if ( processor ) {
	    (*processor)((void*)work);
	}
	/* work freed by processor */
    }
}
