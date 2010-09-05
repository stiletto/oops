/*
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
#include	<ctype.h>
#include	<signal.h>
#include	<locale.h>
#include	<time.h>

#if	defined(SOLARIS)
#include	<thread.h>
#endif

#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>

#include	<netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"



int
list_init(list_t *list)
{
    list->count = 0;
    pthread_mutex_init(&list->lock, NULL);
    list->head.p = list->head.n = &list->head;
    return(0);
}

int
list_add(list_t *list, ll_t *e)
{
ll_t	*last;

/* add this to the tail of the list */
    pthread_mutex_lock(&list->lock);
    last = list->head.p;
    e->n = &list->head ;
    e->p = last ;
    last->n = e ;
    list->head.p = e;
    list->count++;
    pthread_mutex_unlock(&list->lock);
    return(0);
}

int
list_traverse(list_t *list, int (*func)(void*, void*), void *arg)
{
ll_t	*curr;

    pthread_mutex_lock(&list->lock);
    curr = list->head.n;
    while ( curr != &list->head ) {
	switch((*func)(curr, arg)) {
	   case 1:	/* abort scan	*/
		pthread_mutex_unlock(&list->lock);
		return(0);
	   default:
		break;
	}
	curr = curr->n;
    }
    pthread_mutex_unlock(&list->lock);
    return(0);
}
void
list_unlink_item(list_t *list, ll_t *e)
{
    pthread_mutex_lock(&list->lock);
    e->p->n = e->n;
    e->n->p = e->p;
    list->count--;
    pthread_mutex_unlock(&list->lock);
}
