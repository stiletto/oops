#include	<pthread.h>
#include	<stdlib.h>
#include	<sys/time.h>
#include	<errno.h>

#include	"workq.h"

static	void	*workq_server(void*);

/* init workq */

int workq_init(workq_t *wq, int threads, void (*engine)(void *arg))
{
int	status;

    status = pthread_attr_init(&wq->attr);
    if ( status != 0 ) return(status);
    status = pthread_attr_setdetachstate(&wq->attr, PTHREAD_CREATE_DETACHED);
    if ( status != 0 ) {
	pthread_attr_destroy(&wq->attr);
	return(status);
    }
#if     !defined(__FreeBSD__)
    status = pthread_attr_setscope(&wq->attr, PTHREAD_SCOPE_SYSTEM);
    if ( status != 0 ) {
	pthread_attr_destroy(&wq->attr);
	return(status);
    }
#endif
    status = pthread_mutex_init(&wq->mutex, NULL);
    if ( status != 0 ) {
	pthread_attr_destroy(&wq->attr);
	return(status);
    }
    status = pthread_cond_init(&wq->cv, NULL);
    if ( status != 0 ) {
	pthread_attr_destroy(&wq->attr);
	pthread_mutex_destroy(&wq->mutex);
	return(status);
    }
    wq->quit = 0;
    wq->first = wq->last = NULL;
    wq->parallelism = threads;
    wq->counter = 0;
    wq->idle = 0;
    wq->engine = engine;
    wq->valid = WORKQ_VALID;
    return(0);
}

int workq_destroy(workq_t *wq)
{
int	status, status1, status2;

    if ( wq->valid != WORKQ_VALID )
	return EINVAL;

    status = pthread_mutex_lock(&wq->mutex);
    if ( status != 0 )
	return(status);
    wq->valid = 0;			/* prevent any other operations	*/

    /* 1. set quit flag
       2. broadcast to wakeup any sleeping
       4. wait till all quit
    */
    if ( wq->counter > 0 ) {
	wq->quit = 1;
	if ( wq->idle > 0 ) {
	    status = pthread_cond_broadcast(&wq->cv);
	    if ( status != 0 ) {
	        pthread_mutex_unlock(&wq->mutex);
	        return(status);
	    }
	}
	while ( wq->counter > 0 ) {
	    status = pthread_cond_wait(&wq->cv, &wq->mutex);
	    if ( status != 0 ) {
	        pthread_mutex_unlock(&wq->mutex);
	        return(status);
	    }
	}
    }
    status = pthread_mutex_unlock(&wq->mutex);
    if ( status != 0 )
	return(status);
    status = pthread_mutex_destroy(&wq->mutex);
    status1 = pthread_cond_destroy(&wq->cv);
    status2 = pthread_attr_destroy(&wq->attr);
    return(status?status:(status1?status1:status2));    
}

int workq_add(workq_t *wq, void *element)
{
workq_ele_t	*item;
pthread_t	id;
int		status;

    if ( wq->valid != WORKQ_VALID )
	return(EINVAL);

    item = (workq_ele_t*)malloc(sizeof(workq_ele_t));
    if ( item == NULL )
	return(ENOMEM);
    item->data = element;
    item->next = NULL;
    status = pthread_mutex_lock(&wq->mutex);
    if ( status != 0 ) {
	free(item);
	return(status);
    }

    if ( wq->first == NULL )
	wq->first = item;
    else
	wq->last->next = item;
    wq->last = item;

    if ( wq->idle > 0 ) {
	status = pthread_cond_signal(&wq->cv);
	if ( status != 0 ) {
	    pthread_mutex_unlock(&wq->mutex);
	    return(status);
	}
    } else if ( wq->counter < wq->parallelism ) {
	status = pthread_create(&id, &wq->attr, workq_server, (void*)wq);
	if ( status != 0 ) {
	    pthread_mutex_unlock(&wq->mutex);
	    return(status);
	}
	wq->counter++;
    }
    pthread_mutex_unlock(&wq->mutex);
    return(0);
}

static	void	*workq_server(void* arg)
{
struct	timespec	timeout;
struct  timeval         tv;
workq_t 		*wq = (workq_t*)arg;
workq_ele_t		*we;
int			status, timedout;

    status = pthread_mutex_lock(&wq->mutex);
    if ( status != 0 )
	return(NULL);
    for(;;) {
	timedout = 0;
        gettimeofday(&tv, NULL);
        timeout.tv_sec = tv.tv_sec;
        timeout.tv_nsec = tv.tv_usec*1000;

	timeout.tv_sec += IDLE_TIMEOUT;

	while(wq->first == NULL && !wq->quit ) {
	    wq->idle++;
	    status = pthread_cond_timedwait(&wq->cv, &wq->mutex, &timeout);
	    wq->idle--;
	    if ( status == ETIMEDOUT ) {
		timedout = 1;
		break;
	    } else if ( status != 0 ) {
		wq->counter--;
		pthread_mutex_unlock(&wq->mutex);
		return NULL;
	    }
	}
	we = wq->first;
	if ( we != NULL ) {
	    wq->first = we->next;
	    if ( wq->last == we )
	    	wq->last = NULL;
	    status = pthread_mutex_unlock(&wq->mutex);
	    if ( status != 0 )
	    	return(NULL);
	    wq->engine(we->data);
	    free(we);
	    status = pthread_mutex_lock(&wq->mutex);
	    if ( status != 0 )
	        return(NULL);
	}
	if ( wq->first == NULL && wq->quit ) {
	    wq->counter--;
	    if ( wq->counter == 0 )
		pthread_cond_broadcast(&wq->cv);
	    pthread_mutex_unlock(&wq->mutex);
	    return(NULL);
	}

	if ( wq->first == NULL && timedout ) {
	    wq->counter--;
	    break;
	}
    }
    pthread_mutex_unlock(&wq->mutex);
    return(NULL);
}
