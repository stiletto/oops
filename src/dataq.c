#include	<errno.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<pthread.h>
#include	<assert.h>
#include	"dataq.h"

int
dataq_init(dataq_t *dq, int size)
{
    assert(size > 0);
    assert(dq != NULL);
    dq->valid = DATAQ_MAGIC;
    dq->q_max = size;
    dq->q_count = 0;
    dq->q_rptr = dq->q_wptr = 0;
    dq->q_enq_waiters = dq->q_deq_waiters = 0;
    pthread_mutex_init(&dq->q_lock, NULL);
    pthread_cond_init(&dq->q_deq_cv, NULL);
    pthread_cond_init(&dq->q_enq_cv, NULL);
    dq->q_ptr = calloc(size, sizeof(dataq_el_t));
    if ( dq->q_ptr == NULL ) {
	pthread_mutex_destroy(&dq->q_lock);
	pthread_cond_destroy(&dq->q_deq_cv);
	pthread_cond_destroy(&dq->q_enq_cv);
	dq->valid = -1;
	return(-1);
    }
    return(0);
}

int
dataq_enqueue(dataq_t *dq, void *data)
{
    if ( dq->valid != DATAQ_MAGIC ) return(EINVAL);
    pthread_mutex_lock(&dq->q_lock);
    while( dq->q_count >= dq->q_max ) {
	/* no free space */
	dq->q_enq_waiters++;
	pthread_cond_wait(&dq->q_enq_cv, &dq->q_lock);
	dq->q_enq_waiters--;
	if ( dq->valid != DATAQ_MAGIC ) {
	    pthread_mutex_unlock(&dq->q_lock);
	    return(EINVAL);
	}
    }
    dq->q_ptr[dq->q_wptr].data = data;
    dq->q_count++;
    dq->q_wptr = (dq->q_wptr + 1)%dq->q_max;
    if ( dq->q_deq_waiters > 0 ) /* if someone wait on dequeue */
	pthread_cond_signal(&dq->q_deq_cv);
    pthread_mutex_unlock(&dq->q_lock);
    return(0);
}

int
dataq_dequeue(dataq_t *dq, void **data)
{
    if ( dq->valid != DATAQ_MAGIC ) return(EINVAL);
    pthread_mutex_lock(&dq->q_lock);
    while( dq->q_count <= 0 ) {
	/* no data avail */
	dq->q_deq_waiters++;
	pthread_cond_wait(&dq->q_deq_cv, &dq->q_lock);
	dq->q_deq_waiters--;
	/* we must dequeue enqueued data even if dataqueue is no longer valid */
    }
    *data = dq->q_ptr[dq->q_rptr].data;
    dq->q_count--;
    dq->q_rptr = (dq->q_rptr + 1)%dq->q_max;
    if ( dq->q_enq_waiters > 0 ) /* if someone wait on enqqueue */
	pthread_cond_signal(&dq->q_enq_cv);
    pthread_mutex_unlock(&dq->q_lock);
    return(0);
}

int
dataq_dequeue_no_wait(dataq_t *dq, void **data)
{
    if ( dq->valid != DATAQ_MAGIC ) return(EINVAL);
    pthread_mutex_lock(&dq->q_lock);
    if ( dq->q_count <= 0 ) {
	pthread_mutex_unlock(&dq->q_lock);
	return(EWOULDBLOCK);
    }
    *data = dq->q_ptr[dq->q_rptr].data;
    dq->q_count--;
    dq->q_rptr = (dq->q_rptr + 1)%dq->q_max;
    if ( dq->q_enq_waiters > 0 ) /* if someone wait on enqqueue */
	pthread_cond_signal(&dq->q_enq_cv);
    pthread_mutex_unlock(&dq->q_lock);
    return(0);
}
