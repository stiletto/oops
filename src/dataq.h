#if	!defined(DATAQ_H_INCLUDED)
#define DATAQ_H_INCLUDED

#define	DATAQ_MAGIC	0x0000ABBA

typedef	struct	dataq_el_ {
    void	*data;
} dataq_el_t;

typedef	struct	dataq_ {
    int			valid;
    int			q_max;
    pthread_mutex_t	q_lock;
    pthread_cond_t	q_enq_cv;	/* to wait for enqueue 	*/
    pthread_cond_t	q_deq_cv;	/* to wait for dequeue 	*/
    int			q_count;	/* total data in queue 	*/
    dataq_el_t		*q_ptr;
    int			q_rptr;		/* reqd pinter		*/
    int			q_wptr;		/* write pointer	*/
    int			q_enq_waiters;	/* waiters to enqueue	*/
    int			q_deq_waiters;	/* ---"--- to dequeue	*/
} dataq_t, *dataq_ptr;

extern	int dataq_init(dataq_t* dq, int size);
extern	int dataq_destroy(dataq_t *dq);
extern	int dataq_enqueue(dataq_t *dq, void *);
extern	int dataq_dequeue(dataq_t *dq, void **);
extern	int dataq_dequeue_no_wait(dataq_t *dq, void **);
#endif
