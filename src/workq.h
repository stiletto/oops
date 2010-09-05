#if     !defined(__WORKQ_INCLUDED__)
#define __WORKQ_INCLUDED__

#include	<time.h>
#include	<pthread.h>

typedef	struct	work_ele_tag	{
    struct	work_ele_tag	*next;
    void			*data;
} workq_ele_t;
 
typedef struct	workq_tag	{
    pthread_mutex_t	mutex;		/* control access to queue	*/
    pthread_cond_t	cv;		/* wait_for_work		*/
    pthread_attr_t	attr;		/* create detached		*/
    workq_ele_t		*first, *last;	/* work queue			*/
    int			valid;		/* valid			*/
    int			quit;		/* workq should quit		*/
    int			parallelism;	/* maximum threads		*/
    int			counter;	/* current threads		*/
    int			idle;		/* idle threads			*/
    void		(*engine)(void *arg);	/* user function	*/
} workq_t;

extern	int workq_init(workq_t *wq, int threads,
 			void (*engine)(void *));
extern	int workq_destroy(workq_t *wq);
extern	int workq_add(workq_t *wq, void *data);

#define	WORKQ_VALID	0x0decca62
#define	IDLE_TIMEOUT	10

#endif
