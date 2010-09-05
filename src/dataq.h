/* BeginSourceFile dataq.h */

#include "llt.h"
typedef struct dataq_data {
	ll_t list;
	void *data;
} dataq_data_t;

typedef struct dataq_waiter {
	ll_t list;
	pthread_cond_t cv;
	int wakeup;
} dataq_waiter_t;

typedef struct dataq {
	pthread_mutex_t lock;
	int num_data;
	int num_waiters;
	llh_t data;
	llh_t waiters;
} dataq_t;
extern int dataq_init(dataq_t *ptr);
extern int dataq_enqueue(dataq_t *dataq, void *in);
extern int dataq_dequeue(dataq_t *dataq, void **outptr);
extern int dataq_destroy(dataq_t *dataq);
extern int dataq_dequeue_special(dataq_t *dataq, void **outptr);
/* EndSourceFile */
