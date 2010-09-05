/* BeginSourceFile llt.h */

#ifndef llt_h
typedef struct ll {
	struct ll *p;
	struct ll *n;
} ll_t;

typedef struct llh {
	ll_t *front;
	ll_t **back;
} llh_t;

typedef struct list {
	int count;
	pthread_mutex_t lock;
	llh_t head;
} list_t;

void ll_init(llh_t *head);
void ll_enqueue(llh_t *head, ll_t *data);
ll_t *ll_peek(llh_t *head);
ll_t *ll_dequeue(llh_t *head);
ll_t *ll_traverse(llh_t *ptr, int (*func)(void *, void *), void *user);
int ll_check(llh_t *head);
#define llt_h
#endif
/* EndSourceFile */
