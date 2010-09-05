#ifndef llt_h
typedef struct ll {
	struct ll *n;
	struct ll *p;
} ll_t;

typedef struct llh {
	ll_t *front;
	ll_t *back;
} llh_t;

typedef struct list {
	int count;
	pthread_mutex_t lock;
	ll_t head;
} list_t;

#define llt_h
#endif
/* EndSourceFile */
