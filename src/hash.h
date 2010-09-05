/* BeginSourceFile hash.h */

#define ENTRY_LOCKED 1
#define STRING_HASH_KEY 0
#define INT_HASH_KEY 1

#include "llt.h"

typedef struct hash_entry {
	void *data;								/* data storage */
	void *key;								/* key (either int or char*) */
	unsigned int hash_signature;								/* speeds up lookups for strings*/
	short status;								/* holds locked bit */
	short num_waiters;								/* number of threads waiting */
	pthread_t holder;								/* for debugging checks */
	llh_t waiters;								/* threads waiting for entry */
	struct hash_entry *next_entry;	/* ptr to next entry in bucket */
	struct hash_entry *right_entry;	/* next entry in master chain */
	struct hash_entry *left_entry;	/* previous entry in master */
} hash_entry_t;
typedef struct hash_waiter {
	ll_t list;								/* list pointer */
	int wakeup;								/* flag for cv */
	hash_entry_t *entry;								/* which entry we're waiting for */
	pthread_cond_t cv;								/* condition variable we block on */
} hash_waiter_t;
typedef struct hash {
	pthread_mutex_t lock;								/* mutext to protect hash table */
	int size;								/* number of buckets */
	int hash_type;								/* 0 == string, else int */
	int operator_wait_count;								/* #threads waiting to op */
	int get_wait_count;								/* #threads waiting to use get */
	int lock_status;								/* -1 op, 0 unused + get count */
	pthread_cond_t operate_cv;								/* waiters for operate */
	pthread_cond_t get_cv;								/* waiters for get during op */
	hash_entry_t **table;								/* buckets */
	hash_entry_t *start;								/* first entry in master chain */
} hash_t;
extern hash_t *hash_make(int size, int key_type);
extern void **hash_get(hash_t *tbl, char *key);
extern void **hash_find(hash_t *tbl, char *key);
extern int hash_release(hash_t *tbl, void **data);
extern void *hash_delete(hash_t *tbl, void **dataptr);
extern int hash_operate(hash_t *tbl, void (*ptr)(void *, void *, void *),
	  void *usr_arg);
/* EndSourceFile hash.h */
