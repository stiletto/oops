#define	NDEBUG

/* BeginSourceFile hash.c */

#include <pthread.h>
#include "hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
static int
hash_check(hash_t *ptr)									/* call while lock is held! */
{
	int i, count1, count2;
	hash_entry_t *tmp;

	count1 = 0;
	for (i = 0; i < ptr->size; i++) {
		tmp = ptr->table[i];
		while (tmp) {
			int waiters = ll_check(&tmp->waiters);
			assert(waiters == tmp->num_waiters);
			count1++;
			tmp = tmp->next_entry;
		}
	}
	tmp = ptr->start;
	count2 = 0;
	if (tmp) {
		count2++;
		assert(tmp->right_entry == NULL);
		tmp = tmp->left_entry;
	}
	while (tmp) {
		if (tmp->left_entry != NULL)
			assert(tmp->left_entry->right_entry == tmp);
		count2++;
		tmp = tmp->left_entry;
	}
	assert(count2 == count1);
	return (1);
}
static unsigned
hash_string(char *s)
{
	unsigned result = 0;

	while (*s)
		result += (result << 3) + *s++;
	return (result);
}
hash_t *
hash_make(int size, int key_type)
{
	hash_t *ptr;

	ptr = (hash_t *) malloc(sizeof (*ptr));
	ptr->size = size;
	ptr->table = (hash_entry_t **)
					malloc((size_t)(sizeof (hash_entry_t *) * size));
	ptr->start = NULL;
	ptr->hash_type = key_type;
	ptr->lock_status = 0;
	ptr->get_wait_count = 0;
	ptr->operator_wait_count = 0;
	(void) memset((void *) ptr->table, (char) 0,
		  sizeof (hash_entry_t *) * size);
	pthread_mutex_init(&ptr->lock, NULL);
	pthread_cond_init(&ptr->operate_cv, NULL);
	pthread_cond_init(&ptr->get_cv, NULL);
	assert((pthread_mutex_lock(&ptr->lock) == 0) &&
		  (hash_check(ptr) == 1) &&
		  (pthread_mutex_unlock(&ptr->lock) == 0));
	return (ptr);
}
void **
hash_get(hash_t *tbl, char *key)
{
	unsigned int sig;
	unsigned int bucket;
	hash_entry_t *tmp;
	hash_entry_t *new;

	if (tbl->hash_type == STRING_HASH_KEY)
		bucket = (sig = hash_string(key)) % tbl->size;
	else
		bucket = (sig = (unsigned int) key) % tbl->size;
	pthread_mutex_lock(&tbl->lock);
	assert(hash_check(tbl));
	while (tbl->operator_wait_count || tbl->lock_status < 0) {
		tbl->get_wait_count++;
		pthread_cond_wait(&tbl->get_cv, &tbl->lock);
		tbl->get_wait_count--;
	}
	tmp = tbl->table[bucket];
	if (tbl->hash_type == STRING_HASH_KEY)
		while (tmp != NULL) {
			if ((tmp->hash_signature == sig) &&
			   (strcmp(tmp->key, key) == 0))
				break;
			tmp = tmp->next_entry;
		} else {
			while (tmp != NULL) {
				if (tmp->key == key)
					break;
				tmp = tmp->next_entry;
			}
		}
	if (tmp) {
		if (tmp->num_waiters || (tmp->status & ENTRY_LOCKED)) {
			hash_waiter_t wait;
			hash_waiter_t *tst;

			wait.wakeup = 0;
			wait.entry = tmp;
			pthread_cond_init(&wait.cv, NULL);
			tmp->num_waiters++;
			ll_enqueue(&tmp->waiters, &wait.list);

			while (wait.wakeup == 0) {
				pthread_cond_wait(&wait.cv, &tbl->lock);
			}

			tst = (hash_waiter_t *)ll_dequeue(&tmp->waiters);
			assert(tst == &wait);
			tmp->num_waiters--;
			pthread_cond_destroy(&wait.cv);
		}
		tbl->lock_status++;
		tmp->status |= ENTRY_LOCKED;
		tmp->holder = pthread_self();
		assert(hash_check(tbl));
		pthread_mutex_unlock(&tbl->lock);
		return (&tmp->data);
	}
	/* not found. insert new entry into bucket. */
	new = (hash_entry_t *) malloc(sizeof (*new));
	new->key = ((tbl->hash_type == STRING_HASH_KEY)?
					strdup(key): key);
	new->hash_signature = sig;
	/* hook into chain from tbl */
	new->right_entry = NULL;
	if ((new->left_entry = tbl->start) != NULL) {
		assert(tbl->start->right_entry == NULL);
		tbl->start->right_entry = new;
	}
	tbl->start = new;
	/* hook into bucket chain */
	new->next_entry = tbl->table[bucket];
	tbl->table[bucket] = new;
	new->data = NULL;								/* so we know that it is new */
	new->status = ENTRY_LOCKED;
	new->holder = pthread_self();
	new->num_waiters = 0;
	ll_init(&new->waiters);
	tbl->lock_status++;
	assert(hash_check(tbl));
	pthread_mutex_unlock(&tbl->lock);
	return (&new->data);
}
void **
hash_find(hash_t *tbl, char *key)
{
	hash_entry_t *tmp;
	unsigned int sig;

	if (tbl->hash_type == STRING_HASH_KEY)
		sig = hash_string(key);
	else
		sig = (unsigned int) key;
	pthread_mutex_lock(&tbl->lock);
	assert(hash_check(tbl));
	while (tbl->operator_wait_count || tbl->lock_status < 0) {
		tbl->get_wait_count++;
		pthread_cond_wait(&tbl->get_cv, &tbl->lock);
		tbl->get_wait_count--;
	}
	tmp = tbl->table[ sig % tbl->size];
	if (tbl->hash_type == STRING_HASH_KEY) {
		for ( ;tmp != NULL; tmp = tmp->next_entry) {
			if (sig == tmp->hash_signature && strcmp(tmp->key, key) == 0)
				break;
		}
	} else {
		for (; tmp != NULL; tmp = tmp->next_entry) {
			if (tmp->key == key)
				break;
		}
	}
	if (tmp) {
		if (tmp->num_waiters || (tmp->status & ENTRY_LOCKED)) {
			hash_waiter_t wait;

			wait.wakeup = 0;
			wait.entry = tmp;
			pthread_cond_init(&wait.cv, NULL);
			tmp->num_waiters++;
			ll_enqueue(&tmp->waiters, &wait.list);
			while (wait.wakeup == 0)
				pthread_cond_wait(&wait.cv, &tbl->lock);
			tmp->num_waiters--;
			ll_dequeue(&tmp->waiters);
			pthread_cond_destroy(&wait.cv);
		}
		tmp->status |= ENTRY_LOCKED;
		tmp->holder = pthread_self();
		tbl->lock_status++;
		assert(hash_check(tbl));
		pthread_mutex_unlock(&tbl->lock);
		return (&tmp->data);
	}
	assert(hash_check(tbl));
	pthread_mutex_unlock(&tbl->lock);
	return (NULL);
}
int
hash_release(hash_t *tbl, void **data)
{
	hash_entry_t *tmp = (hash_entry_t *)data;
	hash_waiter_t *sleeper = NULL;
	int op_wait;

	pthread_mutex_lock(&tbl->lock);
	assert(hash_check(tbl));
	assert(tbl->lock_status > 0);
	assert(tmp->status & ENTRY_LOCKED);
	assert(tmp->holder == pthread_self());
	tmp->holder = 0;
	tmp->status &= ~ENTRY_LOCKED;
	tbl->lock_status--;
	op_wait = (tbl->operator_wait_count && tbl->lock_status == 0);
	if (tmp->num_waiters) {
		sleeper = (hash_waiter_t *) ll_peek(&tmp->waiters);
		sleeper->wakeup = 0xdeadbeef;
	}
	assert(hash_check(tbl));
	pthread_mutex_unlock(&tbl->lock);
	if (op_wait)
		pthread_cond_broadcast(&tbl->operate_cv);
	if (sleeper)
		pthread_cond_signal(&sleeper->cv);
	return (0);
}
void *
hash_delete(hash_t *tbl, void **dataptr)
{
	hash_waiter_t *sleeper = NULL;
	hash_entry_t *act, *tmp, **prev;
	unsigned int sig;
	char *old;
	int bucket;
	int op_wait;

	act = (hash_entry_t *) dataptr;
	pthread_mutex_lock(&tbl->lock);

	assert(hash_check(tbl));
	assert(act->status & ENTRY_LOCKED);
	assert(act->holder == pthread_self());
	if (tbl->hash_type == STRING_HASH_KEY)
		sig = hash_string(act->key);
	else
		sig = (unsigned int) act->key;
	tmp = tbl->table[ bucket = sig % tbl->size];
	prev = tbl->table + bucket;
	for (; tmp != NULL; tmp = tmp->next_entry) {
		if (tmp == act)
			break;
		prev = &tmp->next_entry;
	}
	assert(tmp != NULL);
	old = tmp->data;
	tbl->lock_status--;
	op_wait = (tbl->operator_wait_count && tbl->lock_status == 0);
	if (tmp->num_waiters) {							/* others are waiting so keep entry here */
		tmp->holder = 0;
		if (tmp->num_waiters) {
			sleeper = (hash_waiter_t *) ll_peek(&tmp->waiters);
			sleeper->wakeup = 0xbadbeef;
			tmp->data = NULL;
			tmp->status &= ~ENTRY_LOCKED;
			tmp->holder = 0;
			tmp = NULL;						/* so we don't free it later */
		}
	} else {
		hash_entry_t *r, *l;
		/*
		 * tmp now points to entry marked for deletion, prev to address
		 * of storage of next pointer pointing to tmp.
		 * remove from bucket chain first.
		 */
		assert(hash_check(tbl));
		if (tbl->hash_type == STRING_HASH_KEY)
			free(tmp->key);
		*prev = tmp->next_entry;
		/* now remove from dbly linked tbl chain */
		r = tmp->right_entry;
		l = tmp->left_entry;
		if (r != NULL)
			r->left_entry = l;
		else
			tbl->start = l;
		if (l != NULL)
			l->right_entry = r;
		assert(hash_check(tbl));
	}
	assert(hash_check(tbl));
	pthread_mutex_unlock(&tbl->lock);
	if (tmp)
		free(tmp);
	if (op_wait)
		pthread_cond_broadcast(&tbl->operate_cv);
	if (sleeper)
		pthread_cond_signal(&sleeper->cv);
	return (old);
}
int
hash_operate(hash_t *tbl,
	void (*ptr)(void *, void *, void *),void *usr_arg)
{
	hash_entry_t *tmp;
	int c = 0;
	int sleepers;

	pthread_mutex_lock(&tbl->lock);
	while (tbl->lock_status != 0) {
		tbl->operator_wait_count++;
		pthread_cond_wait(&tbl->operate_cv, &tbl->lock);
		tbl->operator_wait_count--;
	}
	tmp = tbl->start;
	while (tmp) {
		(*ptr)(tmp->data,usr_arg, tmp->key);
		tmp = tmp->left_entry;
		c++;
	}
	if (tbl->get_wait_count)
		pthread_cond_broadcast(&tbl->get_cv);
	pthread_mutex_unlock(&tbl->lock);
	return (c);
}
/* EndSourceFile */

/* Warning: this must be called with hash locked on higher level !!!! */
void
hash_destroy(hash_t *tbl, void (*ptr)(void*) )
{
	hash_entry_t *tmp, *next;
	int c = 0;
	int sleepers;

	pthread_mutex_lock(&tbl->lock);
	while (tbl->lock_status != 0) {
		tbl->operator_wait_count++;
		pthread_cond_wait(&tbl->operate_cv, &tbl->lock);
		tbl->operator_wait_count--;
	}
	tmp = tbl->start;
	while (tmp) {
		next = tmp->left_entry;
		if ( ptr ) (*ptr)(tmp->data);
		if ( (tbl->hash_type == STRING_HASH_KEY) && tmp->key )
		    free(tmp->key);
		free(tmp);
		tmp = next;
		c++;
	}
	if (tbl->get_wait_count)
		pthread_cond_broadcast(&tbl->get_cv);
	pthread_mutex_unlock(&tbl->lock);
	pthread_mutex_destroy(&tbl->lock);
	pthread_cond_destroy(&tbl->operate_cv);
	pthread_cond_destroy(&tbl->get_cv);
	if ( tbl->table) free(tbl->table);
	free(tbl);
	return;
}
