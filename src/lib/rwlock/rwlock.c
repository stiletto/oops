/*
Copyright (C) 1999, 2000 Igor Khasilev, igor@paco.net
Copyright (C) 2000 Andrey Igoshin, ai@vsu.ru

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

/*-
 * Copyright (c) 1998 Alex Nash
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if	defined(_THREAD_SAFE) || defined(_PTHREADS) || defined(_REENTRANT)

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#include <pthread.h>
#include "rwlock.h"

/* maximum number of times a read lock may be obtained */
#define	MAX_READ_LOCKS		(INT_MAX - 1)

int
pthread_rwlock_destroy (pthread_rwlock_t *rwlock)
{
	int ret;

	if (rwlock == NULL)
		ret = EINVAL;
	else {
		pthread_rwlock_t prwlock;

		prwlock = *rwlock;

		pthread_mutex_destroy(&prwlock->lock);
		pthread_cond_destroy(&prwlock->read_signal);
		pthread_cond_destroy(&prwlock->write_signal);
		free(prwlock);

		*rwlock = NULL;

		ret = 0;
	}

	return(ret);
}

int
pthread_rwlock_init (pthread_rwlock_t *rwlock, const pthread_rwlockattr_t *attr)
{
	pthread_rwlock_t	prwlock;
	int			ret;

	/* allocate rwlock object */
	prwlock = (pthread_rwlock_t)malloc(sizeof(struct pthread_rwlock));

	if (prwlock == NULL)
		return(ENOMEM);

	/* initialize the lock */
	if ((ret = pthread_mutex_init(&prwlock->lock, NULL)) != 0)
		free(prwlock);
	else {
		/* initialize the read condition signal */
		ret = pthread_cond_init(&prwlock->read_signal, NULL);

		if (ret != 0) {
			pthread_mutex_destroy(&prwlock->lock);
			free(prwlock);
		} else {
			/* initialize the write condition signal */
			ret = pthread_cond_init(&prwlock->write_signal, NULL);

			if (ret != 0) {
				pthread_cond_destroy(&prwlock->read_signal);
				pthread_mutex_destroy(&prwlock->lock);
				free(prwlock);
			} else {
				/* success */
				prwlock->state		 = 0;
				prwlock->blocked_writers = 0;

				*rwlock = prwlock;
			}
		}
	}

	return(ret);
}

int
pthread_rwlock_rdlock (pthread_rwlock_t *rwlock)
{
	pthread_rwlock_t 	prwlock;
	int			ret;

	if (rwlock == NULL)
		return(EINVAL);

	prwlock = *rwlock;

	/* check for static initialization */
	if (prwlock == NULL)
		return(EINVAL);

	/* grab the monitor lock */
	if ((ret = pthread_mutex_lock(&prwlock->lock)) != 0)
		return(ret);

	/* give writers priority over readers */
	while (prwlock->blocked_writers || prwlock->state < 0) {
		ret = pthread_cond_wait(&prwlock->read_signal, &prwlock->lock);

		if (ret != 0) {
			/* can't do a whole lot if this fails */
			pthread_mutex_unlock(&prwlock->lock);
			return(ret);
		}
	}

	/* check lock count */
	if (prwlock->state == MAX_READ_LOCKS)
		ret = EAGAIN;
	else
		++prwlock->state; /* indicate we are locked for reading */

	/*
	 * Something is really wrong if this call fails.  Returning
	 * error won't do because we've already obtained the read
	 * lock.  Decrementing 'state' is no good because we probably
	 * don't have the monitor lock.
	 */
	pthread_mutex_unlock(&prwlock->lock);

	return(ret);
}

int
pthread_rwlock_tryrdlock (pthread_rwlock_t *rwlock)
{
	pthread_rwlock_t 	prwlock;
	int			ret;

	if (rwlock == NULL)
		return(EINVAL);

	prwlock = *rwlock;

	/* check for static initialization */
	if (prwlock == NULL)
		return(EINVAL);

	/* grab the monitor lock */
	if ((ret = pthread_mutex_lock(&prwlock->lock)) != 0)
		return(ret);

	/* give writers priority over readers */
	if (prwlock->blocked_writers || prwlock->state < 0)
		ret = EWOULDBLOCK;
	else if (prwlock->state == MAX_READ_LOCKS)
		ret = EAGAIN; /* too many read locks acquired */
	else
		++prwlock->state; /* indicate we are locked for reading */

	/* see the comment on this in pthread_rwlock_rdlock */
	pthread_mutex_unlock(&prwlock->lock);

	return(ret);
}

int
pthread_rwlock_trywrlock (pthread_rwlock_t *rwlock)
{
	pthread_rwlock_t 	prwlock;
	int			ret;

	if (rwlock == NULL)
		return(EINVAL);

	prwlock = *rwlock;

	/* check for static initialization */
	if (prwlock == NULL)
		return(EINVAL);

	/* grab the monitor lock */
	if ((ret = pthread_mutex_lock(&prwlock->lock)) != 0)
		return(ret);

	if (prwlock->state != 0)
		ret = EWOULDBLOCK;
	else
		/* indicate we are locked for writing */
		prwlock->state = -1;

	/* see the comment on this in pthread_rwlock_rdlock */
	pthread_mutex_unlock(&prwlock->lock);

	return(ret);
}

int
pthread_rwlock_unlock (pthread_rwlock_t *rwlock)
{
	pthread_rwlock_t 	prwlock;
	int			ret;

	if (rwlock == NULL)
		return(EINVAL);

	prwlock = *rwlock;

	/* check for static initialization */
	if (prwlock == NULL)
		return(EINVAL);

	/* grab the monitor lock */
	if ((ret = pthread_mutex_lock(&prwlock->lock)) != 0)
		return(ret);

	if (prwlock->state > 0) {
		if (--prwlock->state == 0 && prwlock->blocked_writers)
			ret = pthread_cond_signal(&prwlock->write_signal);
	} else if (prwlock->state < 0) {
		prwlock->state = 0;

		if (prwlock->blocked_writers)
			ret = pthread_cond_signal(&prwlock->write_signal);
		else
			ret = pthread_cond_broadcast(&prwlock->read_signal);
	} else
		ret = EINVAL;

	/* see the comment on this in pthread_rwlock_rdlock */
	pthread_mutex_unlock(&prwlock->lock);

	return(ret);
}

int
pthread_rwlock_wrlock (pthread_rwlock_t *rwlock)
{
	pthread_rwlock_t 	prwlock;
	int			ret;

	if (rwlock == NULL)
		return(EINVAL);

	prwlock = *rwlock;

	/* check for static initialization */
	if (prwlock == NULL)
		return(EINVAL);

	/* grab the monitor lock */
	if ((ret = pthread_mutex_lock(&prwlock->lock)) != 0)
		return(ret);

	while (prwlock->state != 0) {
		++prwlock->blocked_writers;

		ret = pthread_cond_wait(&prwlock->write_signal, &prwlock->lock);

		if (ret != 0) {
			--prwlock->blocked_writers;
			pthread_mutex_unlock(&prwlock->lock);
			return(ret);
		}

		--prwlock->blocked_writers;
	}

	/* indicate we are locked for writing */
	prwlock->state = -1;

	/* see the comment on this in pthread_rwlock_rdlock */
	pthread_mutex_unlock(&prwlock->lock);

	return(ret);
}

int
pthread_rwlockattr_destroy(pthread_rwlockattr_t *rwlockattr)
{
	pthread_rwlockattr_t prwlockattr;

	if (rwlockattr == NULL)
		return(EINVAL);

	prwlockattr = *rwlockattr;

	/* check for static initialization */
	if (prwlockattr == NULL)
		return(EINVAL);

	free(prwlockattr);

	return(0);
}

int
pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *rwlockattr,
	int *pshared)
{
	*pshared = (*rwlockattr)->pshared;

	return(0);
}

int
pthread_rwlockattr_init(pthread_rwlockattr_t *rwlockattr)
{
	pthread_rwlockattr_t prwlockattr;

	if (rwlockattr == NULL)
		return(EINVAL);

	prwlockattr = (pthread_rwlockattr_t)
		malloc(sizeof(struct pthread_rwlockattr));

	if (prwlockattr == NULL)
		return(ENOMEM);

	prwlockattr->pshared 	= PTHREAD_PROCESS_PRIVATE;
	*rwlockattr		= prwlockattr;

	return(0);
}

int
pthread_rwlockattr_setpshared(pthread_rwlockattr_t *rwlockattr, int pshared)
{
	/* Only PTHREAD_PROCESS_PRIVATE is supported. */
	if (pshared != PTHREAD_PROCESS_PRIVATE)
		return(EINVAL);

	(*rwlockattr)->pshared = pshared;

	return(0);
}

#endif /* _THREAD_SAFE || _PTHREADS || _REENTRANT */
