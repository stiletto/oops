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

#if	!defined(PTHREAD_H)
#define PTHREAD_H

#ifndef SIG_BLOCK
#define SIG_BLOCK 0
#endif

#ifndef SIG_UNBLOCK
#define SIG_UNBLOCK 1
#endif

#ifndef SIG_SETMASK
#define SIG_SETMASK 2
#endif

#ifndef _POSIX_THREADS
#define _POSIX_THREADS
#endif

#define PTHREAD_DESTRUCTOR_ITERATIONS	4
#define PTHREAD_KEYS_MAX		64
#define PTHREAD_STACK_MIN		1024
#define PTHREAD_THREADS_MAX		2019

typedef struct pthread_t_		*pthread_t;
typedef struct pthread_attr_t_		*pthread_attr_t;
typedef struct pthread_mutex_t_		*pthread_mutex_t;
typedef struct pthread_mutexattr_t_	*pthread_mutexattr_t;
typedef struct pthread_cond_t_ 		*pthread_cond_t;
typedef struct pthread_condattr_t_ 	*pthread_condattr_t;

#define PTHREAD_CREATE_DETACHED		1

#define PTHREAD_PROCESS_PRIVATE		0
#define PTHREAD_PROCESS_SHARED		1

#define PTHREAD_MUTEX_INITIALIZER	((pthread_mutex_t) -1)
#define PTHREAD_COND_INITIALIZER	((pthread_cond_t) -1)

/*
 * PThread Attribute Functions
 */
int _cdecl pthread_attr_init(pthread_attr_t * attr);

int _cdecl pthread_attr_destroy(pthread_attr_t * attr);

int _cdecl pthread_attr_setdetachstate(pthread_attr_t * attr,
		    int detachstate);
/*
 * PThread Functions
 */
int _cdecl pthread_create(pthread_t * tid,
		    const pthread_attr_t * attr,
		    void *(*start) (void *),
		    void *arg);

pthread_t _cdecl pthread_self(void);

int _cdecl pthread_attr_setstacksize(pthread_attr_t * attr,
		    size_t stacksize);

int _cdecl pthread_sigmask(int how,
		    sigset_t const * set,
		    sigset_t * oset);

/*
 * Mutex Attribute Functions
 */
int _cdecl pthread_mutexattr_init(pthread_mutexattr_t * attr);

int _cdecl pthread_mutexattr_destroy(pthread_mutexattr_t * attr);

int _cdecl pthread_mutexattr_setpshared(pthread_mutexattr_t * attr,
		    int pshared);

/*
 * Mutex Functions
 */
int _cdecl pthread_mutex_init(pthread_mutex_t * mutex,
			const pthread_mutexattr_t * attr);

int _cdecl pthread_mutex_destroy(pthread_mutex_t * mutex);

int _cdecl pthread_mutex_lock(pthread_mutex_t * mutex);

int _cdecl pthread_mutex_trylock(pthread_mutex_t * mutex);

int _cdecl pthread_mutex_unlock(pthread_mutex_t * mutex);

/*
 * Condition Variable Attribute Functions
 */
int _cdecl pthread_condattr_init (pthread_condattr_t * attr);

int _cdecl pthread_condattr_destroy (pthread_condattr_t * attr);

int _cdecl pthread_condattr_setpshared (pthread_condattr_t * attr,
			int pshared);

/*
 * Condition Variable Functions
 */
int _cdecl pthread_cond_init(pthread_cond_t * cond,
			const pthread_condattr_t * attr);

int _cdecl pthread_cond_destroy(pthread_cond_t * cond);

int _cdecl pthread_cond_wait(pthread_cond_t * cond,
			pthread_mutex_t * mutex);

int _cdecl pthread_cond_timedwait(pthread_cond_t * cond,
			pthread_mutex_t * mutex,
			const struct timespec *abstime);

int _cdecl pthread_cond_signal(pthread_cond_t * cond);

int _cdecl pthread_cond_broadcast(pthread_cond_t * cond);

#endif /* PTHREAD_H */
