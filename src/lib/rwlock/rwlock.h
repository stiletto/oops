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

#if	!defined(PTHREAD_PROCESS_PRIVATE)
#define PTHREAD_PROCESS_PRIVATE		0
#endif
#if	!defined(PTHREAD_PROCESS_SHARED)
#define PTHREAD_PROCESS_SHARED		1
#endif

#if	!defined(PTHREAD_RWLOCK_INITIALIZER)
#define	PTHREAD_RWLOCK_INITIALIZER	NULL

struct	pthread_rwlock {
	pthread_mutex_t	lock;		/* monitor lock */
	int		state;		/* 0 = idle  >0 = # of readers  -1 = writer */
	pthread_cond_t	read_signal;
	pthread_cond_t	write_signal;
	int		blocked_writers;
};

struct pthread_rwlockattr {
        int             pshared;
};

typedef	struct	pthread_rwlock		*pthread_rwlock_t;
typedef	struct	pthread_rwlockattr	*pthread_rwlockattr_t;

#if	defined(__cplusplus)
extern	"C" {
#endif

int	pthread_rwlock_destroy		(pthread_rwlock_t *);
int	pthread_rwlock_init		(pthread_rwlock_t *, const pthread_rwlockattr_t *);
int	pthread_rwlock_rdlock		(pthread_rwlock_t *);
int	pthread_rwlock_tryrdlock	(pthread_rwlock_t *);
int	pthread_rwlock_trywrlock	(pthread_rwlock_t *);
int	pthread_rwlock_unlock		(pthread_rwlock_t *);
int	pthread_rwlock_wrlock		(pthread_rwlock_t *);
int	pthread_rwlockattr_init		(pthread_rwlockattr_t *);
int	pthread_rwlockattr_getpshared	(const pthread_rwlockattr_t *, int *);
int	pthread_rwlockattr_setpshared	(pthread_rwlockattr_t *, int);
int	pthread_rwlockattr_destroy	(pthread_rwlockattr_t *);

#if	defined(__cplusplus)
}
#endif
#endif
