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

#include	"oops.h"
#include        "workq.h"
/*#include	"dataq.h"*/

extern	struct		sockaddr_in	Me;

volatile int	killed, huped, logrotate;

struct	run_mod_arg {
	int	(*f)(int);
	int	so;
};

static	int		startup = TRUE;
static	int		wq_init = 0;
static	pthread_t 	dc_thread	= (pthread_t)NULL;
static	pthread_t	eraser_thread	= (pthread_t)NULL;
static	pthread_t	gc_thread	= (pthread_t)NULL;
static	pthread_t	gd_thread	= (pthread_t)NULL;
static	pthread_t 	rl_thread	= (pthread_t)NULL;
static	pthread_t	stat_thread	= (pthread_t)NULL;
static	pthread_attr_t	p_attr;
static	sigset_t	newset, oset;

static	int	blacklist_is_full(void);
static	void	cleanup(void);
static	int	put_in_blacklist(int, void *(f)(void*), int);
static	void	*run_module(int, void *(f)(void*), int, struct sockaddr *);
static	void	set_large_stack_size(pthread_attr_t*);
static	void	set_stack_size(pthread_attr_t*);


#if	!defined(_WIN32)
void
huphandler(int arg)
{
    huped = 1;
    signal(SIGHUP, &huphandler);
}

void
winch_handler(int arg)
{
    logrotate = 1;
    signal(SIGWINCH, &winch_handler);
}

void
killhandler(int arg)
{
    killed = 1;
}
#endif	/* !_WIN32 */

void
run(void)
{
int			r, res, rc;
int			one = -1;
int			descriptors;
socklen_t		icp_sa_len;
socklen_t		cli_addr_len;
struct	sockaddr_in	cli_addr, icp_sa;
struct	pollarg		*pollarg;

    huped = killed = logrotate = 0;
    if ( http_port == 0 ) {
	if ( server_so != -1 ) {
	    CLOSE(server_so);
	    server_so = -1;
	}
	goto create_icp_so;
    }
#ifdef  FREEBSD
    if ( (server_so != -1) && oops_user ) {
        /* we skip socket reopens completely if we run  *
         * under some (unprivileged) user               */
        goto create_icp_so;
    }
#endif

    if ( server_so != -1 )
    	CLOSE(server_so);
    server_so = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "run(): Can't create server socket: %m\n");
	my_sleep(5);
	return;
    } else {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "run(): http_listen on descriptor %d\n", server_so);
    }
    /* bind */
    bzero(&Me, sizeof(Me));
    if ( bind_addr )
	str_to_sa(bind_addr, (struct sockaddr*)&Me);
    Me.sin_port = htons(http_port);
    setsockopt(server_so, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    if ( bind(server_so, (struct sockaddr*)&Me, sizeof(Me)) == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "run(): Can't bind server: %m\n");
	my_sleep(5);
        CLOSE(server_so); server_so = -1;
	return;
    }

    if ( listen(server_so, 8196) ) {
	my_xlog(OOPS_LOG_SEVERE, "run(): Server can't listen: %n\n");
	my_sleep(5);
	CLOSE(server_so); server_so = -1;
	return;
    }

create_icp_so:
    if ( icp_port == 0 ) {
	if ( icp_so != -1 ) {
	    CLOSE(icp_so);
	    icp_so = -1;
	}
	goto skip_socket_opens;
    }
    if ( (icp_so != -1) && oops_user && (icp_port < IPPORT_RESERVED) )
	/* we skip socket reopens completely if we run	*
	 * under some (unprivileged) user		*/
	goto skip_socket_opens;

    /* create icp socket */
    if ( icp_so != -1 )
    	CLOSE(icp_so);
    icp_so = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( icp_so == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "run(): Can't create icp socket: %m\n");
	my_sleep(5);
	CLOSE(server_so); server_so = -1;
	return;
    } else {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "run(): icp_listen on descriptor %d\n", icp_so);
    }
    bzero(&Me, sizeof(Me));
    if ( bind_addr )
	str_to_sa(bind_addr, (struct sockaddr*)&Me);
    Me.sin_port = htons(icp_port);
    if ( bind(icp_so, (struct sockaddr*)&Me, sizeof(Me)) == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "run(): Can't bind icp: %m\n");
	my_sleep(5);
        CLOSE(server_so); server_so = -1;
	CLOSE(icp_so); icp_so = -1;
	return;
    }

skip_socket_opens:
    if ( oops_user ) set_user();
    pthread_attr_init(&p_attr);
    pthread_attr_setdetachstate(&p_attr, PTHREAD_CREATE_DETACHED);

    sigemptyset(&newset);
    sigaddset(&newset, SIGHUP);
    sigaddset(&newset, SIGWINCH);
    sigaddset(&newset, SIGINT);
    sigaddset(&newset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &newset, &oset);

    set_large_stack_size(&p_attr);

    if ( startup == TRUE ) {
	int	rc = 0;
	my_xlog(OOPS_LOG_SEVERE, "Starting threads\n");
	startup = FALSE;
	/* start statistics collector */
	if ( (rc = pthread_create(&stat_thread, &p_attr, statistics, NULL)) ) {
	    my_xlog(OOPS_LOG_SEVERE, "Can't create statistics thread: %m\n");
	}
	/* start garbage collector */
	if ( (rc = pthread_create(&gc_thread, &p_attr, garbage_collector, NULL)) ) {
	    my_xlog(OOPS_LOG_SEVERE, "Can't create garbage_collector thread: %m\n");
	}
	/* start garbage drop */
	if ( (rc = pthread_create(&gd_thread, &p_attr, garbage_drop, NULL)) ) {
	    my_xlog(OOPS_LOG_SEVERE, "Can't create garbage_drop thread: %m\n");
	}
	/* strart log rotator */
	if ( (rc = pthread_create(&rl_thread, &p_attr, rotate_logs, NULL)) ) {
	    my_xlog(OOPS_LOG_SEVERE, "Can't create rotate_logs thread: %m\n");
	}
	/* strart disk cleaner */
	if ( (rc = pthread_create(&dc_thread, &p_attr, clean_disk, NULL)) ) {
	    my_xlog(OOPS_LOG_SEVERE, "Can't create clean_disk thread: %m\n");
	}
	/* strart disk cleaner */
	if ( (rc = pthread_create(&eraser_thread, &p_attr, eraser, NULL)) ) {
	    my_xlog(OOPS_LOG_SEVERE, "Can't create eraser thread: %m\n");
	}
	if (rc) {
	    my_xlog(OOPS_LOG_SEVERE, "Critical error. Some treads not created. Oops stopped.\n");
	    do_exit(1);
	}
	my_sleep(1);
    }

    set_stack_size(&p_attr);

    if ( use_workers > 0 ) {
	/* start workers */
	if ( !wq_init ) {
            workq_init(&wq, max_workers, worker);
	    /* dataq_init(&wq); */
	    wq_init = 1;
	}
    }

#if	!defined(_WIN32)
    signal(SIGHUP,	&huphandler);
    signal(SIGWINCH,	&winch_handler);
    signal(SIGINT,	&killhandler);
    signal(SIGTERM,	&killhandler);
#endif

    pthread_sigmask(SIG_UNBLOCK, &newset, &oset);
    if ( listen_so_list ) {
	struct	listen_so_list	*list = listen_so_list;
	int			k=0;
	while(list) {
	    k++;
	    list = list->next;
	}
	pollarg = xmalloc((2+k)*sizeof(struct pollarg),"run(): 1");
    } else
	pollarg = xmalloc(2*sizeof(struct pollarg),"run(): 2");

wait_clients:
    pollarg[0].request = pollarg[1].request = 0;
    if ( server_so >= 0 ) {
	pollarg[0].fd = server_so;
	pollarg[0].request = FD_POLL_RD;
    } else
	if ( http_port != 0 ) my_xlog(OOPS_LOG_SEVERE, "run(): Server so = %d\n", server_so);
    if ( icp_so >= 0 ) {
	pollarg[1].fd = icp_so;
	pollarg[1].request = FD_POLL_RD;
    } else
	if (icp_port != 0)
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "run(): icp so = %d\n", icp_so);
    if ( listen_so_list ) {
	struct	listen_so_list	*list = listen_so_list;
	int			k=2;
	while(list) {
	    pollarg[k].fd 	= list->so;
	    pollarg[k].request	= FD_POLL_RD;
	    k++;
	    list = list->next;
	}
	descriptors = k;
    } else
	descriptors = 2;
#if	defined(FREEBSD)
    r = poll_descriptors_S(descriptors, &pollarg[0], -1);
#else
    r = poll_descriptors(descriptors, &pollarg[0], -1);
#endif /* FREEBSD */
    if ( r == -1 || huped || killed || logrotate ) {
	if ( huped ) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "run(): Reconfigure request.\n");
	    huped = 0;
	    pthread_sigmask(SIG_SETMASK, &oset, NULL);
	    pthread_attr_destroy(&p_attr);
	    xfree(pollarg);
	    return;
	}
	if ( killed ) {
	    (void)cleanup();
	    exit(1);
	}
	if ( logrotate ) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "run(): Rotate.\n");
	    rotate_logbuff();
	    rotate_accesslogbuff();
	    mod_reopen_logs();
	    logrotate = 0;
	}
	my_xlog(OOPS_LOG_SEVERE, "run(): Failed to select: %m\n");
	goto wait_clients;
    }
    if ( IS_READABLE(&pollarg[1]) ) {
        icp_job_t               *icp_job;
	struct	sockaddr_in	my_icp_sa;
	socklen_t		my_icp_sa_len = sizeof(struct sockaddr_in);

	/* icp request */
        icp_job = calloc(1, sizeof(*icp_job));
	if ( icp_job ) {
	    getsockname(icp_so, (struct sockaddr*)&icp_job->my_icp_sa, 
	                        &my_icp_sa_len);

	    icp_sa_len = sizeof(struct sockaddr_in);
            icp_job->icp_buf = malloc(16385);
            icp_job->icp_so = icp_so;
            rc = 0;
	    if ( icp_job->icp_buf ) {
	        rc = icp_job->icp_buf_len = recvfrom(icp_so, 
	                icp_job->icp_buf, 
	                16384, 
	                0, 
	                (struct sockaddr*)&icp_job->icp_sa, &icp_sa_len);
            }
	    if ( rc <= 0 ) {
	        my_xlog(OOPS_LOG_SEVERE, "run(): icp: recv_from: %m\n");
                IF_FREE(icp_job->icp_buf);
                free(icp_job);
	    } else {
                workq_add(&icp_workq, icp_job);
/*	        process_icp_msg(icp_so, icp_buf, rc, &icp_sa, &my_icp_sa);*/
	    }
        }
	r--; /* one descriptor processed */
    }
    if ( IS_READABLE(&pollarg[0]) ) {
	cli_addr_len = sizeof(cli_addr);
	rc = accept(server_so, (struct sockaddr*)&cli_addr, &cli_addr_len);
	if ( rc >= 0 ) {
	    work_t  *work;
	    if ( refuse_at ) {
		int	drop;
		LOCK_STATISTICS(oops_stat) ;
		drop = (oops_stat.clients >= refuse_at);
		UNLOCK_STATISTICS(oops_stat) ;
		if ( drop ) {
		    /* we will close any connection	*/
		    CLOSE(rc);
		    goto acc_pf;
		}
	    }
	    if ( start_red ) {
		int	drop;
		LOCK_STATISTICS(oops_stat) ;
		drop = (oops_stat.clients >= start_red);
		UNLOCK_STATISTICS(oops_stat) ;
		if ( drop && (rc % 2) ) {
		    /* will kill any odd sockets 	*/
		    CLOSE(rc);
		    LOCK_STATISTICS(oops_stat) ;
		    oops_stat.drops++;
		    oops_stat.drops0++;
		    UNLOCK_STATISTICS(oops_stat) ;
		    goto acc_pf;
		}
	    }
	    if ( max_rate_per_socket 
	         && (one_second_proxy_requests > max_rate_per_socket) ) {
		/* if blacklist is full just close socket	*/
		if ( !blacklist_is_full() ) {
		    put_in_blacklist(rc, run_client, -1);
		} else {
		    /* just close and go forward		*/
		    CLOSE(rc);
		    LOCK_STATISTICS(oops_stat) ;
		    oops_stat.drops++;
		    oops_stat.drops0++;
		    UNLOCK_STATISTICS(oops_stat) ;
		    goto acc_pf;
		}
	    }
	    work = xmalloc(sizeof(*work),"run(): 3");
	    if ( work ) {
		work->so = rc;
		work->f  = run_client;
		work->flags = WORK_NORMAL;
		memcpy(&work->sa, &cli_addr, sizeof(work->sa));
		work->accepted_so = -1 ; /* this is http_port socket */
	    }
	    if ( use_workers ) {
		if ( work ) {
                    workq_add(&wq, (void*)work);
		} else { /* failed to create worker */
		    CLOSE(rc);
		}
	    } else {
		pthread_t 	cli_thread;
		pthread_sigmask(SIG_BLOCK, &newset, &oset);
		/* well, process with this client */
		res = pthread_create(&cli_thread, &p_attr, run_client, (void*)work);
		if ( res ) {
		    my_xlog(OOPS_LOG_SEVERE, "run(): Can't create run_client thread: %m\n");
		    CLOSE(rc);
		}
		pthread_sigmask(SIG_UNBLOCK, &newset, NULL);
	    }
	}
    acc_pf:
	r--; /* one descriptor processed */
    }
    if ( r && listen_so_list ) {
	struct	listen_so_list	*list = listen_so_list;
	struct	sockaddr	cli_addr;
	int                     k=2, rc;
	socklen_t		cli_addr_len = sizeof(cli_addr);

	while(list) {
	    if (IS_READABLE(&pollarg[k]) ) {
                if ( !TEST(list->flags, LISTEN_AND_NO_ACCEPT) ) {
		    /* accept it 							*/
		    rc = accept(pollarg[k].fd, &cli_addr, &cli_addr_len);
		    if ( rc < 0 ) goto acc_f;
                }
		if ( refuse_at ) {
		    int	drop;
		    LOCK_STATISTICS(oops_stat) ;
		    drop = (oops_stat.clients >= refuse_at);
		    UNLOCK_STATISTICS(oops_stat) ;
		    if ( drop ) {
			/* we will close any connection	*/
			CLOSE(rc);
			LOCK_STATISTICS(oops_stat) ;
			oops_stat.drops++;
			oops_stat.drops0++;
			UNLOCK_STATISTICS(oops_stat) ;
			goto acc_pf;
		    }
		}
		if ( start_red ) {
		    int	drop;
		    LOCK_STATISTICS(oops_stat) ;
		    drop = (oops_stat.clients >= start_red);
		    UNLOCK_STATISTICS(oops_stat) ;
		    if ( drop && (rc % 2) ) {
			/* will kill any odd sockets 	*/
			CLOSE(rc);
			LOCK_STATISTICS(oops_stat) ;
			oops_stat.drops++;
			oops_stat.drops0++;
			UNLOCK_STATISTICS(oops_stat) ;
			goto acc_pf;
		    }
		}
		/* if we reach limit put this connect to blacklist		*/
		if (     max_rate_per_socket
		     && (list->requests >= max_rate_per_socket) ) {
		    /* if blacklist is full just close socket	*/
		    if ( !blacklist_is_full() ) {
			put_in_blacklist(rc, list->process_call, pollarg[k].fd);
		    } else {
			/* just close and go forward		*/
			CLOSE(rc);
			LOCK_STATISTICS(oops_stat) ;
			oops_stat.drops++;
			oops_stat.drops0++;
			UNLOCK_STATISTICS(oops_stat) ;
			goto acc_f;
		    }
		}
		/* update number of requests received during last second 	*/
		list->requests++;
		if ( list->process_call ) {
                    if ( TEST(list->flags, LISTEN_AND_DO_SYNC) )
                        list->process_call((void*)pollarg[k].fd);
                      else
		        run_module(rc, list->process_call, pollarg[k].fd, &cli_addr);
		} else {
		    run_module(rc, run_client, pollarg[k].fd, &cli_addr);
		}
	    }
	acc_f:
	    k++;
	    list = list->next;
	}
    }
    goto wait_clients;
}

void*
run_module(int so, void *(f)(void*), int accepted_so, struct sockaddr *sa)
{
pthread_t 	cli_thread;
int		res;
work_t		*work = xmalloc(sizeof(*work),"run_module(): 1");

    if ( work ) {
	work->so = so;
	work->f  = f;
	work->flags = WORK_MODULE;
        if ( sa ) memcpy(&work->sa, sa, sizeof(work->sa));
	work->accepted_so = accepted_so;
    }
    if ( use_workers ) {
	if ( work ) {
            workq_add(&wq, (void*)work);
	} else { /* failed to create worker */
	    CLOSE(so);
	}
    } else {
	pthread_sigmask(SIG_BLOCK, &newset, &oset);
	/* well, process with this client */
	res = pthread_create(&cli_thread, &p_attr, f, (void*)work);
	if ( res ) {
	    my_xlog(OOPS_LOG_SEVERE, "run_module(): Can't pthread_create().\n");
	    CLOSE(so);
	}
	pthread_sigmask(SIG_UNBLOCK, &newset, NULL);
    }
    return(NULL);
}

void
cleanup(void)
{
struct storage_st	*storage;

    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "cleanup(): Clean up and exit.\n");
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "cleanup(): Flushing mem_cache.\n");
    lo_mark_val = 0;
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "cleanup(): Locking config.\n");
    kill_request = 1;
    WRLOCK_CONFIG ;
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "cleanup(): Locking config...Done.\n");

    if ( db_in_use ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "cleanup(): Locking DB.\n");
	WRLOCK_DB ;
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "cleanup(): Locking DB...Done.\n");
	db_mod_sync();
	db_mod_close();
    }
    if ( (storage = storages) != 0 ) {
	while (storage) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "cleanup(): Locking %s\n", storage->path);
	    WRLOCK_STORAGE(storage);
	    if ( TEST(storage->flags, ST_READY) ) {
		flush_super(storage);
		flush_map(storage);
		close_storage(storage->fd);
	    }
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "cleanup(): Storage %s closed.\n", storage->path);
	    printf("Storage %s closed\n", storage->path);
	    storage=storage->next;
	}
    }
    flushout_fb(&logbuff);
}

static int
blacklist_is_full(void)
{
    return(TRUE);
}

static int
put_in_blacklist(int so, void *(f)(void*), int accepted_so)
{
    return(0);
}

static void
set_stack_size(pthread_attr_t *attr)
{
#if	defined(SOLARIS)
size_t	best_size, min_size;
int	rc;
ERRBUF ;

/* if we will use default 1M stack under solaris we can quickly fill
   address space, so set it to some real amount
*/
#if	defined(PTHREAD_STACK_MIN)
    min_size = PTHREAD_STACK_MIN;
#else
    min_size = 16*1024;
#endif	/* PTHREAD_STACK_MIN */
    best_size = 80*1024;
    if ( best_size < min_size ) best_size = min_size;
    rc = pthread_attr_setstacksize(attr, best_size);
    if ( rc ) {
	verb_printf("set_stack_size(): %s\n", STRERROR_R(rc, ERRBUFS));
    }
#endif	/* SOLARIS */
}

static void
set_large_stack_size(pthread_attr_t *attr)
{
#if	defined(FREEBSD)
size_t	best_size, min_size;
int	rc;
ERRBUF ;

/* 
    If we use GigaBASE, then we need stack larger then 128K for threads which
    will write to base. FreeBSD by default give obly 64K
*/
#if	defined(PTHREAD_STACK_MIN)
    min_size = PTHREAD_STACK_MIN;
#else
    min_size = 128*1024;
#endif	/* PTHREAD_STACK_MIN */
    best_size = 128*1024;
    if ( best_size < min_size ) best_size = min_size;
    rc = pthread_attr_setstacksize(attr, best_size);
    if ( rc ) {
	verb_printf("set_large_stack_size(): %s\n", STRERROR_R(rc, ERRBUFS));
    }
#endif	/* FREEBSD */
}
