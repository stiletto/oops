#include        <stdio.h>
#include        <stdlib.h>
#include        <fcntl.h>
#include        <errno.h>
#include        <stdarg.h>
#include        <strings.h>
#include        <netdb.h>
#include        <unistd.h>
#include        <ctype.h>
#include        <signal.h>
#include        <time.h>

#include        <sys/param.h>
#include        <sys/socket.h>
#include        <sys/types.h>
#include        <sys/stat.h>
#include        <sys/file.h>
#include        <sys/time.h>

#include        <netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"
#include	"dataq.h"

struct		sockaddr_in	Me;
int		server_so = -1;
pthread_t 	gc_thread = (pthread_t)NULL, rl_thread = (pthread_t)NULL;
pthread_t 	dc_thread = (pthread_t)NULL;
pthread_t 	dl_thread = (pthread_t)NULL;
pthread_t	stat_thread = (pthread_t)NULL;
dataq_t		wq;

int	current_workers = 0;
int	max_workers = 512;
int	wq_init = 0;

int		huped=0, killed = 0;
sigset_t	newset, oset;
pthread_attr_t	p_attr;

void	*run_client(void*);
void	cleanup(void);
void	*worker(void*);

void
huphandler(int arg)
{
    huped = 1;
    signal(SIGHUP, &huphandler);
}

void
killhandler(int arg)
{
    killed = 1;
}

char			icp_buf[16384];

void
run()
{
int	r, res;
int	one = -1;
int			cli_addr_len;
fd_set			rq;
int			icp_sa_len;
struct	sockaddr_in	cli_addr, icp_sa;
struct	pollarg		pollarg[2];

    if ( server_so != -1 )
    	close(server_so);
    server_so = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	my_log("Can't create server socket: %s\n", strerror(errno));
	my_sleep(5);
	return;
    } else {
	my_log("http_listen on descriptor %d\n", server_so);
    }
    /* bind */
    Me.sin_port = htons(http_port);
    setsockopt(server_so, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    if ( bind(server_so, (struct sockaddr*)&Me, sizeof(Me)) == -1 ) {
	my_log("Can't bind server: %s\n", strerror(errno));
	my_sleep(5);
        close(server_so);server_so = -1;
	return;
    }

    if ( listen(server_so, 128) ) {
	my_log("server can't listen: %s\n", strerror(errno));
	my_sleep(5);
	close(server_so);server_so = -1;
	return;
    }

    /* create icp socket */
    if ( icp_so != -1 )
    	close(icp_so);
    icp_so = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( icp_so == -1 ) {
	my_log("Can't create icp socket: %s\n", strerror(errno));
	my_sleep(5);
	close(server_so);server_so = -1;
	return;
    } else {
	my_log("icp_listen  on descriptor %d\n", icp_so);
    }
    Me.sin_port = htons(icp_port);
    if ( bind(icp_so, (struct sockaddr*)&Me, sizeof(Me)) == -1 ) {
	my_log("Can't bind icp: %s\n", strerror(errno));
	my_sleep(5);
        close(server_so);server_so = -1;
	close(icp_so); icp_so = -1;
	return;
    }
    
    pthread_attr_init(&p_attr);
    pthread_attr_setdetachstate(&p_attr, PTHREAD_CREATE_DETACHED);

    sigemptyset(&newset);
    sigaddset(&newset, SIGHUP);
    sigaddset(&newset, SIGINT);
    sigaddset(&newset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &newset, &oset);

    /* start garbage collector */
    if ( !gc_thread )
	while( (res = pthread_create(&gc_thread, &p_attr, garbage_collector, NULL)) ) {
	    my_log("Hmm. Can't create garbage collector. Still trying\n");
	    my_sleep(5);
    }
    /* strart log rotator */
    if ( !rl_thread )
	while( (res = pthread_create(&rl_thread, &p_attr, rotate_logs, NULL)) ) {
	    my_log("Hmm. Can't create log rotator. Still trying\n");
	    my_sleep(5);
    }
    /* strart disk cleaner */
    if ( !dc_thread )
	while( (res = pthread_create(&dc_thread, &p_attr, clean_disk, NULL)) ) {
	    my_log("Hmm. Can't create clean disk thread. Still trying\n");
	    my_sleep(5);
    }
    if ( !stat_thread )
	while( (res = pthread_create(&stat_thread, &p_attr, statistics, NULL)) ) {
	    my_log("Hmm. Can't create stat thread. Still trying\n");
	    my_sleep(5);
    }
    if ( (use_workers > 0) && (current_workers < use_workers) ) {
	/* start workers */
	int i = use_workers - current_workers;
	if ( !wq_init ) {
	    dataq_init(&wq);
	    wq_init = 1;
	}
	while( i ) {
	    pthread_t thread;
	    pthread_create(&thread, NULL, worker, NULL);
	    i--;
	    current_workers++;
	}
    }
    signal(SIGHUP, &huphandler);
    signal(SIGINT, &killhandler);
    signal(SIGTERM, &killhandler);
    pthread_sigmask(SIG_UNBLOCK, &newset, &oset);

wait_clients:
    FD_ZERO(&rq);
    FD_SET(server_so, &rq);
    FD_SET(icp_so, &rq);
    pollarg[0].fd = server_so;
    pollarg[0].request = FD_POLL_RD;
    pollarg[1].fd = icp_so;
    pollarg[1].request = FD_POLL_RD;
/*    r = select(MAX(server_so, icp_so)+1, &rq, NULL, NULL, NULL);*/
    r = poll_descriptors(2, &pollarg[0], -1);
    if ( r == -1 || huped || killed ) {
	if ( huped ) {
	    my_log("reconfigure request\n");
	    huped = 0;
	    pthread_sigmask(SIG_SETMASK, &oset, NULL);
	    pthread_attr_destroy(&p_attr);
	    return;
	}
	if ( killed ) {
	    (void)cleanup();
	    exit(1);
	}
	my_log("failed to select: %s\n", strerror(errno));
	goto wait_clients;
    }
    if ( IS_READABLE(&pollarg[1]) ) {
	/* icp request */
	icp_sa_len = sizeof(icp_sa);
	r = recvfrom(icp_so, icp_buf, sizeof(icp_buf), 0, (struct sockaddr*)&icp_sa, &icp_sa_len);
	if ( r < 0 ) {
	    my_log("icp:recv_from: %s\n", strerror(errno));
	} else {
	    process_icp_msg(icp_so, icp_buf, r, &icp_sa);
	}
    }
    if ( IS_READABLE(&pollarg[0]) ) {
	cli_addr_len = sizeof(cli_addr);
	r = accept(server_so, (struct sockaddr*)&cli_addr, &cli_addr_len);
	if ( r >= 0 ) {
	    if ( use_workers ) {
		work_t	*work = xmalloc(sizeof(*work),"");
		if ( work ) {
		    work->so = r;
		    work->f  = run_client;
		    dataq_enqueue(&wq, (void*)work);
		    if ( (clients_number >= current_workers) &&
		         (current_workers < max_workers) ) {
			pthread_t thread;
			pthread_create(&thread, NULL, worker, NULL);
			current_workers++;
			printf("Current_workers now: %d\n", current_workers);
		    }
		} else { /* failed to create worker */
		    close(r);
		}
	    } else {
		pthread_t 	cli_thread;
		pthread_sigmask(SIG_BLOCK, &newset, &oset);
		/* well, process with this client */
		res = pthread_create(&cli_thread, &p_attr, run_client, (void*)r);
		if ( res )
		    my_log("Can't pthread_create\n");
		pthread_sigmask(SIG_UNBLOCK, &newset, NULL);
	    }
	}
    }
    goto wait_clients;
}

FILE	*logf;
void
cleanup(void)
{
struct storage_st	*storage;

    my_log("Clean up and exit\n");
    my_log("Locking config\n");
    kill_request = 1;
    WRLOCK_CONFIG ;
    my_log("Locking config...Done\n");
    if ( dbp ) {
	my_log("Locking DB\n");
	WRLOCK_DB ;
	my_log("Locking DB...Done\n");
	dbp->sync(dbp, 0);
	dbp->close(dbp, 0);
    }
    if ( (storage = storages) ) {
	while (storage) {
	    my_log("Locking %s\n", storage->path);
	    WRLOCK_STORAGE(storage);
	    if ( TEST(storage->flags, ST_READY) ) {
		flush_super(storage);
		flush_map(storage);
		close(storage->fd);
	    }
	    my_log("Storage %s closed\n", storage->path);
	    storage=storage->next;
	}
    }
    if ( logf )
	fclose(logf);
}
