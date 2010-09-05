/*
Copyright (C) 1999 Igor Khasilev

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
#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<stdarg.h>
#include	<strings.h>
#include	<netdb.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<signal.h>
#include	<locale.h>
#include	<time.h>

#if	defined(SOLARIS)
#include	<thread.h>
#endif

#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>

#include	<netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"
#include	"version.h"

char	*configfile = "oops.cfg";
FILE	*logf = NULL, *accesslogf = NULL;
int	readconfig(char*);
void	my_log(char*, ...);
int	cidr_net_cmp(const void *, const void *);
int	operation;
char	hostname[64];
struct	sockaddr_in	Me;
int	run_daemon = 0;
int	pid_d = -1;
struct	hash_entry	hash_table[HASH_SIZE];
int	skip_check=0, checked=0;
void	print_networks(struct cidr_net **, int, int), print_acls(), free_acl(struct acls *);
void	free_dom_list(struct domain_list *);
void	print_dom_list(struct domain_list *);
void	free_peers(struct peer *);
extern	int	str_to_sa(char*, struct sockaddr *);

size_t	db_cachesize = 4*1024*1024;	/* 4M */
static	int	my_bt_compare(const DBT*,const DBT*);

int
usage(void)
{
    printf("usage: addrd [-{C|c} config_filename]\n");
    return(0);
}

int
main(int argc, char **argv)
{
char	c;
int	i, rc;
int	format_storages = 0;

    use_workers = 0;
    if ( argc > 1)
    while( (c=getopt(argc, argv, "Zzw:c:C:hDds")) != EOF ) {
	switch(c) {
	case('c'):
	case('C'):
	    /* configfile */
	    configfile = optarg;
	    continue;
	case('w'):
	    /* workers */
	    use_workers = atoi(optarg);
	    continue;
	case('H'):
	case('h'):
	    usage();
	    exit(0);
	    break;	/* for lint */
	case('d'):
	case('D'):
	    run_daemon = 1;
	    break;
	case('Z'):
	case('z'):
	    format_storages = 1;
	    break;
	case('s'):
	    skip_check = 1;
	    break;
	case('?'):
	    usage();
	    exit(1);
	default:
	    printf("Invalid option '%c'\n", c);
	    usage();
	    exit(1);
	}
    }

    setlocale(LC_ALL, "");
    if ( run_daemon ) daemon(0,0);

    signal(SIGPIPE, SIG_IGN);

#ifdef	LINUX
    if ( !use_workers ) use_workers = 10;
#endif

    remove_limits();
    for(i=0;i<HASH_SIZE;i++) {
	bzero(&hash_table[i], sizeof(hash_table[i]));
	pthread_mutex_init(&hash_table[i].lock, NULL);
	pthread_mutex_init(&hash_table[i].size_lock, NULL);
    }
    for(i=0;i<DNS_HASH_SIZE;i++)
	dns_hash[i].last = dns_hash[i].first = NULL;

#if	defined(SOLARIS) && defined(_SC_NPROCESSORS_ONLN)
    {
    int np = sysconf(_SC_NPROCESSORS_ONLN);
	if ( np > 1 ) {
	    printf("Set concurrency to %d\n", np*2);
	    if ( !thr_setconcurrency(np*2) )
		printf("Done\n");
	    else
		printf("Failed\n");
	}
    }
#endif
    icp_so = -1;
    groups = 0;
    stop_cache = NULL;
    storages = NULL;
    startup_sbrk = sbrk(0);
    total_alloc = 0;
    clients_number = 0;
    peers = NULL;
    local_domains = NULL;
    local_networks	= NULL;
    local_networks_sorted = NULL;
    local_networks_sorted_counter = 0;
    oldest_obj = youngest_obj = NULL;
    pthread_mutex_init(&obj_chain, NULL);
    pthread_mutex_init(&malloc_mutex, NULL);
    pthread_mutex_init(&clients_lock, NULL);
    pthread_mutex_init(&accesslog_lock, NULL);
    pthread_mutex_init(&icp_resolver_lock, NULL);
    pthread_mutex_init(&dns_cache_lock, NULL);
    rwl_init(&config_lock);
    rwl_init(&log_lock);
    rwl_init(&db_lock);
    list_init(&icp_requests_list);
    kill_request = 0;
    global_sec_timer = time(NULL);
    bzero(&oops_stat, sizeof(oops_stat));
    pthread_mutex_init(&oops_stat.s_lock, NULL);
#ifdef	MODULES
    load_modules();
#endif
    base_64_init();

run:
    reconfig_request = 1;
    WRLOCK_CONFIG;
    bzero(base,		sizeof(base));
    bzero(logfile,	sizeof(logfile));  log_num = log_size = 0;
    bzero(accesslog,	sizeof(accesslog));accesslog_num = accesslog_size = 0;
    bzero(statisticslog,sizeof(statisticslog));
    bzero(pidfile,	sizeof(pidfile));
    bzero(connect_from,	sizeof(connect_from));
    bzero(icons_path,	sizeof(icons_path));
    bzero(icons_port,	sizeof(icons_port));
    bzero(icons_host,	sizeof(icons_host));
    bzero(dbhome,	sizeof(dbhome));
    bzero(dbname,	sizeof(dbname));
    bzero(mem_max,	sizeof(mem_max));
    bzero(lo_mark,	sizeof(lo_mark));
    bzero(hi_mark,	sizeof(hi_mark));
    bzero(parent_host,	sizeof(parent_host));
    parent_port		= 0;
    http_port		= 3128;
    icp_port		= 3130;
    internal_http_port	= 3129;
    ns_configured	= 0;
    default_expire_interval = DEFAULT_EXPIRE_INTERVAL;
    default_expire_value    = DEFAULT_EXPIRE_VALUE;
    disk_low_free	= DEFAULT_LOW_FREE;
    disk_hi_free	= DEFAULT_HI_FREE;
    maxresident		= DEFAULT_MAXRESIDENT;
    dns_ttl		= DEFAULT_DNS_TTL;
    icp_timeout		= DEFAULT_ICP_TIMEOUT;

    bzero(&dbenv, sizeof(dbenv));
    bzero(&dbinfo,sizeof(dbinfo));
    dbinfo.db_cachesize = db_cachesize;
    dbinfo.db_pagesize = 16*1024;	/* 16k */
    dbinfo.bt_compare = my_bt_compare;

    if ( stop_cache )
	free_stop_cache();

    if ( groups ) {
	free_groups(groups);
	groups = NULL;
    }

    if ( local_domains ) {
	free_dom_list(local_domains);
	local_domains = NULL;
    }
    if ( local_networks_sorted )
	free(local_networks_sorted);
    local_networks_sorted = NULL;
    local_networks_sorted_counter = 0;

    if ( local_networks ) {
	free_net_list(local_networks);
	local_networks = NULL;
    }

    if ( storages ) {
	free_storages(storages);
	storages = NULL;
    }

    if ( peers ) {
	free_peers(peers);
	peers = NULL;
    }
    /* go read config */
    if ( readconfig(configfile) ) exit(1);

    sort_networks();
    (void)print_networks(sorted_networks_ptr,sorted_networks_cnt, TRUE);
    print_acls();

    if ( local_networks ) {
	local_networks_sorted = (struct cidr_net**)sort_n(local_networks, &local_networks_sorted_counter);
	print_networks(local_networks_sorted, local_networks_sorted_counter, FALSE);
    }
    if ( local_domains ) {
	printf("Local domains:\n");
	print_dom_list(local_domains );
    }
    if ( !mem_max_val ) {
	mem_max_val = 20 * 1024 * 1024;
	lo_mark_val = 15 * 1024 * 1024;
	hi_mark_val = 17 * 1024 * 1024;
    }
    if ( logfile[0] != 0 ) {
        rwl_wrlock(&log_lock);
	if ( logf )
	    fclose(logf);
	logf = fopen(logfile, "a");
	if ( !logf ) printf("%s: %s\n", logfile, strerror(errno));
	rwl_unlock(&log_lock);
    }
    if ( accesslog[0] != 0 ) {
	if ( accesslogf )
	    fclose(accesslogf);
	accesslogf = fopen(accesslog, "a");
	if ( !accesslogf ) printf("%s: %s\n", accesslog, strerror(errno));
    }

    next_alloc_storage = NULL;
    reconfig_request = 0;
    if ( disk_hi_free >= 100          ) disk_hi_free  = DEFAULT_HI_FREE;
    if ( disk_low_free > disk_hi_free ) disk_low_free = disk_hi_free;
    UNLOCK_CONFIG;
    if ( connect_from[0] != 0 ) {
	connect_from_sa_p = &connect_from_sa;
	if ( str_to_sa(connect_from, (struct sockaddr*)connect_from_sa_p) ) {
	    my_log("WARNING: can't resolve %s, binding disabled\n",
	    	connect_from);
	    connect_from_sa_p = NULL;
	} else
	    my_log("Binding to %s enabled\n", connect_from);
    } else
	connect_from_sa_p = NULL;

    if ( format_storages ) {
	do_format_storages();
	exit(0);
    }

    if ( dbhome[0] && db_appinit(dbhome, NULL, &dbenv, 
    		DB_CREATE|DB_THREAD) ) {
		my_log("db_appinit(%s) failed: %s\n", dbhome, strerror(errno));
    }
    if ( (rc = db_open(dbname, DB_BTREE,
    		DB_CREATE|DB_THREAD,
    		0644,
    		&dbenv,
    		&dbinfo,
    		&dbp)) ) {
	my_log("db_open: %s\n", strerror(rc));
	dbp = NULL;
    }
    prepare_storages();
    my_log( "oops%sStarted\n", VERSION);
#ifdef	DB_VERSION_STRING
    my_log("DB engine by %s\n", DB_VERSION_STRING);
#endif
    if ( pidfile[0] != 0 ) {
	char	pid[11];
	flock_t	fl;

	if ( pid_d != -1 )
	    close(pid_d);
	pid_d = open(pidfile, O_RDWR|O_CREAT|O_NONBLOCK, S_IRUSR|S_IWUSR|S_IRGRP);
	if ( pid_d == -1 ) {
	    my_log("Fatal: Can't create pid file: %s\n", strerror(errno));
	    do_exit(1);
	}
	bzero(&fl, sizeof(fl));
	fl.l_type=F_WRLCK;
	fl.l_whence=fl.l_len=0;
	if ( fcntl(pid_d, F_SETLK, &fl) < 0 ) {
	    my_log("Fatal: Can't lock pid file: %s\n", strerror(errno));
	    do_exit(1);
	}
	sprintf(pid, "%-10d", (int)getpid());
	write(pid_d, pid, strlen(pid));
    }
    bzero(&Me, sizeof(Me));
    Me.sin_family = AF_INET;
    /* this is all we need to start server */
    run();
    reconfig_request = 1;
    WRLOCK_CONFIG ;
    if ( logf) {
	rwl_wrlock(&log_lock);
	fclose(logf);
	logf = NULL;
	rwl_unlock(&log_lock);
    }
    if ( accesslogf) {
	fclose(accesslogf);
	accesslogf = NULL;
    }
    if ( dbp ) {
	dbp->close(dbp, 0);
	dbp = NULL;
    }
    if ( dbhome[0] && db_appexit(&dbenv) ) {
	my_log("db_appexit failed");
    }
    reconfig_request = 0;
    UNLOCK_CONFIG ;
    goto run;
}

void
free_groups(struct group *groups)
{
struct	group		*next;
struct	cidr_net	*nets, *next_net;

    while(groups) {
	next=groups->next;

	pthread_mutex_destroy(&groups->group_mutex);
	if (groups->name ) free(groups->name);
	nets = groups->nets;
	while(nets) {
	    next_net = nets->next;
	    free(nets);
	    nets = next_net;
	}
	if ( groups->badports ) free(groups->badports);
	if ( groups->auth_mods ) free_string_list(groups->auth_mods);
	if ( groups->redir_mods ) free_string_list(groups->redir_mods);
	free_acl(groups->http);
	free_acl(groups->icp);

	free(groups);
	groups = next;
    }
    if ( sorted_networks_ptr ) {
	free(sorted_networks_ptr);
	sorted_networks_ptr = NULL;
    }
}

void
free_acl(struct acls *acls) {
struct	acl		*acl,  *next_acl;
struct	domain_list	*dom_list;
	if ( acls ) {
	    acl = acls->allow;
	    while( acl ) {
		next_acl = acl->next;
		switch( acl->type ) {
		case ACL_DOMAINDST:
			dom_list = acl->list;
			free_dom_list(dom_list);
			break;
		default:
			printf("Unknown ACL type\n");
			break;
		}
		free(acl);
		acl = next_acl;
	    }
	    acl = acls->deny;
	    while( acl ) {
		next_acl = acl->next;
		switch( acl->type ) {
		case ACL_DOMAINDST:
			dom_list = acl->list;
			free_dom_list(dom_list);
			break;
		default:
			printf("Unknown ACL type\n");
			break;
		}
		free(acl);
		acl = next_acl;
	    }
	    free(acls);
	}
}
void
print_acls()
{
struct	group		*group = groups;
struct	acls		*acls;
struct	acl		*acl, *next_acl;
struct	domain_list	*dom_list;

    while( group ){
	if ( group->http ) {
	    printf("Group %s\n", group->name);
	    acls = group->http;
	    acl = acls->allow;
	    if ( acl ) printf("Allow:\n");
	    while( acl ) {
		next_acl = acl->next;
		switch( acl->type ) {
		case ACL_DOMAINDST:
			dom_list = acl->list;
			print_dom_list(dom_list);
			break;
		default:
			printf("Unknown ACL type\n");
			break;
		}
		acl = next_acl;
	    }
	    acl = acls->deny;
	    if ( acl ) printf("Deny:\n");
	    while( acl ) {
		next_acl = acl->next;
		switch( acl->type ) {
		case ACL_DOMAINDST:
			dom_list = acl->list;
			print_dom_list(dom_list);
			break;
		default:
			printf("Unknown ACL type\n");
			break;
		}
		acl = next_acl;
	    }
	}
	group=group->next;
    }
}
void
print_dom_list(struct domain_list *list)
{
struct	domain_list	*next;

    while(list) {
	next = list->next;
	if ( list->domain ) printf("\tDomain: %s\n", list->domain);
	list = next;
    }
}
void
free_net_list(struct cidr_net *nets)
{
struct	cidr_net *next_net;

    while(nets) {
	next_net = nets->next;
	free(nets);
	nets = next_net;
    }
}
void
free_dom_list(struct domain_list *list)
{
struct	domain_list	*next;

    while(list) {
	next = list->next;
	if ( list->domain ) {
	    free(list->domain);
	}
	free(list);
	list = next;
    }
}
void
sort_networks()
{
struct	group		*g = groups;
struct	cidr_net	*n;
int			i;

    /* 1. count networks */
    sorted_networks_cnt = 0;
    while( g ) {
	n = g->nets;
	while(n) {
	    n->group = g ;
	    n=n->next;
	    sorted_networks_cnt++;
	}
	g = g->next;
    }
    if ( sorted_networks_cnt ) {
	sorted_networks_ptr = malloc(sorted_networks_cnt * sizeof(struct cidr_net*));
	if ( !sorted_networks_ptr ) {
	    my_log("No mem for sorted_networks\n");
	    sorted_networks_cnt = 0;
	    return;
	}
    } else
	return;
    /* 2. build list */
    i = 0;
    g = groups;
    while( g ) {
	n = g->nets;
	while(n) {
	    sorted_networks_ptr[i] = n ;
	    i++;
	    n=n->next;
	}
	g = g->next;
    }
    /* sort list */
    printf("Sorting networks\n");
    qsort(sorted_networks_ptr, sorted_networks_cnt, sizeof(struct cidr_net*),
    	 cidr_net_cmp);
}
struct cidr_net**
sort_n(struct cidr_net *nets, int *counter)
{
struct cidr_net *next;
struct cidr_net	**res;
int		i;

    *counter = 0;
    next = nets;
    while(next) {
	next=next->next;
	(*counter)++;
    }
    if ( *counter ) {
	/* allocate array */
	res = (struct cidr_net **)malloc(*counter * sizeof(struct cidr_net*));
	if ( !res ) {
	    *counter = 0;
	    return(NULL);
	}
	/* build list */
	next = nets; i = 0;
	while(next) {
	    res[i] = next;
	    i++;
	    next=next->next;
	}
	/* well, sort them */
	qsort(res, *counter, sizeof(struct cidr_net*), cidr_net_cmp);
        return(res);
    }
    return(NULL);
}

int
cidr_net_cmp(const void *a1, const void *a2)
{
struct cidr_net	*n1, *n2;

    n1 = *((struct cidr_net**)a1);
    n2 = *((struct cidr_net**)a2);
    return(n2->masklen - n1->masklen);
}
void
print_networks(struct cidr_net **n, int i, int print_name)
{
int k=0;
    if ( !n || !i ) return;
    while( k < i) {
	printf("Net %08x/%-2d[%s]\n", (*n)->network, (*n)->masklen, print_name?(*n)->group->name:"");
	k++; n++;
    }
}

void
add_to_stop_cache(char *string)
{
struct	string_list	*new;

    new = xmalloc(sizeof(*new), "for news top_cache");
    if ( new ) {
	new->string = string;
	new->next = stop_cache;
	stop_cache = new;
    }
}

void
free_stop_cache()
{
struct	string_list	*curr, *next;

    curr = stop_cache;
    while (curr ) {
	next = curr->next;
	if ( curr->string ) free(curr->string);
	free(curr);
	curr = next;
    }
    stop_cache = NULL;
}

void
init_storages(struct storage_st *current)
{
struct storage_st * next = NULL;
    while (current) {
	next = current->next;
	init_storage( current ) ;
	current=next;
    }
}
void
free_storages(struct storage_st *current)
{
struct storage_st *next=NULL;

    while (current) {
	next = current->next;
	free_storage( current ) ;
	current=next;
    }
}

void
free_peers(struct peer *peer)
{
struct	peer	*next;
    while(peer) {
	next = peer->next;
	if ( peer->name )
	    free(peer->name);
	if ( peer->acls )
	    free_acl(peer->acls);
	free(peer);
	peer = next;
    }
}
int
my_bt_compare(const DBT* a, const DBT* b)
{
    if ( a->size != b->size ) return(a->size-b->size);
    return(memcmp(a->data, b->data, a->size));
}
