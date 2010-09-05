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
#include	<string.h>
#include	<netdb.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<signal.h>
#include	<locale.h>
#include	<time.h>
#include	<pwd.h>

#if	defined(SOLARIS)
#include	<thread.h>
#endif

#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>
#include	<sys/resource.h>

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
int	check_config_only;
struct	obj_hash_entry	hash_table[HASH_SIZE];
int	skip_check=0, checked=0;
void	print_networks(struct cidr_net **, int, int), print_acls(), free_acl(struct acls *);
void	free_dom_list(struct domain_list *);
void	print_dom_list(struct domain_list *);
void	free_peers(struct peer *);
void	free_denytimes(struct denytime *);
void	free_dstd_ce(void*);
int	close_listen_so_list(struct listen_so_list *list);
extern	int	str_to_sa(char*, struct sockaddr *);
void	open_db();
void	set_user();

size_t	db_cachesize = 4*1024*1024;	/* 4M */
static	int	my_bt_compare(const DBT*,const DBT*);

int
usage(void)
{
    printf("usage: addrd [-{C|c} config_filename] [-{Z|z}] [-V] [-w num] [-W num]\n");
    printf("-C|c filename	- path to config file\n");
    printf("-z|Z		- format storages\n");
    printf("-V		- show version info\n");
    printf("-v		- verbose startup\n");
    printf("-x[shfad]	- log level(s-storages,h-http,f-ftp,a-all,d-dns)\n");
    printf("-w number	- use thread pool. number define initial size of the pool.\n");
    printf("-W number	- limit thread pool size to number\n");
    return(0);
}

int
main(int argc, char **argv)
{
char	c,*vlvls;
int	i, rc;
int	format_storages = 0;

    use_workers = 0;
    max_workers = 0;
    current_workers = 0;
    check_config_only = FALSE;
    verbose_startup = FALSE;
    verbosity_level = 0;
    my_pid = getpid();
    /* set stdout unbuffered					*/
    setbuf(stdout, NULL);
    /* stderr by default is unbuffered, but this wont hurt 	*/
    setbuf(stderr, NULL);

    if ( argc > 1)
    while( (c=getopt(argc, argv, "W:w:Zzc:C:hx:DdsvV")) != EOF ) {
	switch(c) {
	case('v'):
		/* verbose startup */
		verbose_startup = TRUE;
		break;
	case('V'):
		printf("oops version %s\n\n", VERSION);
		printf("CC=%s\n\n", OOPS_CC);
		printf("CFLAGS=%s\n\n", OOPS_CFLAGS);
		printf("LIBS=%s\n\n", OOPS_LIBS);
		exit(0);
	case('x'):
		vlvls = optarg;
		while ( *vlvls ) {
		    switch( *vlvls ) {
			case 's':
				verbosity_level |= LOG_STOR;
				break;
			case 'f':
				verbosity_level |= LOG_FTP;
				break;
			case 'h':
				verbosity_level |= LOG_HTTP;
				break;
			case 'd':
				verbosity_level |= LOG_DNS;
				break;
			case 'a':
				verbosity_level = -1;
				break;
		    }
		    vlvls++;
		}
		break;
	case('C'):
	    check_config_only = TRUE;
	case('c'):
	    /* configfile */
	    configfile = optarg;
	    continue;
	case('w'):
	    /* workers */
	    use_workers = atoi(optarg);
	    break;
	case('W'):
	    /* workers */
	    max_workers = atoi(optarg);
	    break;
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
    if ( !max_workers ) {
#ifdef	RLIM_NPROC
	if ( !getrlimit(RLIMIT_NPROC, &rl) ) {
	    max_workers = rl.rlim_cur;
	} else
	    max_workers = 250;
#else
	max_workers = 250;
#endif
    }
#endif
    if ( (use_workers > 0) && (max_workers <= 0) ) {
	max_workers = 250;
    }
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
	    verb_printf("Set concurrency to %d\n", np*2);
	    if ( !thr_setconcurrency(np*2) )
		verb_printf("Done\n");
	    else
		verb_printf("Failed\n");
	}
    }
#endif
    server_so = -1;
    icp_so = -1;
    groups = 0;
    stop_cache = NULL;
    storages = NULL;
    startup_sbrk = sbrk(0);
    total_alloc = 0;
    clients_number = 0;
    peers = NULL;
    peer_down_interval = 10 ;			/* default 10 sec. */
    tcpports = NULL;
    local_domains = NULL;
    local_networks	= NULL;
    local_networks_sorted = NULL;
    local_networks_sorted_counter = 0;
    listen_so_list = NULL;
    oldest_obj = youngest_obj = NULL;
    pthread_mutex_init(&obj_chain, NULL);
    pthread_mutex_init(&malloc_mutex, NULL);
    pthread_mutex_init(&clients_lock, NULL);
    pthread_mutex_init(&accesslog_lock, NULL);
    pthread_mutex_init(&icp_resolver_lock, NULL);
    pthread_mutex_init(&dns_cache_lock, NULL);
    pthread_mutex_init(&st_check_in_progr_lock, NULL);
    pthread_mutex_init(&mktime_lock, NULL);
    rwl_init(&config_lock);
    rwl_init(&log_lock);
    rwl_init(&db_lock);
    list_init(&icp_requests_list);
    kill_request = 0;
    global_sec_timer = time(NULL);
    bzero(&oops_stat, sizeof(oops_stat));
    pthread_mutex_init(&oops_stat.s_lock, NULL);
    named_acls = NULL;
    global_refresh_pattern = NULL;
    charsets = NULL;
    acl_allow = acl_deny = NULL;
    stop_cache_acl = NULL;
    oops_user = NULL;
    oops_chroot = NULL;
#ifdef	MODULES
    if ( !check_config_only )
	load_modules();
#endif
    base_64_init();

    /* reserve some fd's	*/
    for(i=0;i<RESERVED_FD;i++)
	reserved_fd[i] = open("/dev/null", O_RDONLY);

run:
    reconfig_request = 1;
    pthread_mutex_lock(&st_check_in_progr_lock);
    st_check_in_progr = TRUE;
    pthread_mutex_unlock(&st_check_in_progr_lock);
    WRLOCK_CONFIG;
    dbenv = NULL;
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
    if ( bind_addr ) {
	free(bind_addr);
	bind_addr = NULL;
    }
    ns_configured	= 0;
    always_check_freshness  = FALSE;
    last_modified_factor = 10;
    force_http11	= FALSE;
    force_completion	= 75;	/* 75% */
    default_expire_interval = DEFAULT_EXPIRE_INTERVAL;
    max_expire_value 	    = 4*DEFAULT_EXPIRE_INTERVAL;
    ftp_expire_value 	    = FTP_EXPIRE_VALUE;
    default_expire_value    = DEFAULT_EXPIRE_VALUE;
    disk_low_free	= DEFAULT_LOW_FREE;
    disk_hi_free	= DEFAULT_HI_FREE;
    maxresident		= DEFAULT_MAXRESIDENT;
    dns_ttl		= DEFAULT_DNS_TTL;
    icp_timeout		= DEFAULT_ICP_TIMEOUT;
    logs_buffered	= FALSE;
    insert_x_forwarded_for = TRUE;
    insert_via		= TRUE;
    if ( oops_user ) {
	free(oops_user);
	oops_user = NULL;
    }
    if ( oops_chroot ) {
	free(oops_chroot);
	oops_chroot = NULL;
    }
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

    if ( listen_so_list ) {
	close_listen_so_list(listen_so_list);
	listen_so_list = NULL;
    }

    if ( tcpports ) free_tcp_ports_in_use();

    if ( named_acls ) {
	free_named_acls(named_acls);
	named_acls = NULL;
    }
    if ( global_refresh_pattern ) {
	free_refresh_patterns(global_refresh_pattern);
	global_refresh_pattern = NULL;
    }
    if ( acl_allow ) {
	free_acl_access(acl_allow);
	acl_allow = NULL;
    }
    if ( acl_deny ) {
	free_acl_access(acl_deny);
	acl_deny = NULL;
    }
    if ( stop_cache_acl ) {
	free_acl_access(stop_cache_acl);
	stop_cache_acl = NULL;
    }

    /* release reserved fd's	*/
    for(i=0;i<RESERVED_FD;i++)
	if ( reserved_fd[i] >= 0 ) {
	    close(reserved_fd[i]);
	}

    /* go read config */
    if ( readconfig(configfile) ) exit(1);
    if ( check_config_only ) exit(0);
    if ( oops_chroot ) {
	int rc = chroot(oops_chroot);

	if ( rc == -1 )
	    verb_printf("Can't chroot(): %s\n", strerror(errno));
    }
    if ( oops_user ) set_user();

    if ( logfile[0] != 0 ) {
        rwl_wrlock(&log_lock);
	if ( logf )
	    fclose(logf);
	logf = fopen(logfile, "a");
	if ( !logf ) verb_printf("%s: %s\n", logfile, strerror(errno));
	if ( logf && !logs_buffered )
	    setbuf(logf, NULL);
	rwl_unlock(&log_lock);
    }
    if ( accesslog[0] != 0 ) {
	if ( accesslogf )
	    fclose(accesslogf);
	accesslogf = fopen(accesslog, "a");
	if ( !accesslogf ) verb_printf("%s: %s\n", accesslog, strerror(errno));
	if ( accesslogf && !logs_buffered )
	    setbuf(accesslogf, NULL);
    }

    /* reserve them again	*/
    for(i=0;i<RESERVED_FD;i++) {
	reserved_fd[i] = open("/dev/null", O_RDONLY);
    }

    init_domain_name();
    sort_networks();
    (void)print_networks(sorted_networks_ptr,sorted_networks_cnt, TRUE);
    print_acls();

    if ( local_networks ) {
	local_networks_sorted = (struct cidr_net**)sort_n(local_networks, &local_networks_sorted_counter);
	print_networks(local_networks_sorted, local_networks_sorted_counter, FALSE);
    }
    if ( local_domains ) {
	verb_printf("Local domains:\n");
	print_dom_list(local_domains );
    }
    if ( !mem_max_val ) {
	mem_max_val = 20 * 1024 * 1024;
	lo_mark_val = 15 * 1024 * 1024;
	hi_mark_val = 17 * 1024 * 1024;
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

    report_limits();
    open_db();
    prepare_storages();
    my_log( "oops %s Started\n", VERSION);
    version = VERSION;
#ifdef	DB_VERSION_STRING
    my_log("DB engine by %s\n", DB_VERSION_STRING);
    db_ver = DB_VERSION_STRING;
#else
    db_ver = "Unknown";
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
#if	DB_VERSION_MAJOR<3
    if ( dbhome[0] && db_appexit(dbenv) ) {
	my_log("db_appexit failed");
    }
    if ( dbenv ) free(dbenv);
#else
    if ( dbenv ) dbenv->close(dbenv,0);
#endif
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
	if ( groups->srcdomains ) free_dom_list(groups->srcdomains);
	if ( groups->denytimes ) free_denytimes(groups->denytimes);
	if ( groups->badports ) free(groups->badports);
	if ( groups->auth_mods ) leave_l_string_list(groups->auth_mods);
	if ( groups->redir_mods ) leave_l_string_list(groups->redir_mods);
	if ( groups->networks_acl ) free_acl_access(groups->networks_acl);
	free_acl(groups->http);
	free_acl(groups->icp);
	if ( groups->dstdomain_cache )
	    hash_destroy(groups->dstdomain_cache, free_dstd_ce);
	free(groups);
	groups = next;
    }
    if ( sorted_networks_ptr ) {
	free(sorted_networks_ptr);
	sorted_networks_ptr = NULL;
    }
}
void
free_dstd_ce(void *a)
{
    free(a);
}

void
free_denytimes(struct denytime *dt)
{
struct	denytime *next;

    while(dt) {
	next = dt->next;
	free(dt);
	dt = next;
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
			verb_printf("Unknown ACL type\n");
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
			verb_printf("Unknown ACL type\n");
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
	    verb_printf("Group %s\n", group->name);
	    acls = group->http;
	    acl = acls->allow;
	    if ( acl ) verb_printf("Allow:\n");
	    while( acl ) {
		next_acl = acl->next;
		switch( acl->type ) {
		case ACL_DOMAINDST:
			dom_list = acl->list;
			print_dom_list(dom_list);
			break;
		default:
			verb_printf("Unknown ACL type\n");
			break;
		}
		acl = next_acl;
	    }
	    acl = acls->deny;
	    if ( acl ) verb_printf("Deny:\n");
	    while( acl ) {
		next_acl = acl->next;
		switch( acl->type ) {
		case ACL_DOMAINDST:
			dom_list = acl->list;
			print_dom_list(dom_list);
			break;
		default:
			verb_printf("Unknown ACL type\n");
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
	if ( list->domain ) verb_printf("\tDomain: %s\n", list->domain);
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
    verb_printf("Sorting networks\n");
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
	verb_printf("Net %08x/%-2d[%s]\n", (*n)->network, (*n)->masklen, print_name?(*n)->group->name:"");
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

int
close_listen_so_list(struct listen_so_list *list)
{
struct listen_so_list *next;

    while(list) {
	next = list->next;
	if ( list->so != -1 ) close(list->so);
	xfree(list);
	list = next;
    }
    return(0);
}
int
add_socket_to_listen_list(int so, int flags, void* (*f)(void*))
{
struct	listen_so_list *new = xmalloc(sizeof(*new),""), *next;

    if ( !new ) return(1);
    new->so = so;
    new->flags = flags;
    new->process_call = f;
    new->next = NULL;
    if ( !listen_so_list ) {
	listen_so_list = new;
	return(0);
    } else {
	next = listen_so_list;
	while (next->next)
	    next = next->next;
	next->next = new;
    }
    return(0);
}
void
open_db()
{
int	rc;

    dbp = NULL;
#if	DB_VERSION_MAJOR<3
    dbenv = calloc(sizeof(*dbenv),1);
    bzero(&dbinfo,sizeof(dbinfo));
    dbinfo.db_cachesize = db_cachesize;
    dbinfo.db_pagesize = 16*1024;	/* 16k */
    dbinfo.bt_compare = my_bt_compare;
    if ( !dbhome[0] || !dbname[0] ) return;
    if (db_appinit(dbhome, NULL, dbenv, 
    		DB_CREATE|DB_THREAD) ) {
		my_log("db_appinit(%s) failed: %s\n", dbhome, strerror(errno));
    }
    if ( (rc = db_open(dbname, DB_BTREE,
    		DB_CREATE|DB_THREAD,
    		0644,
    		dbenv,
    		&dbinfo,
    		&dbp)) ) {
	my_log("db_open: %s\n", strerror(rc));
	dbp = NULL;
    }
#else
    if ( !dbhome[0] || !dbname[0]) return;
    if ( db_env_create(&dbenv, 0) )
	return;
    dbenv->set_errfile(dbenv, stderr);
    dbenv->set_errpfx(dbenv, "oops");
    dbenv->set_cachesize(dbenv, 0, db_cachesize, 0);
    rc = dbenv->open(dbenv, dbhome, NULL,
	DB_CREATE|DB_THREAD|DB_INIT_MPOOL,
	0);
    if ( rc ) {
	my_log("Can't open dbenv.\n");
	dbenv->close(dbenv, 0); dbenv = NULL;
	return;
    }
    rc = db_create(&dbp, dbenv, 0);
    if ( rc ) {
	dbenv->close(dbenv, 0); dbenv = NULL;
	dbp = NULL;
	return;
    }
    dbp->set_bt_compare(dbp, my_bt_compare);
    dbp->set_pagesize(dbp, 16*1024);
    rc = dbp->open(dbp, dbname, NULL, DB_BTREE, DB_CREATE, 0);
    if ( rc ) {
	my_log("dbp->open(%s): %s\n", dbname, db_strerror(rc));
	dbenv->close(dbenv, 0); dbenv = NULL;
	dbp = NULL;
	return;
    }
#endif
}
void
set_user()
{
int		rc;
struct passwd	*pwd = NULL;
         
    if ( (pwd = getpwnam(oops_user)) ) {
	rc = setgid(pwd->pw_gid);
	if ( rc == -1 )
	    printf("set_user: Can't setgid(): %s\n", strerror(errno));
	rc = setuid(pwd->pw_uid);
	if ( rc == -1 )
	    printf("set_user: Can't setuid(): %s\n", strerror(errno));
    } else
	printf("set_user: Can't getpwnam('%s')\n", oops_user);
}
