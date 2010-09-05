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

#define		OOPS_MAIN
#include	"oops.h"
#undef		OOPS_MAIN

#include	"version.h"

extern	int	readconfig(char*);

int	operation;
char	hostname[64];
struct	sockaddr_in	Me;
int	run_daemon = 0;
int	pid_d = -1;
struct	obj_hash_entry	hash_table[HASH_SIZE];
int	checked = 0;

static	char	*configfile = "oops.cfg";

static	int	cidr_net_cmp(const void *, const void *);
static	int	close_listen_so_list(void);
static	void	free_acl(struct acls *);
static	void	free_bind_acl_list(bind_acl_t*);
static	void	free_dstd_ce(void*);
static	void	free_peers(struct peer *);
static	void	print_acls(void);
static	void	print_dom_list(struct domain_list *);
static	void	remove_limits(void);
static	void	report_limits(void);
static	int	usage(void);


#if	defined(_WIN32)
BOOL	WINAPI	KillHandler(DWORD dwCtrlType);
#endif

time_t			start_time;
struct			mem_obj	*youngest_obj, *oldest_obj;
pthread_rwlock_t	config_lock;
pthread_rwlock_t	db_lock;
char    		logfile[MAXPATHLEN], pidfile[MAXPATHLEN], base[MAXPATHLEN];
char    		accesslog[MAXPATHLEN];
char    		statisticslog[MAXPATHLEN];
char			dbhome[MAXPATHLEN];
char			disk_state_string[MAXPATHLEN];
int			db_in_use, broken_db;
char			dbname[MAXPATHLEN];
int			reserved_fd[RESERVED_FD];
int			accesslog_num, accesslog_size;
int			log_num, log_size;
unsigned int		maxresident;
unsigned int		minresident;
int			icp_so;
int			server_so;
int			peer_down_interval;
char    		icons_path[MAXPATHLEN];
char    		icons_port[64];
char    		icons_host[MAXPATHLEN];
char    		mem_max[MAXPATHLEN];
char    		lo_mark[MAXPATHLEN];
char    		hi_mark[MAXPATHLEN];
u_short 		internal_http_port;
char    		connect_from[64];
char			parent_host[64];
int			parent_port;
char			*parent_auth;
int			always_check_freshness;
int			force_http11;
unsigned int		force_completion;
refresh_pattern_t	*global_refresh_pattern;
int			max_rate_per_socket;
int			one_second_proxy_requests;
struct	domain_list 	*local_domains;
struct	cidr_net	*local_networks;
struct	cidr_net	**local_networks_sorted;
int			local_networks_sorted_counter;
struct	sockaddr_in	connect_from_sa, *connect_from_sa_p;
struct	sockaddr_in	ns_sa[OOPSMAXNS];
int			ns_configured;
u_short 		http_port;
u_short			icp_port;
char			*bind_addr;
struct			string_list	*stop_cache;
struct			storage_st	*storages, *next_alloc_storage;
int			default_expire_value;
int			max_expire_value;
int			ftp_expire_value;
int			default_expire_interval;
int			last_modified_factor;
int			disk_low_free, disk_hi_free;
int			kill_request, reconfig_request;
volatile	time_t	global_sec_timer;
int			dns_ttl;
int			icp_timeout;
int			accesslog_buffered;
int			logfile_buffered;
int			verbose_startup;
int			verbosity_level;
int			check_config_only;
int			skip_check;
unsigned            negative_cache;

pthread_mutex_t		obj_chain;
pthread_mutex_t		malloc_mutex;
pthread_mutex_t		clients_lock;
pthread_mutex_t		icp_resolver_lock;
pthread_mutex_t		dns_cache_lock;
pthread_mutex_t		st_check_in_progr_lock;
pthread_mutex_t		mktime_lock;
pthread_mutex_t		flush_mem_cache_lock;

int			use_workers;
int			current_workers;
int			max_workers;
int			total_alloc;
int			clients_number;
int			total_objects;
char			*version;
pid_t			my_pid;
int			st_check_in_progr;
struct	oops_stat	oops_stat;
struct	peer		*peers;
struct	group		*groups;
struct	cidr_net	**sorted_networks_ptr;
struct	listen_so_list	*listen_so_list;
int			sorted_networks_cnt;
int		mem_max_val, lo_mark_val, hi_mark_val, swap_advance;
u_short		internal_http_port;
struct	obj_hash_entry	hash_table[HASH_SIZE];
struct	dns_hash_head		dns_hash[DNS_HASH_SIZE];
hash_t		*icp_requests_hash = NULL;
list_t		blacklist;
char		domain_name[MAXHOSTNAMELEN+1];
char		host_name[MAXHOSTNAMELEN+1];
char		*oops_user;
char            *ftp_passw;
char		*oops_chroot;
uid_t           oops_uid = -1;
int             insert_via;
int             insert_x_forwarded_for;
int		dont_cache_without_last_modified;
int		storages_ready;
int             fetch_with_client_speed;
int             dst_ip_acl_present;

named_acl_t	*named_acls;
struct charset	*charsets;
acl_chk_list_hdr_t	*acl_allow;
acl_chk_list_hdr_t	*acl_deny;
acl_chk_list_hdr_t	*stop_cache_acl;
acl_chk_list_hdr_t	*always_check_freshness_acl;
bind_acl_t		*bind_acl_list;
int		blacklist_len;
unsigned int	start_red;
unsigned int	refuse_at;
filebuff_t	logbuff;
filebuff_t	accesslogbuff;

struct denytime	*expiretime;

struct	rq_hash_entry	rq_hash[RQ_HASH_SIZE];
struct	ip_hash_head	ip_hash[IP_HASH_SIZE];

workq_t icp_workq;
workq_t wq;

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
free_stop_cache(void)
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
	if ( groups->redir_mods ) leave_l_mod_call_list(groups->redir_mods);
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

static void
sort_networks(void)
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
	sorted_networks_ptr = xmalloc(sorted_networks_cnt * sizeof(struct cidr_net*),"sort_networks(): 1");
	if ( !sorted_networks_ptr ) {
	    my_xlog(OOPS_LOG_SEVERE, "sort_networks(): No mem for sorted_networks.\n");
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
    verb_printf("sort_networks(): Sorting networks.\n");
    qsort(sorted_networks_ptr, sorted_networks_cnt, sizeof(struct cidr_net*),
    	 cidr_net_cmp);
}

void
print_networks(struct cidr_net **n, int i, int print_name)
{
int k=0;
    if ( !n || !i ) return;
    while( k < i) {
	verb_printf("print_networks(): Net %08x/%-2d[%s]\n", (*n)->network, (*n)->masklen, print_name?(*n)->group->name:"");
	k++; n++;
    }
}

static int
usage(void)
{
    printf("usage:  oops [-{C|c} config_filename] [-v] [-V] [-w num] [-W num]\n");
    printf("             [-x acdfhinsACDFHINS] [-{Z|z}]\n");
    printf("-C|c filename - path to config file (-C - config test).\n");
    printf("-d            detaches from the terminal, so runs as daemon.\n");
    printf("-v            - verbose startup.\n");
    printf("-V            - show version info.\n");
    printf("-w number     - use thread pool. number define initial size of the pool.\n");
    printf("-W number     - limit thread pool size to number.\n");
    printf("-x[abcdfhins] - log level (a-all, b-cache, c-notice, d-debug, f-ftp, h-http,\n");
    printf("                           i-information, n-dns, s-storages).\n");
    printf("-x[ABCDFHINS]  - negative log level.\n");
    printf("-z|Z          - format storages.\n");
    return(0);
}

int
main(int argc, char **argv)
{
char	*vlvls;
int	c, i;
int	format_storages = 0;

    use_workers = 0;
    max_workers = 0;
    current_workers = 0;
    check_config_only = FALSE;
    verbose_startup = FALSE;
    verbosity_level = OOPS_LOG_SEVERE | OOPS_LOG_PRINT | OOPS_LOG_NOTICE;
    /* set stdout unbuffered					*/
    setbuf(stdout, NULL);
    /* stderr by default is unbuffered, but this wont hurt 	*/
    setbuf(stderr, NULL);

#if	defined(_WIN32)
    SetConsoleTitle("Oops Internet Object Cache");
    if ( SetConsoleCtrlHandler(KillHandler, TRUE) == 0 )
	my_xlog(OOPS_LOG_PRINT, "main(): SetConsoleCtrlHandler(): %m\n");

    if ( winsock_init() == -1 )
	exit(1);
#endif	/* _WIN32 */

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
		break;
	case('x'):
		vlvls = optarg;
		while ( *vlvls ) {
		    switch( *vlvls ) {
			case 'a':
				verbosity_level = -1;
				break;
			case 'A':
				verbosity_level = OOPS_LOG_SEVERE | OOPS_LOG_PRINT;
				break;
			case 'b':
				verbosity_level |= OOPS_LOG_CACHE;
				break;
			case 'B':
				verbosity_level &= ~ OOPS_LOG_CACHE;
				break;

			case 'c':
				verbosity_level |= OOPS_LOG_NOTICE;
				break;
			case 'C':
				verbosity_level &= ~ OOPS_LOG_NOTICE;
				break;

			case 'd':
				verbosity_level |= OOPS_LOG_DBG;
				break;
			case 'D':
				verbosity_level &= ~ OOPS_LOG_DBG;
				break;

			case 'f':
				verbosity_level |= OOPS_LOG_FTP;
				break;
			case 'F':
				verbosity_level &= ~ OOPS_LOG_FTP;
				break;

			case 'h':
				verbosity_level |= OOPS_LOG_HTTP;
				break;
			case 'H':
				verbosity_level &= ~ OOPS_LOG_HTTP;
				break;

			case 'i':
				verbosity_level |= OOPS_LOG_INFORM;
				break;
			case 'I':
				verbosity_level &= ~ OOPS_LOG_INFORM;
				break;

			case 'n':
				verbosity_level |= OOPS_LOG_DNS;
				break;
			case 'N':
				verbosity_level &= ~ OOPS_LOG_DNS;
				break;

			case 's':
				verbosity_level |= OOPS_LOG_STOR;
				break;
			case 'S':
				verbosity_level &= ~ OOPS_LOG_STOR;
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
	    break;
	default:
	    printf("Invalid option '%c'\n", c);
	    usage();
	    exit(1);
	}
    }

#if     __FreeBSD__ >= 3
    siginterrupt(SIGTERM, 1);
    siginterrupt(SIGHUP, 1);
    siginterrupt(SIGINT, 1);
    siginterrupt(SIGWINCH, 1);
#endif
        
    setlocale(LC_ALL, "");
    if ( run_daemon ) daemon(TRUE, TRUE);
    my_pid = getpid();

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
    if ( (max_workers  > 0) && (use_workers <= 0) )
	use_workers = MAX(1, max_workers/2);
    if ( (use_workers > 0) && (max_workers <= 0) ) {
	max_workers = 250;
    }
    remove_limits();
    for(i=0;i<HASH_SIZE;i++) {
	bzero(&hash_table[i], sizeof(hash_table[i]));
	pthread_mutex_init(&hash_table[i].lock, NULL);
	pthread_mutex_init(&hash_table[i].size_lock, NULL);
    }
    for(i=0;i<RQ_HASH_SIZE;i++) {
	bzero(&rq_hash[i], sizeof(rq_hash[i]));
	pthread_mutex_init(&rq_hash[i].lock, NULL);
    }
    for(i=0;i<IP_HASH_SIZE;i++) {
	bzero(&ip_hash[i], sizeof(ip_hash[i]));
	pthread_mutex_init(&ip_hash[i].lock, NULL);
    }
    for(i=0;i<DNS_HASH_SIZE;i++)
	dns_hash[i].last = dns_hash[i].first = NULL;

#if	defined(SOLARIS) && defined(_SC_NPROCESSORS_ONLN)
    {
    int np = sysconf(_SC_NPROCESSORS_ONLN);
	if ( np > 1 ) {
	    verb_printf("Set concurrency to %d\n", np*2);
	    if ( !thr_setconcurrency(np*2) )
		verb_printf("Done.\n");
	    else
		verb_printf("Failed.\n");
	}
    }
#endif

    server_so = -1;
    icp_so = -1;
    groups = 0;
    stop_cache = NULL;
    storages = NULL;
    total_alloc = 0;
    clients_number = 0;
    peers = NULL;
    peer_down_interval = 10 ;			/* default 10 sec. */
    local_domains = NULL;
    local_networks	= NULL;
    local_networks_sorted = NULL;
    local_networks_sorted_counter = 0;
    listen_so_list = NULL;
    oldest_obj = youngest_obj = NULL;
    pthread_mutex_init(&obj_chain, NULL);
    pthread_mutex_init(&malloc_mutex, NULL);
    pthread_mutex_init(&clients_lock, NULL);
    pthread_mutex_init(&icp_resolver_lock, NULL);
    pthread_mutex_init(&dns_cache_lock, NULL);
    pthread_mutex_init(&st_check_in_progr_lock, NULL);
    pthread_mutex_init(&mktime_lock, NULL);
    pthread_mutex_init(&flush_mem_cache_lock, NULL);
    pthread_rwlock_init(&config_lock, NULL);
    pthread_rwlock_init(&db_lock, NULL);
    icp_requests_hash = hash_init(128, HASH_KEY_INT);
    list_init(&blacklist);
    workq_init(&icp_workq, 64, icp_processor);
    kill_request = 0;
    global_sec_timer = time(NULL);
    bzero(&oops_stat, sizeof(oops_stat));
    pthread_mutex_init(&oops_stat.s_lock, NULL);
    named_acls = NULL;
    global_refresh_pattern = NULL;
    charsets = NULL;
    acl_allow = acl_deny = NULL;
    always_check_freshness_acl = NULL;
    stop_cache_acl = NULL;
    oops_user = NULL;
    ftp_passw = NULL;
    oops_chroot = NULL;
    bind_acl_list = NULL;
    one_second_proxy_requests = 0;
    bzero(&logbuff, sizeof(logbuff)); logbuff.fd = -1;
    bzero(&accesslogbuff, sizeof(accesslogbuff));  accesslogbuff.fd = -1;
    init_filebuff(&logbuff);
    init_filebuff(&accesslogbuff);
    parent_auth = NULL;
    expiretime = NULL;

    if ( !check_config_only )
	load_modules();
    base_64_init();

    /* reserve some fd's	*/
    for(i=0;i<RESERVED_FD;i++)
	reserved_fd[i] = open(_PATH_DEVNULL, O_RDONLY);

run:
    reconfig_request = 1;
    pthread_mutex_lock(&st_check_in_progr_lock);
    st_check_in_progr = TRUE;
    pthread_mutex_unlock(&st_check_in_progr_lock);
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
    swap_advance = 1;
    parent_port		= 0;
    IF_FREE(parent_auth);
    http_port		= 3128;
    icp_port		= 3130;
    internal_http_port	= 3129;
    max_rate_per_socket = 0;
    blacklist_len	= 0;
    start_red		= 0;
    refuse_at		= 0;

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
    minresident		= DEFAULT_MINRESIDENT;
    dns_ttl		= DEFAULT_DNS_TTL;
    icp_timeout		= DEFAULT_ICP_TIMEOUT;
    accesslog_buffered	= FALSE;
    logfile_buffered	= FALSE;
    insert_x_forwarded_for = TRUE;
    insert_via		= TRUE;
    dont_cache_without_last_modified = FALSE;
    storages_ready = FALSE;
    fetch_with_client_speed = TRUE;
    dst_ip_acl_present = FALSE;
    negative_cache = 0;
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

    if ( oops_user ) {
	free(oops_user);
	oops_user = NULL;
    }
    if ( ftp_passw ) {
	free(ftp_passw);
	ftp_passw = NULL;
    }
    if ( oops_chroot ) {
	free(oops_chroot);
	oops_chroot = NULL;
    }

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

    if ( always_check_freshness_acl ) {
	free_acl_access(always_check_freshness_acl);
	always_check_freshness_acl = NULL;
    }

    if ( bind_acl_list ) {
	free_bind_acl_list(bind_acl_list);
	bind_acl_list = NULL;
    }

    if ( expiretime != NULL ) {
	free_denytimes(expiretime);
	expiretime = NULL;
    }

    /* release reserved fd's	*/
    for(i=0;i<RESERVED_FD;i++)
	if ( reserved_fd[i] >= 0 )
	    close(reserved_fd[i]);

    /* go read config */
    if ( readconfig(configfile) ) return(1);
    if ( check_config_only ) return(0);

    if ( listen_so_list ) {
	close_listen_so_list();
	/* we set listen_so_list = NULL; in close_listen_so_list() if need */
    }

    if ( oops_chroot ) {
#if	defined(HAVE_CHROOT)
	verb_printf("changing root to %s\n", oops_chroot);
	if ( chroot(oops_chroot) == -1 )
	    verb_printf("Can't chroot(): %m\n");
#endif	/* HAVE_CHROOT */
    }

    if ( pidfile[0] != 0 && (pid_d == -1) ) {
	char	pid[11];
	flock_t fl;

	pid_d = open(pidfile, O_RDWR|O_CREAT|O_NONBLOCK, S_IRUSR|S_IWUSR|S_IRGRP);
	if ( pid_d == -1 ) {
	    fprintf(stderr, "main(): Fatal: Can't create pid file.\n");
	    my_xlog(OOPS_LOG_SEVERE, "main(): Fatal: Can't create pid file: %m\n");
	    do_exit(1);
	}
#if	!defined(_WIN32)
	bzero(&fl, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = 0; fl.l_len = 0;
	if ( fcntl(pid_d, F_SETLK, &fl) < 0 ) {
	    fprintf(stderr, "main(): Fatal: Can't lock pid file.\n");
	    my_xlog(OOPS_LOG_SEVERE, "main(): Fatal: Can't lock pid file: %m\n");
	    do_exit(1);
	}
#endif	/* !_WIN32 */
	snprintf(pid, sizeof(pid)-1, "%-10d", (int)getpid());
	write(pid_d, pid, strlen(pid));
    }

    if ( oops_user ) set_euser(oops_user);
    if ( logfile[0] != 0 ) {
	reopen_filebuff(&logbuff, logfile, logfile_buffered);
    }
    if ( accesslog[0] != 0 ) {
	reopen_filebuff(&accesslogbuff, accesslog, accesslog_buffered);
    }
    if ( format_storages ) {
	do_format_storages();
	return(0);
    }

    next_alloc_storage = NULL;
    db_in_use = db_mod_open();
    broken_db = FALSE;
    prepare_storages();

    if ( oops_user ) set_euser(NULL);	/* back to saved uid */

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
	print_dom_list(local_domains);
    }
    if ( !mem_max_val ) {
	mem_max_val = 20 * 1024 * 1024;
	lo_mark_val = 15 * 1024 * 1024;
	hi_mark_val = 17 * 1024 * 1024;
    }
    reconfig_request = 0;
    UNLOCK_CONFIG;

    run_modules();

    /* reserve them again	*/
    for(i=0;i<RESERVED_FD;i++)
	reserved_fd[i] = open(_PATH_DEVNULL, O_RDONLY);

    if ( disk_hi_free >= 100          ) disk_hi_free  = DEFAULT_HI_FREE;
    if ( disk_low_free > disk_hi_free ) disk_low_free = disk_hi_free;
    if ( connect_from[0] != 0 ) {
	connect_from_sa_p = &connect_from_sa;
	if ( str_to_sa(connect_from, (struct sockaddr*)connect_from_sa_p) ) {
	    my_xlog(OOPS_LOG_SEVERE, "main(): WARNING: can't resolve %s, binding disabled.\n",
	    	connect_from);
	    connect_from_sa_p = NULL;
	} else
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "main(): Binding to %s enabled.\n", connect_from);
    } else
	connect_from_sa_p = NULL;

    report_limits();
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "main(): oops %s Started.\n", VERSION);
    version = VERSION;
    bzero(&Me, sizeof(Me));
    Me.sin_family = AF_INET;
    /* this is all we need to start server */


    skip_check = 0;
    run();
    reconfig_request = 1;
    WRLOCK_CONFIG ;
    close_filebuff(&logbuff);
    close_filebuff(&accesslogbuff);
    if ( db_in_use ) {
	db_mod_close();
	db_in_use = FALSE;
    }
    storages_ready = FALSE;
    reconfig_request = 0;
    UNLOCK_CONFIG ;
    goto run;

}

static void
free_dstd_ce(void *a)
{
    xfree(a);
}

static void
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
			verb_printf("free_acl(): Unknown ACL type\n");
			break;
		}
		xfree(acl);
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
		xfree(acl);
		acl = next_acl;
	    }
	    xfree(acls);
	}
}

static void
print_acls(void)
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
			verb_printf("Unknown ACL type.\n");
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

static void
print_dom_list(struct domain_list *list)
{
struct	domain_list	*next;

    while(list) {
	next = list->next;
	if ( list->domain ) verb_printf("\tDomain: %s\n", list->domain);
	list = next;
    }
}

static int
cidr_net_cmp(const void *a1, const void *a2)
{
struct cidr_net	*n1, *n2;

    n1 = *((struct cidr_net**)a1);
    n2 = *((struct cidr_net**)a2);
    return(n2->masklen - n1->masklen);
}

static void
free_peers(struct peer *peer)
{
struct	peer	*next;
    while(peer) {
	next = peer->next;
	if ( peer->name )
	    free(peer->name);
	if ( peer->acls )
	    free_acl(peer->acls);
	IF_FREE(peer->my_auth);
	if ( peer->peer_access )
	    free_acl_access(peer->peer_access);
	free(peer);
	peer = next;
    }
}

static int
close_listen_so_list(void)
{
struct listen_so_list *list = listen_so_list, *next, *new, *new_curr=NULL;

    if ( !oops_user ) goto just_free;

    new = NULL;
    while ( list ) {
	next = list->next;
	/* we will close any non-privileged socket */
	if ( list->port && (list->port < IPPORT_RESERVED) ) {
	    if ( !new ) {
		new = new_curr = list;
		list->next = NULL;
	    } else {
		new_curr->next = list;
		new_curr = list;
		list->next = NULL;
	    }
	} else {
	    if ( list->so != -1 ) CLOSE(list->so);
	    xfree(list);
	}
	list = next;
    }
    listen_so_list = new;
    return(0);

just_free:
    while(list) {
	next = list->next;
	if ( list->so != -1 ) CLOSE(list->so);
	xfree(list);
	list = next;
    }
    listen_so_list = NULL;
    return(0);
}

int
add_socket_to_listen_list(int so, u_short port, struct in_addr *addr, int flags, void* (*f)(void*))
{
struct	listen_so_list *new = xmalloc(sizeof(*new),"add_socket_to_listen_list(): 1"), *next;

    if ( !new ) return(1);
    bzero(new, sizeof(*new));
    new->so = so;
    new->port = port;
    new->flags = flags;
    if ( addr ) new->addr.s_addr = addr->s_addr;
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
set_user(void)
{
#if	!defined(_WIN32)
int		rc;
struct passwd	*pwd = NULL;
         
    if ( (pwd = getpwnam(oops_user)) != 0 ) {
	rc = setgid(pwd->pw_gid);
	if ( rc == -1 )
	    verb_printf("set_user(): Can't setgid(): %m\n");
        else
            oops_uid = pwd->pw_uid;

#if	defined(LINUX)
	/* due to linuxthreads design you can not call setuid even
	   when you call setuid before any thread creation
	 */
	rc = seteuid(pwd->pw_uid);
#else
	rc = setuid(pwd->pw_uid);
#endif
	if ( rc == -1 )
	    verb_printf("set_user(): Can't setuid(): %m\n");
    } else
	printf("set_user(): Can't getpwnam() `%s'.\n", oops_user);
#endif	/* !_WIN32 */
}

static void
free_bind_acl_list(bind_acl_t* list)
{
bind_acl_t	*next;

    while(list) {
	next = list->next;
	if ( list->name ) free(list->name);
	if ( list->acl_list ) free_acl_access(list->acl_list);
	free(list);
	list = next;
    }
}

static void
remove_limits(void)
{
#if	!defined(_WIN32)
struct	rlimit	rl = {RLIM_INFINITY, RLIM_INFINITY};

#if	defined(RLIMIT_DATA)
	if ( !getrlimit(RLIMIT_DATA, &rl) ) {
	    rl.rlim_cur = rl.rlim_max;
	    if ( !setrlimit(RLIMIT_DATA, &rl) ) {
		printf("RLIMIT_DATA changed to maximum: %u\n", (unsigned)rl.rlim_max);
	    } else {
		printf("warning: Can't change RLIMIT_DATA\n");
	    }
	}
#endif
#if	defined(RLIMIT_NOFILE)
	if ( !getrlimit(RLIMIT_NOFILE, &rl) ) {
	    rl.rlim_cur = rl.rlim_max = OPEN_FILES_MAXIMUM;
	    if ( !setrlimit(RLIMIT_NOFILE, &rl) ) {
		printf("RLIMIT_NOFILE changed to maximum: %u\n", (unsigned)rl.rlim_max);
	    } else {
		printf("warning: Can't change RLIMIT_NOFILE\n");
	    }
	}
#endif
#if	defined(_RLIMIT_CORE)
	if ( !getrlimit(RLIMIT_CORE, &rl) ) {
	    rl.rlim_cur = 0;
	    if ( !setrlimit(RLIMIT_CORE, &rl) ) {
		printf("RLIMIT_CORE changed to minimum: %u\n", (unsigned)rl.rlim_cur);
	    } else {
		printf("warning: Can't change RLIMIT_CORE\n");
	    }
	}
#endif
#if	defined(RLIMIT_NPROC) && defined(LINUX)
	if ( !getrlimit(RLIMIT_NPROC, &rl) ) {
	    rl.rlim_cur = RLIM_INFINITY;
	    if ( !setrlimit(RLIMIT_NPROC, &rl) ) {
		printf("RLIMIT_NPROC changed to maximum: %u\n", (unsigned)rl.rlim_cur);
	    } else {
		printf("warning: Can't change RLIMIT_NPROC\n");
	    }
	}
#endif
#endif	/* !_WIN32 */
}

static void
report_limits(void)
{
#if	!defined(_WIN32)
struct	rlimit	rl = {RLIM_INFINITY, RLIM_INFINITY};

#if	defined(RLIMIT_DATA)
	if ( !getrlimit(RLIMIT_DATA, &rl) ) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "report_limits(): RLIMIT_DATA: %u\n", (unsigned)rl.rlim_cur);
	}
#endif
#if	defined(RLIMIT_NOFILE)
	if ( !getrlimit(RLIMIT_NOFILE, &rl) ) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "report_limits(): RLIMIT_NOFILE: %u\n", (unsigned)rl.rlim_cur);
	}
#endif
#if	defined(RLIMIT_CORE)
	if ( !getrlimit(RLIMIT_CORE, &rl) ) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "report_limits(): RLIMIT_CORE: %u\n", (unsigned)rl.rlim_cur);
	}
#endif
#if	defined(RLIMIT_NPROC) && defined(LINUX)
	if ( !getrlimit(RLIMIT_NPROC, &rl) ) {
	    if ( !getrlimit(RLIMIT_NPROC, &rl) ) /* ??? same condition ??? */    {
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "report_limits(): RLIMIT_NPROC: %u\n", (unsigned)rl.rlim_cur);
	    }
	}
#endif
#endif	/* !_WIN32 */
}
