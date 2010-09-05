#include <assert.h>
#include "llt.h"

#if	!defined(HAVE_UINT32_T)
typedef	unsigned	uint32_t;
#endif

#if   defined(BSDOS) || defined(LINUX) || defined(FREEBSD)
#define       flock_t struct flock
#endif

#if	!defined(MAX)
#define	MAX(a,b)	((a)>(b)?(a):(b))
#endif
#if	!defined(MIN)
#define	MIN(a,b)	((a)>(b)?(b):(a))
#endif

#if	!defined(MAXHOSTNAMELEN)
#define	MAXHOSTNAMELEN	256
#endif

#define	DECREMENT_REFS(obj)\
	{\
		lock_obj(obj);\
		obj->refs--;\
		unlock_obj(obj);\
	}
#define	INCREMENT_REFS(obj)\
	{\
		lock_obj(obj);\
		obj->refs++;\
		unlock_obj(obj);\
	}

#define	WRLOCK_STORAGE(s)\
	{\
		rwl_wrlock(&(s->storage_lock));\
	}

#define	RDLOCK_STORAGE(s)\
	{\
		rwl_rdlock(&(s->storage_lock));\
	}

#define	UNLOCK_STORAGE(s)\
	{\
		rwl_unlock(&(s->storage_lock));\
	}

#define	WRLOCK_DB\
	{\
		rwl_wrlock(&db_lock);\
	}

#define	RDLOCK_DB\
	{\
		rwl_rdlock(&db_lock);\
	}

#define	UNLOCK_DB\
	{\
		rwl_unlock(&db_lock);\
	}

#define	WRLOCK_CONFIG \
	{\
		rwl_wrlock(&config_lock);\
	}

#define	RDLOCK_CONFIG \
	{\
		rwl_rdlock(&config_lock);\
	}

#define	UNLOCK_CONFIG \
	{\
		rwl_unlock(&config_lock);\
	}

#define	MUST_BREAK	( kill_request | reconfig_request )

#define	SLOWDOWN \
    {\
	int	r;\
	struct  timeval tv;\
	r = group_traffic_load(inet_to_group(&rq->client_sa.sin_addr));\
	tv.tv_sec = 0;tv.tv_usec = 0;\
	if ( r >= 85 ) {\
	    if ( r < 95 ) /* start to slow down */\
		tv.tv_usec = 250;\
	    else if ( r < 100 )\
		tv.tv_usec = 500;\
	    else\
		tv.tv_sec = MIN(2,r/100);\
	    r = select(0, NULL, NULL, NULL, &tv);\
	}\
    }


#define MID(A)		((40*group->cs0.A + 30*group->cs1.A + 30*group->cs2.A)/100)
#define	ROUND(x,b)	((x)%(b)?(((x)/(b)+1)*(b)):(x))
#define	TRUE		(1)
#define	FALSE		(0)

#define	MAXNS		(5)
#define	MAXBADPORTS	(10)

#define	CHUNK_SIZE	(64)
#define	ROUND_CHUNKS(s)	((((s) / CHUNK_SIZE) + 1) * CHUNK_SIZE)

#define	HASH_SIZE	(512)
#define	HASH_MASK	(HASH_SIZE-1)

#define	DNS_HASH_SIZE	(512)
#define	DNS_HASH_MASK	(DNS_HASH_SIZE-1)

#define	METH_GET	0
#define	METH_HEAD	1
#define	METH_POST	2
#define	METH_PUT	3
#define	METH_CONNECT	4
#define	METH_TRACE	5

#define	AND_PUT		1
#define	AND_USE		2
#define	PUT_NEW_ANYWAY	4
#define	NO_DISK_LOOKUP	8

#define	OBJ_EMPTY	0
#define	OBJ_INPROGR	2
#define	OBJ_READY	3

#define	FLAG_DEAD		1	/* obj is unusable anymore	*/
#define	FLAG_FROM_DISK		(1<<1)	/* obj loaded from disk		*/
#define	ANSW_HAS_EXPIRES	(1<<2)
#define	ANSW_NO_CACHE		(1<<3)
#define	ANSW_NO_STORE		(1<<4)
#define	ANSW_HAS_MAX_AGE	(1<<5)
#define	ANSW_MUST_REVALIDATE	(1<<6)
#define	ANSW_PROXY_REVALIDATE	(1<<7)
#define	ANSW_LAST_MODIFIED	(1<<8)
#define	ANSW_SHORT_CONTAINER	(1<<9)

#define	STATUS_OK		200
#define	STATUS_NOT_MODIFIED	304

#define	RQ_HAS_CONTENT_LEN	1
#define	RQ_HAS_IF_MOD_SINCE	(1<<1)
#define	RQ_HAS_NO_STORE		(1<<2)
#define	RQ_HAS_NO_CACHE		(1<<3)
#define	RQ_HAS_MAX_AGE		(1<<4)
#define	RQ_HAS_MAX_STALE	(1<<5)
#define	RQ_HAS_MIN_FRESH	(1<<6)
#define	RQ_HAS_NO_TRANSFORM	(1<<7)
#define	RQ_HAS_ONLY_IF_CACHED	(1<<8)
#define	RQ_HAS_AUTHORIZATION	(1<<9)
#define RQ_GO_DIRECT		(1<<10)
#define	RQ_HAS_CLOSE_CONNECTION (1<<11)
#define	RQ_HAS_BANDWIDTH	(1<<12)
#define	RQ_CONVERT_FROM_CHUNKED (1<<13)

#define	ACCESS_DOMAIN		1
#define ACCESS_PORT		2


#define	MEM_OBJ_MUST_REVALIDATE	1
#define	MEM_OBJ_WARNING_110	2
#define	MEM_OBJ_WARNING_113	4

#define	CRLF			"\r\n"

#define	ANSW_SIZE		(2*1024)
#define	READ_ANSW_TIMEOUT	(10*60)		/* 10 minutes	*/

#define	DEFAULT_EXPIRE_VALUE	(3*24*3600)	/* 3 days	*/
#define	DEFAULT_EXPIRE_INTERVAL	(1*3600)	/* each hour	*/

#define	DEFAULT_LOW_FREE	(5)		/* these values for BIG storages */
#define	DEFAULT_HI_FREE		(6)
#define	DEFAULT_MAXRESIDENT	(1024*1024)	/* 1MB		*/
#define	DEFAULT_DNS_TTL		(30*60)		/* 30 min's	*/
#define	DEFAULT_ICP_TIMEOUT	(1000000)	/* 1 sec	*/

#define	ADDR_AGE		(3600)

#define	ERR_BAD_URL		1
#define	ERR_BAD_PORT		2
#define	ERR_ACC_DOMAIN		3
#define	ERR_DNS_ERR		4
#define	ERR_INTERNAL		5
#define	ERR_ACC_DENIED		6
#define	ERR_TRANSFER		7

#define	SET(a,b)		(a|=b)
#define	CLR(a,b)		(a&=~b)
#define	TEST(a,b)		(a&b)

#define	malloc(x)	xmalloc(x, NULL)
#define	free(x)		xfree(x)

typedef	struct {
	pthread_mutex_t	m;
	int		rwlock;
	pthread_cond_t	readers_ok;
	unsigned int	waiting_writers;
	pthread_cond_t	writer_ok;
} rwl_t;


struct	url {
    char	*proto;
    char	*host;
    u_short	port;
    char	*path;
    char	*httpv;
    char	*login;		/* for non-anonymous */
    char	*password;	/* FTP sessions	     */
};

struct	obj_times {
	time_t			date;		/* from the server answer	*/
	time_t			expires;	/* from the server answer	*/
	time_t			age;		/* Age: from stored answer	*/
	time_t			max_age;	/* max-age: from server		*/
	time_t			last_modified;	/* Last-Modified: from server	*/
};

struct	buff {
	struct	buff	*next;
	int		used;		/* size of stored data			*/
					/* this changes as we add more data	*/
	int		curr_size;	/* size of the buffer itself		*/
					/* this grows as we expand buffer	*/
	char		*data;
};

struct	request {
	struct		sockaddr_in client_sa;
	time_t		request_time;	/* time of request creation	*/
	int		state;
	int		http_major;
	int		http_minor;
	int		meth;
	struct	url	url;
        int		headers_off;
	int		flags;
	int		content_length;
	int		leave_to_read;
	time_t		if_modified_since;
	int		max_age;
	int		max_stale;
	int		min_fresh;
	struct	av	*av_pairs;
	struct	buff	*data;		/* for POST */
};

struct	av {
	char		*attr;
	char		*val;
	struct	av	*next;
};

struct	superb {
	uint32_t		magic;		/* to detect that this is storage	*/
	uint32_t		id;		/* to find needed storage	*/
	uint32_t		blks_total;	/* total_blks			*/
	uint32_t		blks_free;	/* free blocks			*/
	uint32_t		blk_siz;	/* block size			*/
	uint32_t		free_first;	/* first free pointer		*/
	uint32_t		free_last;	
};

/* storage state flag		*/
#define	ST_CHECKED		1	/* storage is checked and fixed (or check skipped by user request */
#define	ST_READY		2	/* storage is ready for using 	*/
#define	ST_FORCE_CLEANUP	4	/* force cleanup on storage	*/

struct	storage_st {
	struct	storage_st	*next;
	char			*path;		/* path to storage	*/
	int			size;		/* size			*/
	int			flags;		/* flags, like ready	*/
	rwl_t			storage_lock;	/* locks for writings	*/
	struct	superb		super;		/* in-memory super	*/
	int			fd;		/* descriptor for access*/
	char			*map;		/* busy map		*/
};

struct	disk_ref {
	uint32_t	blk;			/* block number in storage	*/
	long		id;			/* id of the storage		*/
	size_t		size;			/* stored size			*/
	time_t		expires;		/* expiration date		*/
};

struct	mem_obj {
	struct	mem_obj		*next;		/* in hash			*/
	struct	mem_obj		*prev;		/* in hash			*/
	struct	mem_obj		*older;		/* older object			*/
	struct	mem_obj		*younger;	/* younger			*/
	struct	hash_entry	*hash_back;	/* back pointer to hash chain	*/
	pthread_mutex_t		lock;		/* for refs and obj as whole	*/
	int			refs;		/* references			*/
	int			readers;	/* readers from obj in mem	*/
	int			writers;	/* writers to obj in mem	*/
	int			decision_done;	/* for revalidate process	*/
	pthread_mutex_t		decision_lock;	/* protects for the decision	*/
	pthread_cond_t		decision_cond;
	struct	mem_obj		*child_obj;	/* after reload decision	*/
	struct	url		url;		/* url				*/
	int			state;
	int			flags;
	pthread_mutex_t		state_lock;
	pthread_cond_t		state_cond;
	time_t			filled;		/* when filled			*/
	size_t			size;		/* current data size		*/
	size_t			content_length;	/* what server say about content */
	size_t			resident_size;	/* size of object in memory	*/
	struct	buff		*container;	/* data storage			*/
	pthread_t		creator;	/* creator of obj in mem	*/
	struct	buff		*hot_buff;	/* buf to write			*/
	int			status_code;	/* from the server nswer	*/
	time_t			request_time;	/* when request was made	*/
	time_t			response_time;	/* when responce was received	*/
	struct	obj_times	times;
	struct	av		*headers;	/* headers */
	struct	disk_ref	*disk_ref;	/* disk reference, if loaded from storage	*/
};

struct	output_object {
	struct	av	*headers;
	struct	buff	*body;
	int		flags;
};

struct	hash_entry {
	struct	mem_obj		*next;
	pthread_mutex_t		lock;
	int			size;		/* size of objects in this hash */
	pthread_mutex_t		size_lock;	/* lock to change size		*/
};

struct	server_answ {
#define	GOT_HDR	(1)
	int			state;
	int			flags;
	size_t			content_len;
	int			checked;
	int			status_code;
	struct	obj_times	times;
	struct	av		*headers;
};

struct	ftp_r {
	int		control;	/* control socket	*/
	int		data;		/* data socket		*/
	int		client;		/* client socket	*/
	int		size;		/* result of 'SIZE' cmd */
#define	MODE_PASV	0
#define	MODE_PORT	1
	int		mode;		/* PASV or PORT		*/
	struct	request	*request;	/* referer from orig	*/
	struct	mem_obj	*obj;		/* object		*/
	char		*dehtml_path;	/* de-hmlized path	*/
	struct	buff	*server_log;	/* ftp server answers	*/
	struct	string_list *nlst;	/* NLST results		*/
	int		received;	/* how much data received */
	char		*type;		/* mime type		*/
};

struct	cidr_net {
	int				network;
	int				masklen;
	int				mask;
	struct	group			*group;
	struct	cidr_net		*next;
};

struct	search_list	{
	char				*string;
	struct	search_list		*next;
	char				*off;
	int				len;
};

struct	string_list	{
	char				*string;
	struct	string_list		*next;
};

struct	domain_list	{
	char				*domain;
	int				length;
	struct	domain_list		*next;
};

struct	group_ops_struct {
#define	OP_NETWORKS	1
#define	OP_HTTP		2
#define	OP_ICP		3
#define	OP_BADPORTS	4
#define	OP_BANDWIDTH	5
#define	OP_MISS		6
#define	OP_AUTH_MODS	7
	int				op;
	void				*val;
	struct	group_ops_struct	*next;
};

struct	range {
	int	from;
	int	length;
};
struct	badports {
	struct	range	ranges[MAXBADPORTS];
};

struct	acl {
#define	ACL_DOMAINDST		1
	int			type;	/* what kind of acl? dstdomain, port, etc.. */
	void			*list;	/* acls			*/
	struct	acl		*next;	/* next in chain	*/
};
struct	acls {
	struct	acl	*allow;
	struct	acl	*deny;
};

struct	group_stat {
	int	requests;
	int	bytes;
};

struct	group	{
	char			*name;
	struct	cidr_net	*nets;
	struct	acls		*http;
	struct	acls		*icp;
	struct	badports	*badports;
	int			bandwidth;
	int			miss_deny;	/* TRUE if deny	*/
	struct	string_list	*auth_mods;	/* auth modules */
	pthread_mutex_t		group_mutex;
	struct	group_stat	cs0;		/* current	*/
	struct	group_stat	cs1;		/* prev second	*/
	struct	group_stat	cs2;		/* pre-prev sec */
	struct	group_stat	cs_total;	/* total	*/
	struct  group		*next;
};

struct	domain {
	char			*dom;
	struct	domain		*next;
};

#define	MAX_DNS_ANSWERS	(15)

struct	dns_hash_head {
	struct dns_cache	*first;
	struct dns_cache	*last;
};
struct	dns_cache_item {
	time_t		time;		/* when created or become bad	*/
	char		good;		/* good or bad			*/
	struct	in_addr	address;	/* address itself		*/
};
struct	dns_cache {
	struct dns_cache *next;		/* link				*/
	time_t		time;		/* when filled			*/
	int		stamp;		/* to speed-up search		*/
	char		*name;		/* host name			*/
	short		nitems;		/* how much answers here	*/
	short		nlast;		/* last answered		*/
	short		ngood;		/* how much good entries here	*/
	struct dns_cache_item *items;
};
#define	SOURCE_DIRECT	0
#define	PEER_PARENT	1
#define	PEER_SIBLING	2

#define	PEER_DOWN	1

struct	peer	{
	struct	peer		*next;
	char			*name;
	u_short			http_port;
	u_short			icp_port;
	char			type;		/* peer or parent */
	struct	acls		*acls;
	int			addr_age;	/* resolve only after some timeout */
	struct	sockaddr_in	addr;
	int			state;		/* state like UP/DOWN...	*/
};

struct	icp_queue_elem {
	ll_t			ll;
	/* this part is from requestor		*/
	/* ---------------------------- 	*/
	/* url in icp format			*/
	char			*url;
	/* request number - id of request	*/
	int			rq_n;
	/* how much peers was sent request to	*
	 * (we will wait that many answers)	*/
	int			requests_sent;
	int			waitors;
	/* this is sync part		*/
	/* ---------------------------- */
	pthread_cond_t		icpr_cond;
	pthread_mutex_t		icpr_mutex;
	/* this is answer		*/
	/* ---------------------------- */
	int			status;
	int			type;
	struct	sockaddr_in	peer_sa;
};

struct  charset {
	struct  charset		*next;
	char			*Name;
	struct  string_list	*CharsetAgent;
	char			*Table;
};
                                
#define	LOCK_STATISTICS(s)	pthread_mutex_lock(&s.s_lock)
#define	UNLOCK_STATISTICS(s)	pthread_mutex_unlock(&s.s_lock)

struct	oops_stat {
	pthread_mutex_t	s_lock;
	uint32_t	clients;	/* currently clients in service		*/
	uint32_t	requests_http;	/* total http requests  processed	*/
	uint32_t	hits;		/* total hits				*/
	uint32_t	requests_icp;	/* total icp requests processed		*/
	uint32_t	requests_http0;	/* current minute requests		*/
	uint32_t	hits0;		/* current minute hits			*/
	uint32_t	storages_free;	/* current free storage %%		*/
};

struct		mem_obj	*youngest_obj, *oldest_obj;
rwl_t		config_lock;
rwl_t		log_lock;
rwl_t		db_lock;
char    	logfile[MAXPATHLEN], pidfile[MAXPATHLEN], base[MAXPATHLEN];
char    	accesslog[MAXPATHLEN];
char    	statisticslog[MAXPATHLEN];
char		dbhome[MAXPATHLEN];
DB		*dbp;
char		dbname[MAXPATHLEN];
int		accesslog_num, accesslog_size;
int		log_num, log_size;
int		maxresident;
int		icp_so;
char    	icons_path[MAXPATHLEN];
char    	icons_port[64];
char    	icons_host[MAXPATHLEN];
char    	mem_max[MAXPATHLEN];
char    	lo_mark[MAXPATHLEN];
char    	hi_mark[MAXPATHLEN];
u_short 	internal_http_port;
char    	connect_from[64];
char		parent_host[64];
int		parent_port;
struct	domain_list 	*local_domains;
struct	cidr_net	*local_networks;
struct	cidr_net	**local_networks_sorted;
int			local_networks_sorted_counter;
struct	sockaddr_in	connect_from_sa, *connect_from_sa_p;
struct	sockaddr_in	ns_sa[MAXNS];
int			ns_configured;
u_short 	http_port;
u_short		icp_port;
struct		string_list	*stop_cache;
struct		storage_st	*storages, *next_alloc_storage;
void		*startup_sbrk;
int		default_expire_value;
int		default_expire_interval;
int		disk_low_free, disk_hi_free;
int		kill_request, reconfig_request;
time_t		global_sec_timer;
int		dns_ttl;
int		icp_timeout;

pthread_mutex_t	obj_chain;
pthread_mutex_t	malloc_mutex;
pthread_mutex_t	clients_lock;
pthread_mutex_t	accesslog_lock;
pthread_mutex_t	icp_resolver_lock;
pthread_mutex_t	dns_cache_lock;

DB_ENV			dbenv;
DB_INFO			dbinfo;

int			total_alloc;
int			clients_number;
int			total_objects;
struct	oops_stat	oops_stat;
struct	peer		*peers;
struct	group		*groups;
struct	cidr_net	**sorted_networks_ptr;
int			sorted_networks_cnt;
void			sort_networks();
void			add_to_stop_cache(char*);
int		mem_max_val, hi_mark_val, lo_mark_val;
u_short		internal_http_port;
extern	struct	hash_entry	hash_table[HASH_SIZE];
struct	dns_hash_head		dns_hash[DNS_HASH_SIZE];
#ifdef		SOLARIS
int		daemon(int, int);
#endif
list_t		icp_requests_list;
void		do_exit(int);
void		run();
void		*garbage_collector(void*);
void		*rotate_logs(void*);
void		*clean_disk(void*);
void		*statistics(void*);
void		*deadlock(void*);
void		say_bad_request(int, char*, char*, int, struct request *);
int		parse_url(char*, char*, struct url *, int);
int		sendstr(int, char*);
int		readt(int, char*, int, int);
int		wait_for_read(int, int);
void		*xmalloc(size_t, char*);
void		xfree(void *);
void 		my_log(char *form, ...);
int		in_stop_cache(struct request *);
void		log_access(int elapsed, struct sockaddr_in *sa, char *tag,
		int code, int size, char *meth, struct url *url,
		char* hierarchy, char *content,char *source);
int		http_date(char *date, time_t*);
int		mk1123time(time_t, char*, int);
int		str_to_sa(char*, struct sockaddr*);
struct mem_obj	*create_obj();
struct mem_obj	*locate_in_mem(struct url*, int);
void		leave_obj(struct mem_obj*);
void		change_state(struct mem_obj*, int);
struct	buff	*alloc_buff(int);
int		attach_data(char*, int, struct buff*);
char		*htmlize(char*);
char		*dehtmlize(char*);
char		*html_escaping(char*);
int		check_server_headers(struct server_answ *a, struct mem_obj *obj, struct buff *b);
int		store_in_chain(char *src, int size, struct mem_obj *obj);
void		free_chain(struct buff *);
void		free_avlist(struct av *);
void		free_groups(struct group *);
void		free_stop_cache();
void		free_container(struct buff *buff);
void		free_url(struct url*);
void		free_net_list(struct cidr_net*);
void		ftp_fill_mem_obj(int, struct request *, char *, struct mem_obj*);
struct	cidr_net **sort_n(struct cidr_net*, int*);
int		writen(int, char*, int);
int		writet(int, char*, int, int);
int		tm_to_time(struct tm *, time_t*);
int		tm_cmp(struct tm*, struct tm*);
void		send_error(int, int, char*);
time_t		current_obj_age(struct mem_obj *);
time_t		obj_freshness_lifetime(struct mem_obj *);
int		is_attr(struct av*, char*);
int		send_av_pair(int, char*, char*);
void		increase_hash_size(struct hash_entry*, int);
void		decrease_hash_size(struct hash_entry*, int);
struct	group*	inet_to_group(struct in_addr*);
int		deny_http_access(int, struct request *);
void		rwl_init(rwl_t*);
void		rwl_destroy(rwl_t*);
void		rwl_rdlock(rwl_t*);
void		rwl_wrlock(rwl_t*);
void		rwl_unlock(rwl_t*);
void		remove_limits();
void		free_storages(struct storage_st*);
void		init_storages(struct storage_st*);
void		free_storage(struct storage_st *);
void		init_storage(struct storage_st *);
void		check_storages(struct storage_st *);
void		prepare_storages();
void		do_format_storages(void);
int		locate_url_on_disk(struct url *, struct disk_ref**);
int		load_obj_from_disk(struct mem_obj *, struct disk_ref *);
struct storage_st *locate_storage_by_id(long);
int		erase_from_disk(char *, struct disk_ref*);
void		process_icp_msg(int so, char *buf, int len, struct sockaddr_in *sa);
void		my_sleep(int);
int		calculate_resident_size(struct mem_obj *);
void		leave_obj(struct mem_obj*);
void		destroy_obj(struct mem_obj*);
int		move_obj_to_storage(struct mem_obj *obj, struct storage_st **st, struct disk_ref **);
char		*request_free_blks(struct storage_st*, uint32_t);
int		release_blks(uint32_t n, struct storage_st *storage, struct disk_ref*);
int		flush_super(struct storage_st *);
int		flush_map(struct storage_st *);
char		*my_inet_ntoa(struct sockaddr_in *);
int		set_socket_options(int);
char		*my_inet_ntoa(struct sockaddr_in*);
void		send_ssl(int, struct request*);
int		bind_server_so(int);
int		is_local_dom(char*);
int		is_local_net(struct sockaddr_in*);
void		send_not_cached(int, struct request*, char*);
int		send_icp_requests(struct request *, struct icp_queue_elem*);
void		icp_request_destroy(struct icp_queue_elem*);
int		is_domain_allowed(char*, struct acls *);
struct string_list *add_to_string_list(struct string_list **, char *);
void		free_string_list(struct string_list*);
struct search_list *add_to_search_list(struct search_list **, char *, int);
void		free_search_list(struct search_list*);
void		free_dns_hash_entry(struct dns_cache*);
char		*attr_value(struct av*, char*);
char		*lookup_mime_type(char*);
struct	peer	*peer_by_http_addr(struct sockaddr_in*);
char		*base64_encode(char*);
char		*base64_decode(char*);
struct	charset	*lookup_charset_by_name(struct charset *, char*);
struct	charset	*lookup_charset_by_Agent(struct charset *, char*);
struct	charset	*add_new_charset(struct charset **, char *);
int		free_charsets(struct charset*);
int		miss_deny(struct group*);
int		put_av_pair(struct av **, char *, char*);
struct	av	*lookup_av_by_attr(struct av*, char*);
