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

#if	defined(_WIN32)
#include	"lib/win32/config.h"
#include	"lib/win32/environment.h"
#else
#include	"config.h"
#include	"environment.h"
#endif
/*
#if	DB_VERSION_MAJOR >= 3
#undef	USE_INTERNAL_DB_LOCKS
#endif
*/
#define	forever()	for(;;)

#if	defined(REGEX_H)
#include	REGEX_H
#endif

/* libpcre3/libpcre2/libpcre1 backward compatibility: */

#if     !defined(REG_EXTENDED)
#define REG_EXTENDED 0
#endif

#if     !defined(REG_NOSUB)
#define REG_NOSUB 0
#endif

/* :libpcre3/libpcre2/libpcre1 backward compatibility */

#include "hash.h"
#include "llt.h"
#include "workq.h"

typedef struct	tm	tm_t;

#if	!defined(HAVE_UINT32_T) && !defined(_UINT32_T)
typedef	unsigned	uint32_t;
#endif

#if	!defined(HAVE_UINT16_T)
typedef	unsigned short	uint16_t;
#endif

#if     !defined(HAVE_UINT8_T)
typedef unsigned char	uint8_t;
#endif

#if   defined(BSDOS) || defined(LINUX) || defined(FREEBSD) || defined(OSF) || defined(OPENBSD)
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
		pthread_rwlock_wrlock(&(s->storage_lock));\
	}

#define	RDLOCK_STORAGE(s)\
	{\
		pthread_rwlock_rdlock(&(s->storage_lock));\
	}

#define	UNLOCK_STORAGE(s)\
	{\
		pthread_rwlock_unlock(&(s->storage_lock));\
	}

#define	WRLOCK_DB\
	{\
		pthread_rwlock_wrlock(&db_lock);\
	}

#define	RDLOCK_DB\
	{\
		pthread_rwlock_rdlock(&db_lock);\
	}

#define	UNLOCK_DB\
	{\
		pthread_rwlock_unlock(&db_lock);\
	}

#define	WRLOCK_CONFIG \
	{\
		pthread_rwlock_wrlock(&config_lock);\
	}

#define	RDLOCK_CONFIG \
	{\
		pthread_rwlock_rdlock(&config_lock);\
	}

#define	UNLOCK_CONFIG \
	{\
		pthread_rwlock_unlock(&config_lock);\
	}

#define	MUST_BREAK	( kill_request | reconfig_request )

#define	IF_FREE(p)	{if ( p ) xfree(p);}
#define	IF_STRDUP(d,s)	{if ( d ) xfree(d); d = strdup(s);}

#define	SLOWDOWN \
    {\
	int	r;\
	struct  timeval tv;\
	r = traffic_load(rq);\
	tv.tv_sec = 0;tv.tv_usec = 0;\
	if ( r >= 50 ) {\
	    if ( r < 95 ) /* start to slow down */\
		tv.tv_usec = 100000;\
	    else if ( r < 100 )\
		tv.tv_usec = 200000;\
	    else\
		tv.tv_sec = MIN(5,r/100);\
	    r = poll_descriptors(0, NULL, tv.tv_sec*1000+tv.tv_usec/1000);\
	}\
    }

#define	SLOWDOWN_SESS \
    {\
	int	r;\
	struct  timeval tv;\
	r = sess_traffic_load(rq);\
	tv.tv_sec = 0;tv.tv_usec = 0;\
	if ( r >= 85 ) {\
	    if ( r < 95 ) /* start to slow down */\
		tv.tv_usec = 2500;\
	    else if ( r < 100 )\
		tv.tv_usec = 5000;\
	    else\
		tv.tv_sec = r/100;\
	    r = poll_descriptors(0, NULL, tv.tv_sec*1000+tv.tv_usec/1000);\
	}\
    }

#define	FORCE_COMPLETION(obj) \
	( obj && obj->content_length && obj->size && obj->container && \
	  !TEST(obj->flags, FLAG_DEAD) && \
	  ( ((obj->size - obj->container->used)*100)/obj->content_length >= force_completion))

#define MID(A)		((40*group->cs0.A + 30*group->cs1.A + 30*group->cs2.A)/100)
#define MID_IP(A)	((40*(A->traffic0) + 30*(A->traffic1) + 30*(A->traffic2))/100)
#if	!defined(ABS)
#define	ABS(x)		((x)>0?(x):(-(x)))
#endif
#define	ROUND(x,b)	((x)%(b)?(((x)/(b)+1)*(b)):(x))

#define	OOPSMAXNS	(5)
#define	MAXBADPORTS	(10)

#define		STORAGE_PAGE_SIZE	((off_t)4096)

#define	CHUNK_SIZE	(64)
#define	ROUND_CHUNKS(s)	((((s) / CHUNK_SIZE) + 1) * CHUNK_SIZE)

#define	HASH_SIZE	(1024)
#define	HASH_MASK	(HASH_SIZE-1)

#define	DNS_HASH_SIZE	(512)
#define	DNS_HASH_MASK	(DNS_HASH_SIZE-1)

#define	OOPS_DB_PAGE_SIZE	(4*1024)

#define	METH_GET                0
#define	METH_HEAD               1
#define	METH_POST               2
#define	METH_PUT                3
#define	METH_CONNECT            4
#define	METH_TRACE              5
#define	METH_PROPFIND           6
#define	METH_PROPPATCH          7
#define	METH_DELETE             8
#define	METH_MKCOL              9
#define	METH_COPY               10
#define	METH_MOVE               11
#define	METH_LOCK               12
#define	METH_UNLOCK             13
#define	METH_PURGE              14
#define	METH_OPTIONS            15
#define	METH_PURGE_SITE         16
#define METH_PURGE_SITE_R       17

#define	AND_PUT		            1
#define	AND_USE		            2
#define	PUT_NEW_ANYWAY	        4
#define	NO_DISK_LOOKUP	        8
#define	READY_ONLY	            16
#define NULL_REQUEST            32

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
#define	ANSW_KEEP_ALIVE		(1<<10)
#define	ANSW_HDR_CHANGED	(1<<11)	/* if some server headers was changed		*/
#define	ANSW_EXPIRES_ALTERED	(1<<12)	/* if expires was altered because of refr_patt	*/

#define	STATUS_OK               200
#define	STATUS_NOT_MODIFIED     304
#define STATUS_FORBIDEN         403
#define STATUS_NOT_FOUND        404
#define STATUS_GATEWAY_TIMEOUT  504

#define	RQ_HAS_CONTENT_LEN	    1
#define	RQ_HAS_IF_MOD_SINCE	    (1<<1)
#define	RQ_HAS_NO_STORE		    (1<<2)
#define	RQ_HAS_NO_CACHE		    (1<<3)
#define	RQ_HAS_MAX_AGE		    (1<<4)
#define	RQ_HAS_MAX_STALE	    (1<<5)
#define	RQ_HAS_MIN_FRESH	    (1<<6)
#define	RQ_HAS_NO_TRANSFORM	    (1<<7)
#define	RQ_HAS_ONLY_IF_CACHED	(1<<8)
#define	RQ_HAS_AUTHORIZATION	(1<<9)
#define RQ_GO_DIRECT		    (1<<10)
#define	RQ_HAS_CLOSE_CONNECTION (1<<11)
#define	RQ_HAS_BANDWIDTH	    (1<<12)
#define	RQ_CONVERT_FROM_CHUNKED (1<<13)
#define RQ_NO_ICP		        (1<<15)
#define RQ_FORCE_DIRECT		    (1<<16)
#define RQ_HAS_HOST		        (1<<17)
#define RQ_HAVE_RANGE		    (1<<18)
#define RQ_HAVE_PER_IP_BW	    (1<<19)
#define	RQ_CONVERT_FROM_GZIPPED (1<<20)
#define	RQ_SERVED_DIRECT        (1<<21)

#define	DOWNGRADE_ANSWER	1
#define	UNCHUNK_ANSWER		2
#define	UNGZIP_ANSWER		4

#define	ACCESS_DOMAIN		1
#define ACCESS_PORT		2
#define	ACCESS_METHOD		3

#define	MEM_OBJ_MUST_REVALIDATE	1
#define	MEM_OBJ_WARNING_110	2
#define	MEM_OBJ_WARNING_113	4

#define	CRLF			"\r\n"

#define	ANSW_SIZE		(2*1024)
#define	READ_ANSW_TIMEOUT	(5*60)		/* 5 minutes	*/

#define	DEFAULT_EXPIRE_VALUE	(7*24*3600)	/* 7 days	*/
#define	DEFAULT_EXPIRE_INTERVAL	(1*3600)	/* each hour	*/
#define	FTP_EXPIRE_VALUE	(7*24*3600)	/* expire for ftp */

#define	DEFAULT_LOW_FREE	(5)		/* these values for BIG storages */
#define	DEFAULT_HI_FREE		(6)
#define	DEFAULT_MAXRESIDENT	(1024*1024)	/* 1MB		*/
#define	DEFAULT_MINRESIDENT	(0)	        /* no limit	*/
#define	DEFAULT_DNS_TTL		(30*60)		/* 30 min's	*/
#define	DEFAULT_ICP_TIMEOUT	(1000000)	/* 1 sec	*/

#define	RESERVED_FD		(20)		/* reserve low number file descriptors */

#define	ADDR_AGE		(3600)

#define	DECODING_BUF_SZ		(1024)

#define	ERR_BAD_URL		1
#define	ERR_BAD_PORT		2
#define	ERR_ACC_DOMAIN		3
#define	ERR_DNS_ERR		4
#define	ERR_INTERNAL		5
#define	ERR_ACC_DENIED		6
#define	ERR_TRANSFER		7
#define	ERR_ACL_DENIED		8

#define	OOPS_LOG_STOR		1
#define	OOPS_LOG_FTP		2
#define	OOPS_LOG_HTTP		4
#define	OOPS_LOG_DNS		8
#define	OOPS_LOG_DBG		16
#define	OOPS_LOG_PRINT		32
#define	OOPS_LOG_INFORM		4096
#define	OOPS_LOG_NOTICE		8192
#define	OOPS_LOG_SEVERE		16384
#define	OOPS_LOG_CACHE		(OOPS_LOG_SEVERE*2)

#define MAX_DOC_HDR_SIZE    (32*1024)

#define	SET(a,b)		(a|=(b))
#define	CLR(a,b)		(a&=~b)
#define	TEST(a,b)		((a)&(b))

#if	!defined(NO_NEED_XMALLOC)
#define	malloc(x)	xmalloc(x, NULL)
#endif

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
	int			age;		/* Age: from stored answer	*/
	int			max_age;	/* max-age: from server		*/
	time_t			last_modified;	/* Last-Modified: from server	*/
};

struct	buff {
	struct	buff	*next;
	uint32_t	used;		/* size of stored data			*/
					/* this changes as we add more data	*/
	uint32_t	curr_size;	/* size of the buffer itself		*/
					/* this grows as we expand buffer	*/
	char		*data;
};

struct	refresh_pattern	{
	struct  refresh_pattern	*next;	/* if we link them in list	*/
				int	min;
				int	lmt;
				int	max;
				int	named_acl_index;
				int	valid;
};
typedef	struct  refresh_pattern refresh_pattern_t;

#define	IP_HASH_SIZE	(256)
#define	IP_HASH_MASK	(RQ_HASH_SIZE-1)
typedef	struct	ip_hash_entry	{
	struct	ip_hash_entry	*prev, *next;	/* link			*/
	struct	in_addr		addr;		/* ip address		*/
	int			refcount;	/* also sessions counter*/
	pthread_mutex_t		lock;		/* lock			*/
	int			traffic0,	/* last sec traffic	*/
				traffic1,	/* prev sec traffic	*/
				traffic2;	/* pre-pref traffic	*/
	time_t			access;		/* last_access		*/
} ip_hash_entry_t;

typedef	struct	ip_hash_head	{
	ip_hash_entry_t		*link;		/* link to row		*/
	pthread_mutex_t		lock;		/* lock for row		*/
} ip_hash_head_t;

#define	MAXACLNAMELEN		32

struct	named_acl {
	struct	named_acl	*next;
	char			name[MAXACLNAMELEN];
	char			type;
	int			internal_number;
	void			*data;
};
typedef	struct	named_acl	named_acl_t;

typedef struct	acl_chk_list_ {
	struct  acl_chk_list_ 	*next;
	named_acl_t		*acl;
	int			sign;
} acl_chk_list_t;

typedef struct	acl_chk_list_hdr_ {
	struct  acl_chk_list_		*next;
	named_acl_t			*acl;
	int				sign;
	struct  acl_chk_list_hdr_	*next_list;
	char				*aclbody;
} acl_chk_list_hdr_t;

typedef	struct	acl_ct_data_ {
	char	*ct;
	int	len;
} acl_ct_data_t;

struct	bind_acl {
	struct	bind_acl	*next;
	char			*name;
	struct	in_addr		addr;
	acl_chk_list_hdr_t	*acl_list;
};

typedef  struct  mod_call_ {
        struct  mod_call_               *next;
        char                            mod_name[16];
        int                             mod_instance;
} mod_call_t;

typedef struct l_mod_call_list_ {
        mod_call_t                      *list;
        int                             refs;
        pthread_mutex_t                 lock;
} l_mod_call_list_t;



typedef struct bind_acl bind_acl_t;
#define	PROTO_HTTP	0
#define	PROTO_FTP	1
#define	PROTO_OTHER	2
struct	request {
	struct			sockaddr_in client_sa;
	struct			sockaddr_in my_sa;
	time_t			request_time;	/* time of request creation	*/
	int			state;
	int			http_major;
	int			http_minor;
	int			meth;
	char			*method;
	struct	url		url;
	char			proto;
	int			headers_off;
	int			flags;
	int			content_length;
	int			leave_to_read;
	time_t			if_modified_since;
	int			max_age;
	int			max_stale;
	int			min_fresh;
	struct	av		*av_pairs;
	struct	buff		*data;		/* for POST				*/
        l_mod_call_list_t       *redir_mods;	/* redir modules			*/
	refresh_pattern_t	refresh_pattern;/* result of refresh_pattern		*/
	char			*original_host;	/* original value of Host: if redir-ed	*/
	char			src_charset[16];
	char			dst_charset[16];
	struct	l_string_list	*cs_to_server_table;
	struct	l_string_list	*cs_to_client_table;
	char			*matched_acl;
	int			accepted_so;	/* socket where was accept-ed		*/
	char			*source;	/* content_source (for access_log)	*/
	char			*tag;		/* HIT/MISS/... (for access_log)	*/
	char			*hierarchy;	/* hierarchy				*/
	char			*c_type;
	int			code;		/* code 				*/
	int			received;
	char			*proxy_user;	/* if proxy-auth used			*/
	char			*original_path;	/* original path			*/
	int			range_from;
	int			range_to;
	char			*peer_auth;
	int			sess_bw;	/* session bandwidth			*/
	int			per_ip_bw;	/* per ip bw				*/
	time_t			last_writing;	/* second of last_writing		*/
	int			s0_sent;	/* data size sent during last second	*/
	int			so;		/* socket				*/
	struct	sockaddr_in	conn_from_sa;	/* connect from address			*/
	struct	request		*next;		/* next in hash				*/
	struct	request		*prev;		/* prev in hash				*/
	int			doc_size;	/* corr. document size			*/
	int			doc_received;
	int			doc_sent;
	ip_hash_entry_t		*ip_hash_ptr;
	char			*decoding_buff;	/* for inflate or any other content decoding */
	char			*decoded_beg, *decoded_end;
	struct			sockaddr_in dst_sa; /* if we have to use dst_ip acl */
        time_t                  site_purged;    /* if we go through accel/map with 'purged' */
#if	defined(HAVE_ZLIB)
	z_streamp		strmp;
	z_stream		strm;
	char			inflate_started;
#endif
    int         source_port;    /* for access_log */
};

#define	RQ_HASH_SIZE	(256)
#define	RQ_HASH_MASK	(RQ_HASH_SIZE-1)
struct	rq_hash_entry {
	pthread_mutex_t	lock;
	struct	request	*link;
};

#define	_MINUTE_	(60)
#define	_HOUR_		(3600)
#define	_DAY_		(24*_HOUR_)
#define	_WEEK_		(7*_DAY_)
#define	_MONTH_		(4*_WEEK_)

typedef	struct	hg_entry_ {
	int	from, to;
	int	sum;
} hg_entry;

struct	av {
	char		*attr;
	char		*val;
	struct	av	*next;
};

typedef struct	myport_ {
	u_short		port;
	struct	in_addr	in_addr;
	int		so;		/* socket (transparent on linux need it) */
} myport_t;

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
	struct  storage_st  *next;
	char                *path;		/* path to storage	*/
	off_t               size;		/* size			*/
	int                 flags;		/* flags, like ready	*/
	pthread_rwlock_t    storage_lock;	/* locks for writings	*/
	struct  superb      super;      /* in-memory super	*/
	fd_t                fd;         /* descriptor for access*/
	char                *map;       /* busy map		*/
	off_t               i_off;      /* initial offset in file*/
        struct stat         statb;
        unsigned            *segmap;
};

struct	disk_ref {
	uint32_t	blk;			/* block number in storage	*/
	uint32_t	id;			/* id of the storage		*/
	size_t		size;			/* stored size			*/
	time_t		expires;		/* expiration date		*/
	time_t		created;		/* creation date		*/
	uint32_t	reserved0;
};


#define	HTTP_DOC	0
#define	FTP_DOC		1

struct	mem_obj {
	struct	mem_obj		*next;		/* in hash			*/
	struct	mem_obj		*prev;		/* in hash			*/
/*	struct	mem_obj		*older;		/ * older object    */
/*	struct	mem_obj		*younger;	/ * younger			*/
	struct	obj_hash_entry	*hash_back;	/* back pointer to hash chain	*/
	pthread_mutex_t		lock;		/* for refs and obj as whole	*/
	int			refs;		/* references			*/
	int			readers;	/* readers from obj in mem	*/
	int			writers;	/* writers to obj in mem	*/
	int			decision_done;	/* for revalidate process	*/
	pthread_mutex_t		decision_lock;	/* protects for the decision	*/
	pthread_cond_t		decision_cond;
	struct	mem_obj		*child_obj;	/* after reload decision	*/
	struct	url		url;		/* url				*/
	int			httpv_major;
	int			httpv_minor;
	int			state;
	int			flags;
	pthread_mutex_t		state_lock;
	pthread_cond_t		state_cond;
	time_t			filled;		/* when filled			*/
	size_t			size;		/* current data size		*/
	size_t			content_length;	/* what server say about content */
	size_t			x_content_length; /* if doc was received in chunks - actual content size */
	size_t			x_content_length_sum;
	size_t			resident_size;	/* size of object in memory	*/
	struct	buff		*container;	/* data storage			*/
	struct	buff		*hot_buff;	/* buf to write			*/
	int			status_code;	/* from the server nswer	*/
	time_t			request_time;	/* when request was made	*/
	time_t			response_time;	/* when responce was received	*/
	struct	obj_times	times;
	char			doc_type;	/* http or ftp */
	struct	av		*headers;	/* headers */
	struct	disk_ref	*disk_ref;	/* disk reference, if loaded from storage	*/
	int			insertion_point;/* where to insert additional headers	*/
	int			tail_length;	/* length of \n\n or \r\n\r\n et al.	*/
	time_t			created;	/* when created in memory	*/
	time_t			last_access;	/* last time locate finished ot this object	*/
	int			accessed;	/* # times when locate finished on this obj	*/
	int			rate;		/* rate to swap out		*/
	size_t			ungzipped_cont_len;
						/* content length of ungzipped content	*/
};

#define	MAX_INTERNAL_NAME_LEN	24
typedef struct internal_doc_tag {
	char		internal_name[MAX_INTERNAL_NAME_LEN];
	char		*content_type;
	int		content_len;
	int		expire_shift;
	unsigned char	*body;
} internal_doc_t;

struct	output_object {
	struct	av	*headers;
	struct	buff	*body;
	int		flags;
};

struct	obj_hash_entry {
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
	size_t			x_content_length;
	int			checked;
	int			status_code;
	struct	obj_times	times;
	struct	av		*headers;
	time_t			response_time;	/* these times can be filled	*/
	time_t			request_time;	/* when we load obj from disk	*/
	int			httpv_major;
	int			httpv_minor;
};

struct	ftp_r {
	int		control;	/* control socket	*/
	int		data;		/* data socket		*/
	int		client;		/* client socket	*/
	uint32_t	size;		/* result of 'SIZE' cmd */
#define	MODE_PASV	0
#define	MODE_PORT	1
	int		mode;		/* PASV or PORT		*/
	struct	request	*request;	/* referer from orig	*/
	struct	mem_obj	*obj;		/* object		*/
	char		*dehtml_path;	/* de-hmlized path	*/
	char		*server_path;	/* path as server report*/
	struct	buff	*server_log;	/* ftp server answers	*/
	struct	string_list *nlst;	/* NLST results		*/
	uint32_t	received;	/* how much data received */
	char		*type;		/* mime type		*/
#define	FTP_TYPE_DIR	1
#define	FTP_TYPE_FILE	2
	int		file_dir;	/* file or dir		*/
	struct	buff	*container;
#define	PARTIAL_ANSWER	1
	int		ftp_r_flags;
};

struct	cidr_net {
	uint32_t			network;
	uint32_t			masklen;
	uint32_t			mask;
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
typedef	struct string_list	string_list_t;

struct	l_string_list	{
	struct	string_list		*list;
	int				refs;
	pthread_mutex_t			lock;
};
typedef	struct	l_string_list l_string_list_t;

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
#define	OP_REDIR_MODS	8
#define	OP_DENYTIME	9
#define	OP_SRCDOMAINS	10
#define	OP_NETWORKS_ACL	11
#define	OP_MAXREQRATE	12
#define	OP_PER_SESS_BW	13
#define	OP_PER_IP_BW	14
#define	OP_PER_IP_CONN	15
#define	OP_CONN_FROM	16
	int				op;
	void				*val;
	struct	group_ops_struct	*next;
};

struct	denytime {
	char			days;
	int			start_minute;
	int			end_minute;
	struct	denytime	*next;
};

struct	range {
	int	from;
	int	length;
};
struct	badports {
	struct	range	ranges[MAXBADPORTS];
};

struct	urlregex_acl_data {
	char	*regex;
	regex_t	preg;
};
struct	urlpath_acl_data {
	char	*regex;
	regex_t	preg;
};
struct	acl_ip_data {
	int			num;
	struct	cidr_net	**sorted;
	struct	cidr_net	*unsorted;
};


#define	ACL_URLREGEX        1
#define	ACL_PATHREGEX       2
#define	ACL_URLREGEXI       3
#define	ACL_PATHREGEXI      4
#define	ACL_USERCHARSET     5
#define	ACL_SRC_IP          6
#define	ACL_METHOD          7
#define	ACL_PORT            8
#define	ACL_DSTDOM          9
#define	ACL_DSTDOMREGEX     10
#define	ACL_SRCDOM          11
#define	ACL_SRCDOMREGEX     12
#define	ACL_TIME            13
#define	ACL_CONTENT_TYPE	14
#define	ACL_USERNAME        15
#define ACL_HEADER_SUBSTR   16
#define	ACL_DST_IP          17

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

struct  header_substr_data {
    char    *header;
    char    *substr;
};

typedef struct  header_substr_data header_substr_data_t;

struct  dstdomain_cache_entry {
#define	DSTDCACHE_NOTFOUND	0
#define	DSTDCACHE_ALLOW		1
#define	DSTDCACHE_DENY		2
	int	access;			/* access check result	*/
	time_t	when_created;		/* when created		*/
};

struct	group	{
	char			*name;
	struct	cidr_net	*nets;
	struct	domain_list	*srcdomains;
	struct	acls		*http;
	struct	acls		*icp;
	struct	badports	*badports;
	int			bandwidth;
	int			miss_deny;		/* TRUE if deny		*/
	struct	l_string_list	*auth_mods;		/* auth modules		*/
	l_mod_call_list_t	*redir_mods;		/* redir modules	*/
	pthread_mutex_t		group_mutex;
	struct	group_stat	cs0;			/* current		*/
	struct	group_stat	cs1;			/* prev second		*/
	struct	group_stat	cs2;			/* pre-prev sec		*/
	struct	group_stat	cs_total;		/* total		*/
	struct  group		*next;
	struct	denytime	*denytimes;
	hash_t			*dstdomain_cache;	/* cashe for dstdom checks */
	acl_chk_list_hdr_t	*networks_acl;
	int			maxreqrate;		/* max request rate	*/
	int			per_sess_bw;		/* max bandw per session */
	int			per_ip_bw;		/* bandw per ip address (or client) */
	int			per_ip_conn;		/* max number of conns per ip	*/
	struct	sockaddr_in	conn_from_sa;		/* connect from address	*/
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
#define	PEER_PARENT	    1
#define	PEER_SIBLING	2
#define SOURCE_NONE     3

#define	PEER_UP		0
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
	int			rq_sent;	/* tot. requests sent	*/
	int			an_recvd;	/* tot. answers		*/
	int			hits_recvd;	/* tot. hits received	*/
	int			rq_recvd;	/* tot. reqs received	*/
	int			hits_sent;	/* hits answers to peer	*/
	time_t			last_sent;	/* time when last rq sent  */
	time_t			last_recv;	/* time when last rq recvd */
	char			*my_auth;	/* we send to remote	*/
	acl_chk_list_hdr_t	*peer_access;	/* acls to allow/deny requests	*/
	time_t			down_time;	/* time when peer goes down from up */
	int			down_timeout;	/* how long avoid this after down */
};

struct	icp_queue_elem {
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
	u_char			*Table;
};
typedef	struct charset charset_t;

typedef	struct	u_charset {
	char		name[16];
	charset_t	*cs;
} u_charset_t;

#define	WORK_NORMAL	1
#define	WORK_MODULE	2
typedef	struct	work {
	int	so;		/* socket		*/
	void*	(*f)(void*);	/* processor or NULL	*/
	int	flags;
	int	accepted_so;	/* on which socket connection was accepted	*/
        struct  sockaddr_in sa;
} work_t;

#define LISTEN_AND_NO_ACCEPT    1
#define LISTEN_AND_DO_SYNC      2

struct	listen_so_list	{
	int                     so;		/* socket number				*/
	u_short                 port;		/* port we listen on				*/
	struct	in_addr         addr;		/* address we listen on				*/
	void                    *(*process_call)(void*);/* this will be called after accept()	*/
	struct	listen_so_list	*next;		/* link to next					*/
	int                     requests;	/* requests we accepted during curr. second	*/
        int                     flags;      /* do we need accept or not on this fd  */
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
	uint32_t	requests_http1;	/* last minute requests			*/
	uint32_t	hits1;		/* last minute hits			*/
	uint32_t	storages_free;	/* current free storage %%		*/

	uint32_t	requests_icp0;	/* current minute icp requests processed		*/
	uint32_t	requests_icp1;	/* prev minute icp requests processed		*/
	uint32_t	requests_http0_max; /* per minute max			*/
	uint32_t	requests_icp0_max;
	uint32_t	hits0_max;	/* maximum current minute hits		*/
	uint32_t	clients_max;	/* maximum number of clients		*/
#if	HAVE_GETRUSAGE
	struct  rusage  rusage;		/* current rusage			*/
	struct  rusage  rusage0;	/* prev min rusage			*/
#endif
	time_t		timestamp;	/* last update time				*/
	time_t		timestamp0;	/* prev update time			*/
	int		drops0;		/* client drops (RED, refuse)	*/
	int		drops;		/* drops total			*/
};

#define	MAXPOLLFD	(8)
#define	FD_POLL_RD	(1)
#define	FD_POLL_WR	(2)
#define	FD_POLL_HU	(4)
#define	IS_READABLE(a)	(((a)->answer)&FD_POLL_RD)
#define	IS_WRITEABLE(a)	(((a)->answer)&FD_POLL_WR)
#define	IS_HUPED(a)	(((a)->answer)&FD_POLL_HU)

struct	pollarg {
	int	fd;
	short	request;
	short	answer;
};

#define        IS_SPACE(a)     isspace((unsigned)a)
#define        IS_DIGIT(a)     isdigit((unsigned)a)

#define	ERRBUF		char	errbuf[256]
#define	ERRBUFS		errbuf, sizeof(errbuf)-1

#include	"dataq.h"

#define	FILEBUFFSZ	(16*1024)
typedef	struct	filebuff_ {
	int		fd;
	int		buffered;
	pthread_mutex_t	lock;
	struct	buff	*buff;
	dataq_t		queue;
} filebuff_t;


#define	DB_API_RES_CODE_OK		0
#define	DB_API_RES_CODE_ERR		1
#define	DB_API_RES_CODE_NOTFOUND	2
#define	DB_API_RES_CODE_EXIST		3

#define	DB_API_CURSOR_NORMAL		0
#define	DB_API_CURSOR_CHECKDISK		1

typedef	struct	db_api_arg_ {
	void	*data;
	size_t	size;
	int	flags;
} db_api_arg_t;

typedef	struct	eraser_data_ {
	char	*url;
	void	*disk_ref;
} eraser_data_t;

#include	"extern.h"


typedef struct  icp_job_tag {
        struct  sockaddr_in     my_icp_sa;
        struct  sockaddr_in     icp_sa;
        int                     icp_so;
        char                    *icp_buf;
        int                     icp_buf_len;
} icp_job_t;


#include "lib.h"
