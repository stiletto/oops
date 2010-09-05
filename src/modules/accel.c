#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<stdarg.h>
#include	<string.h>
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

#include	"../oops.h"
#include	"../modules.h"
#include	"../gnu_regex.h"

char	module_type   = MODULE_REDIR ;
char	module_name[] = "accel" ;
char	module_info[] = "WWW-accelerator" ;

static	rwl_t	accel_lock;
#define	RDLOCK_ACCEL_CONFIG	rwl_rdlock(&accel_lock)
#define	WRLOCK_ACCEL_CONFIG	rwl_wrlock(&accel_lock)
#define	UNLOCK_ACCEL_CONFIG	rwl_unlock(&accel_lock)

#define	MAP_STRING		1
#define	MAP_REGEX		2
#define	MAP_STRING_CS		4
#define	MAP_REGEX_CS		8
#define	MAP_ACL			16

#define	MAXMATCH		10

#define	NMYPORTS	4
static	myport_t	myports[NMYPORTS];	/* my ports		*/
static	int		nmyports;		/* actual number	*/

static	refresh_pattern_t	*refr_patts;

struct	to_host {
	struct	to_host	*next;
	char		*name;
	u_short		port;
	char		*path;		/* if we have to prepend path	*/
	char		failed;		/* TRUE or FALSE 		*/
	time_t		last_failed;	/* when failed to connect 	*/
};

struct	map {
	struct	map	*next;
	int		type;
	char		*from_host;
	regex_t		preg;			/* regex if MAP_REGEX			*/
	int		acl_index;		/* acl index if type MAP_ACL		*/
	u_short		from_port;
	int		hosts;
	pthread_mutex_t	last_lock;
	struct	to_host	*to_hosts;
	struct	to_host	*last_used;
	l_string_list_t	*cs_to_server_table;	/* translation from client to server	*/
	l_string_list_t	*cs_to_client_table;	/* translation from server to client	*/
	char		*src_cs_name;		/* source charset name			*/
	struct	map	*next_in_hash;		/* link in hash	table for usual maps,
						   next map for acl, regex maps		*/
	int		ortho;			/* something orthogonal to hash function*/
};

typedef	struct	rewrite_location_ {
	struct  rewrite_location_	*next;
	int				acl_index;
	regex_t				preg;
	char				*dst;
} rewrite_location_t ;

typedef	struct	map_hash_ {
	struct	map	*next;
} map_hash_t;

static	struct	map	*maps, *default_map, *new_map();
static	struct	map	*find_map(struct request*, size_t, regmatch_t*, char*);
static	struct	map	*other_maps_chain;
static	map_hash_t	*map_hash_table;
static	struct	to_host	*new_to_host();
static	int		rewrite_host;
static	int		use_host_hash;
static	void		free_maps(struct map *);
static	void		parse_map(char*);
static	void		parse_map_acl(char*);
static	void		parse_map_regex(char*);
static	void		parse_map_regex_charset(char*);
static	void		parse_map_charset(char*);
static	void		parse_map_file(char*);
static  void		check_map_file_age();
static	void		reload_map_file(void);
static	int		sleep_timeout, dead_timeout;
static	char		*build_destination(char*,regmatch_t*, char*);
static	char		*build_src(struct request *);
static	rewrite_location_t	*rewrite_location;
static	void		insert_rewrite_location(char*);
static	void		free_rewrite_location(rewrite_location_t*);

static	char		map_file[MAXPATHLEN];
static	time_t		map_file_mtime = 0, map_file_check_time = 0;

unsigned
hash_function(char *s)
{
unsigned int n = 0;
unsigned int j = 0;
unsigned int i = 0;

    if ( use_host_hash <= 0 ) return(0);

    while (*s) {
        j++;
        n ^= 271 * (unsigned) *s++;
    }
    i = n ^ (j * 271);

    return( i % use_host_hash);
}

unsigned
ortho_hash_function(char *s)
{
unsigned int j = 0;

    if ( use_host_hash <= 0 ) return(0);

    while (*s) {
        j += *(s++);
    }

    return( j );
}

void
place_map_in_hash(struct map *map)
{
unsigned 	b, o;
struct map	*this;
char		host_tmp[MAXHOSTNAMELEN], *s, *d;

    if ( !map || !map_hash_table ) return;

    switch (map->type) {
 case MAP_STRING:
 case MAP_STRING_CS:
	if ( !map->from_host ) goto other;
	d = host_tmp; s = map->from_host;
	while ( *s && (d - host_tmp < MAXHOSTNAMELEN) ) *d++ = tolower(*s++);
	*d = 0;
	b = hash_function(host_tmp);
	o = ortho_hash_function(host_tmp);
	map->ortho = o;
	if ( !map_hash_table[b].next ) map_hash_table[b].next = map;
	  else {
	    this = map_hash_table[b].next;
	    while ( this->next_in_hash ) this = this->next_in_hash;
	    this->next_in_hash = map;
	}
	break;
 default:
   other:
	if ( !other_maps_chain ) other_maps_chain = map;
	  else {
	    this = other_maps_chain;
	    while ( this->next_in_hash ) this = this->next_in_hash;
	    this->next_in_hash = map;
	}
	break;
    }
}

int
mod_load()
{
    verb_printf("Accel started\n");
    rwl_init(&accel_lock);
    nmyports = 0;
    maps = NULL;
    default_map = NULL;
    sleep_timeout = 600;
    dead_timeout = 20;
    refr_patts = NULL;
    rewrite_location = NULL;
    rewrite_host = TRUE;
    map_file[0] = 0;
    use_host_hash = 0;
    map_hash_table = NULL;
    other_maps_chain = NULL;
    return(MOD_CODE_OK);
}
int
mod_unload()
{
    verb_printf("banners stopped\n");
    return(MOD_CODE_OK);
}
int
mod_config_beg()
{
    WRLOCK_ACCEL_CONFIG ;
    nmyports = 0;
    if ( maps ) {
	free_maps(maps);
	maps = NULL;
    }
    if ( default_map ) {
	free_maps(default_map);
	default_map = NULL;
    }
    if ( refr_patts ) {
	free_refresh_patterns(refr_patts);
	refr_patts = NULL;
    }
    if ( rewrite_location ) {
	free_rewrite_location(rewrite_location);
	rewrite_location = NULL;
    }
    map_file[0] = 0;
    rewrite_host = TRUE;
    use_host_hash = 0;
    if ( map_hash_table ) {
	free(map_hash_table);
	map_hash_table = NULL;
    }
    other_maps_chain = NULL;
    sleep_timeout = 600;
    dead_timeout = 20;
    map_file_mtime = 0;
    map_file_check_time = 0;
    UNLOCK_ACCEL_CONFIG ;
    return(MOD_CODE_OK);
}
int
mod_config_end()
{
    if ( use_host_hash > 0 ) {
	map_hash_table = calloc(use_host_hash, sizeof(*map_hash_table));
    }
    if ( map_file )
	reload_map_file();
    return(MOD_CODE_OK);
}

int
mod_config(char *config)
{
char		*p = config, *s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;

    WRLOCK_ACCEL_CONFIG ;
    while( *p && isspace(*p) ) p++;

    if ( !strncasecmp(p, "myport", 6) ) {
	p += 6;
	while (*p && isspace(*p) ) p++;
	nmyports = parse_myports(p, &myports, NMYPORTS);
	verb_printf("%s will use %d ports\n", module_name, nmyports);
    } else
    if ( !strncasecmp(p, "rewrite_host", 12) ) {
	p += 12; while (*p && isspace(*p) ) p++;
	if ( !strcasecmp(p, "yes") ) {
	    rewrite_host = TRUE;
	    verb_printf("%s will rewrite 'Host:' header\n", module_name);
	} else {
	    rewrite_host = FALSE;
	    verb_printf("%s won't rewrite 'Host:' header\n", module_name);
	}
    } else
    if ( !strncasecmp(p, "dead_timeout", 12) ) {
	p += 12;
	while (*p && isspace(*p) ) p++;
	dead_timeout = atoi(p);
    } else
    if ( !strncasecmp(p, "use_host_hash", 13) ) {
	p += 13;
	while (*p && isspace(*p) ) p++;
	use_host_hash = atoi(p);
    } else
    if ( !strncasecmp(p, "sleep_timeout", 13) ) {
	p += 13;
	while (*p && isspace(*p) ) p++;
	sleep_timeout = atoi(p);
    } else
    if ( !strncasecmp(p, "file", 4) )
	parse_map_file(p);
done:
    UNLOCK_ACCEL_CONFIG ;
    return(MOD_CODE_OK);
}

struct	map
*new_map()
{
struct	map	*res;

    res = malloc(sizeof(*res));
    if ( !res ) return(NULL);
    bzero(res, sizeof(*res));
    pthread_mutex_init(&res->last_lock, NULL);
    return(res);
}

struct to_host
*new_to_host()
{
struct	to_host	*res;

    res = malloc(sizeof(*res));
    if ( !res ) return(NULL);
    bzero(res, sizeof(*res));
    return(res);
}

void
free_maps(struct map * map)
{
struct	map	*next_map;
struct	to_host	*host, *next_host;

    while (map) {
	next_map = map->next;
	if ( map->from_host ) free(map->from_host);
	if ( (map->type == MAP_REGEX)
	     || (map->type == MAP_ACL)
	     || (map->type == MAP_REGEX_CS) ) {
		regfree(&map->preg);
	}
	if ( map->cs_to_client_table )
	    leave_l_string_list(map->cs_to_client_table);
	if ( map->cs_to_server_table )
	    leave_l_string_list(map->cs_to_server_table);
	if ( map->src_cs_name ) free(map->src_cs_name);
	host = map->to_hosts;
	while ( host ) {
	    next_host = host->next;
	    if ( host->name ) free(host->name);
	    free(host);
	    host = next_host;
	}
	pthread_mutex_destroy(&map->last_lock);
	free(map);
	map = next_map;
    }
}

int
redir_rewrite_header(char **hdr, struct request *rq, int *flags)
{
struct	map		*map;
struct	url		url, new_url;
char			*p, *new_host, *new_location = NULL, *src = NULL, *new_l_val = NULL;
char			*old_path;
regmatch_t		pmatch[MAXMATCH];
rewrite_location_t	*rl;

    if ( !rewrite_location
         || !hdr || !*hdr || !rq ) return(MOD_CODE_OK);
    if ( !(**hdr == 'L' || **hdr == 'l' ) ) return(MOD_CODE_OK);
    if ( strncasecmp(*hdr, "Location:", 9) ) return(MOD_CODE_OK);

    p = (*hdr) + 9;
    while ( *p && isspace(*p) ) p++;
    if ( !*p )
	return;

    RDLOCK_ACCEL_CONFIG ;

    bzero(&url, sizeof(url));
    bzero(&new_url, sizeof(new_url));

    my_xlog(LOG_HTTP, "redir_rewrite_header called for '%s'\n", *hdr);

    src = build_src(rq);
    map = find_map(rq, MAXMATCH, pmatch, src);

    if ( !map )
	goto done;

    rl = rewrite_location;
    while ( rl ) {
	/* if the source match acl	*/
	if ( rl->acl_index && url_match_named_acl_by_index(src, rl->acl_index) ) {
	    /* if 'Location:' value match rl->preg	*/
	    if ( !regexec(&rl->preg, p, MAXMATCH, (regmatch_t*)&pmatch, 0) ) {
		/* here it is 		*/
		new_l_val = build_destination(p, pmatch, rl->dst);
		break;
	    }
	}
	rl = rl->next;
    }

    if ( !new_l_val ) goto done;
    if ( parse_raw_url(new_l_val, &new_url) ) goto done;
    if ( parse_raw_url(p, &url) ) goto done;	/* to get 'path' from old Loc: */

    if ( !new_url.port ) new_url.port = 80;

    if ( new_url.proto && new_url.host ) {
	int	len = strlen(new_url.proto) +
		      strlen(new_url.host);
	if ( new_url.path ) len += strlen(new_url.path);
	if (     url.path ) len += strlen(url.path+1);	/* we don't need leading / here */
	len += 10 /* Location: */ + 3 /* :// */
		 + 10 /* possible port */ + 1 /* \0 */ ;
	new_location = malloc(len);
	if ( !new_location ) goto done;
	if ( new_url.port != 80 )
	    sprintf(new_location, "Location: %s://%s:%d%s%s", new_url.proto,
				new_url.host, new_url.port, 
				new_url.path?new_url.path:"",
				    url.path?(url.path+1):"");
	   else
	    sprintf(new_location, "Location: %s://%s%s%s", new_url.proto,
				new_url.host, 
				new_url.path?new_url.path:"",
				    url.path?(url.path+1):"");
	free(*hdr); *hdr = new_location;
    }

done:
    UNLOCK_ACCEL_CONFIG ;
    if ( new_l_val ) free(new_l_val);
    if ( src ) free(src);
    free_url(&new_url);
    free_url(&url);
    return(MOD_CODE_OK);
}

/*
   this return OK if connected or will not connect.
   result - in resulting_so.
*/

int
redir_connect(int *resulting_so, struct request *rq, int *flags)
{
struct	map		*map;
struct	to_host		*host;
int			max_attempts, so = -1, saved_so, rc;
struct	sockaddr_in	server_sa;
regmatch_t		pmatch[MAXMATCH];
char			*src = NULL;

    /* this lock can be long (if we can't connect immediately) */
    RDLOCK_ACCEL_CONFIG ;
    my_log("redir_connect called\n");
    if ( !rq  ) goto done;;
    if ( !resulting_so ) goto done;

    src = build_src(rq);
    map = find_map(rq, MAXMATCH, pmatch, src);
    if ( !map || !map->hosts ) goto done;
    /* connect using next server */
    max_attempts = map->hosts;
    pthread_mutex_lock(&map->last_lock);
    host = map->last_used;
    if ( !host )
	host = map->to_hosts;
    map->last_used = host->next;
    /* if host marked as failed and sleep_timeout passed - try it */
    if ( host->failed && (global_sec_timer - host->last_failed > sleep_timeout) )
	host->failed = FALSE;
    pthread_mutex_unlock(&map->last_lock);
    if ( !host ) goto done;	/* something wrong */

    so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( so < 0 )
	goto done;

    while ( max_attempts ) {
	if ( !host->failed ) {
	    char 	*use_name;
	    u_short	use_port;
	    /* we can try this */
	    /* if map is regex then first record can be regex			*/
	    /* in this case we can use host and port from rewritten request	*/
	    if ( ((map->type == MAP_REGEX)
	        ||(map->type==MAP_ACL)
	        ||(map->type==MAP_REGEX_CS))
	    	  && (host == map->to_hosts) ) {
		use_name = rq->url.host;
		use_port = rq->url.port;
	    } else {
		use_name = host->name;
		use_port = host->port;
	    }
	    my_xlog(LOG_HTTP, "accel:redir_connect: connecting to %s:%d\n", use_name, use_port);
	    rc = str_to_sa(use_name, (struct sockaddr*)&server_sa);
	    server_sa.sin_port = htons(use_port);
	    if ( rc ) /* have no name */
		goto try_next_host;
	    fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0) | O_NONBLOCK );
	    rc = connect(so, (struct sockaddr*)&server_sa, sizeof(server_sa));
	    if ( rc == 0 ) {
		/* this is ok */
		*resulting_so = so;
		goto done;
	    }
	    if ( errno == EINPROGRESS ) {
	      /* do timed wait */
	      struct pollarg pollarg;

		pollarg.fd = so;
		pollarg.request = FD_POLL_WR|FD_POLL_HU;
		rc = poll_descriptors(1, &pollarg, dead_timeout*1000);
		if ( (rc > 0) && !IS_HUPED(&pollarg) ) {
		    /* connected */
		    *resulting_so = so;
		    goto done;
		}
		my_xlog(LOG_HTTP, "accel: Connect failed\n");
	    }
	    if ( so != -1 ) {
		close(so);
		so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if ( so < 0 )
		    goto done;
	    }
	    host->failed = TRUE;
	    host->last_failed = global_sec_timer;
	}
  try_next_host:
	host = host->next;
	if ( !host ) host = map->to_hosts;
	max_attempts--;
    }
    UNLOCK_ACCEL_CONFIG ;
    if ( so >= 0 )
	close(so);
    if ( src ) free(src);
    return(MOD_CODE_ERR);
done:
    UNLOCK_ACCEL_CONFIG ;
    if ( src ) free(src);
    return(MOD_CODE_OK);
}

int
redir(int so, struct group *group, struct request *rq, int *flags)
{
struct	map		*map;
regmatch_t		pmatch[MAXMATCH];
char			*destination = NULL, *src = NULL, *ohost;
struct	av		*host_av;

    check_map_file_age();

    RDLOCK_ACCEL_CONFIG ;
    my_log("redir called\n");
    if ( !rq ) goto done;

    src = build_src(rq);
    pmatch[0].rm_so = pmatch[0].rm_eo = -1;
    map = find_map(rq, MAXMATCH, pmatch, src);
    if ( !map || !map->to_hosts) goto done;

    if ( rq->original_host ) free(rq->original_host);
    rq->original_host = NULL;

    ohost = attr_value(rq->av_pairs, "host:");
    if ( ohost ) /* we was able to extract Host: */
	rq->original_host = strdup(ohost);

    /* Now! rewrite url */
    if ( rq->url.host ) free(rq->url.host);
    switch (map->type) {
case MAP_STRING_CS:
	if ( map->cs_to_server_table ) {
	    lock_l_string_list(map->cs_to_server_table);
	    rq->cs_to_server_table = map->cs_to_server_table;
	}
	if ( map->cs_to_client_table ) {
	    lock_l_string_list(map->cs_to_client_table);
	    rq->cs_to_client_table = map->cs_to_client_table;
	}
	if ( map->src_cs_name )
	    strncpy(rq->src_charset, map->src_cs_name, sizeof(rq->src_charset)-1 );
case MAP_STRING:
	/* 1. rewrite host part			*/
	if ( map->to_hosts->name ) {
	    rq->url.host = strdup(map->to_hosts->name);
	}

	/* 2. rewrite port part			*/
	rq->url.port = map->to_hosts->port;

	/* 3. If need - rewrite path part	*/
	if ( map->to_hosts->path && rq->url.path ) {
	    int	 newpathlen = strlen(map->to_hosts->path)+strlen(rq->url.path)+1;
	    char *newpath;

	    newpath = malloc(newpathlen);
	    if ( newpath ) {
		sprintf(newpath, "%s%s", map->to_hosts->path, rq->url.path);
		free(rq->url.path);
		rq->url.path = newpath;
	    }
	}
	break;
case MAP_REGEX_CS:
	if ( map->cs_to_server_table ) {
	    lock_l_string_list(map->cs_to_server_table);
	    rq->cs_to_server_table = map->cs_to_server_table;
	}
	if ( map->cs_to_client_table ) {
	    lock_l_string_list(map->cs_to_client_table);
	    rq->cs_to_client_table = map->cs_to_client_table;
	}
	if ( map->src_cs_name )
	    strncpy(rq->src_charset, map->src_cs_name, sizeof(rq->src_charset)-1 );
case MAP_ACL:
case MAP_REGEX:
	/* if this is map_regex - build rewritten url*/
	if ( map->to_hosts && map->to_hosts->name)
	    destination = build_destination(src,pmatch, map->to_hosts->name);
	if ( destination ) {
	    struct url	url;
	    my_xlog(LOG_HTTP, "accel: new dest: %s\n", destination);
	    /* we must split new destination */
	    if ( !parse_raw_url(destination, &url) ) {
		/* it is ok 				  */
		/* 1. if there was no port in destination */
		if ( !url.port ) url.port = 80;
		url.httpv = rq->url.httpv;
		rq->url.httpv = NULL;
		free_url(&rq->url);
		memcpy(&rq->url, &url, sizeof(url));
	    }
	    free(destination);
	}
	break;

default:
	my_log("Unknown MAP type %d\n", map->type);
	goto done;
    }

    if ( !rq->original_host ) /* there was no host: ? */
	rq->original_host = strdup(rq->url.host);

    /* rewrite 'Host:' (if configured)				*/
    if ( rewrite_host && (host_av = lookup_av_by_attr(rq->av_pairs, "host:") ) ) {
	if (host_av->val) free(host_av->val);
	host_av->val = strdup(rq->url.host);
    }
    if ( !TEST(rq->flags, RQ_HAS_HOST) && rq->url.host) {
	/* insert Host: header */
	put_av_pair(&rq->av_pairs, "Host:", rq->url.host);
    }
    /* check if we have to change refresh patt for this request */
    if ( refr_patts ) {
	refresh_pattern_t *curr = refr_patts;
	while ( curr ) {
	    if ( rq_match_named_acl_by_index(rq, curr->named_acl_index) == TRUE ) {
		/* transfer this refresh patt into the request */
		rq->refresh_pattern = *curr;
		rq->refresh_pattern.valid = 1;
		break;
	    }
	    curr = curr->next;
	}
    }
    /* force this request to be DIRECT, and NO_ICP_REQUESTS */
    SET(rq->flags, RQ_FORCE_DIRECT|RQ_NO_ICP);
    /* Now url is rewritten */
done:
    UNLOCK_ACCEL_CONFIG ;
    if ( src ) free(src);
    return(MOD_CODE_OK);
}

struct map
*find_map(struct request *rq, size_t nmatch, regmatch_t pmatch[], char *src)
{
struct	map		*res = NULL, *map = maps;
struct	sockaddr_in	map_sa;
char			*host;
u_short			port;

    port = ntohs(rq->my_sa.sin_port);
    if ( nmyports > 0 ) {
	int     n = nmyports;
	myport_t *mp = myports;
	/* if this is not on my port */
	while( n ) {
	    /* if ports are equal and addresseses are equal (unless wildcard myport) */
	    if (    ( mp->port == port)
	         && (   (mp->in_addr.s_addr == INADDR_ANY) 
	             || (mp->in_addr.s_addr == rq->my_sa.sin_addr.s_addr)) )
	         break;
	    n--;mp++;
	}
	if ( !n ) {
	    goto done;  /* not my */
	}
    } else
	return(NULL);

    my_log("accel: it's my\n");
    /* first - take destination from 'Host:'			*/
    if ( rq->original_host ) {
	host = rq->original_host;
    } else
	host = attr_value(rq->av_pairs, "host");
    if ( host ) {
	char	host_buf[MAXHOSTNAMELEN], *o;

	strncpy(host_buf, host, sizeof(host_buf) - 1);
	if ( (o = strchr(host_buf, ':')) ) {
	    *o = 0;
	    port = atoi(o+1);
	} else
	    port = 80;
	/* now host_buf contain host part	*/
	if ( (use_host_hash) > 0 && map_hash_table ) {
	    char	*t;
	    unsigned 	b,o;
	    struct map	*this;

	    /* lowercase host			*/
	    t = host_buf; while ( *t ) {*t = tolower(*t);t++;}
	    b = hash_function(host_buf);
	    o = ortho_hash_function(host_buf);

	    if ( map_hash_table[b].next ) {
		/* check this line of hash table */
		this = map_hash_table[b].next;
		while ( this ) {
		    if ( this->ortho != o ) {
			this = this->next_in_hash;
			continue;
		    }
		    if (    !strcasecmp(host_buf, this->from_host)
			 && (port == this->from_port) ) {
			my_xlog(LOG_HTTP, "Found in hash\n");
			goto hash_found;
		    }
		    this = this->next_in_hash;
		}
		/* not found, try with other maps */
	    }
	    this = other_maps_chain;
	    while ( this ) {
		/* if rq match this map */
		switch ( this->type ) {
		case MAP_REGEX_CS:
		case MAP_REGEX:
		    if ( src && !regexec(&this->preg, src, nmatch, pmatch, 0) ) {
			my_xlog(LOG_HTTP, "accel: Host %s found in regex map\n", host);
			goto hash_found;
		    }
		    break;
		case MAP_ACL:
		    if ( rq_match_named_acl_by_index(rq, this->acl_index)
			&& !regexec(&this->preg, src, nmatch, pmatch, 0) ) {
			my_xlog(LOG_HTTP, "accel: Host %s found in acl map\n", host);
			goto hash_found;
		    }
		    break;
		}
		this = this->next_in_hash;
	    }
	hash_found:
	    return(this);
	}
	while(map) {
	    switch( map->type ) {
	case MAP_STRING_CS:
	case MAP_STRING:
		if ( !strcasecmp(host_buf, map->from_host) && (port == map->from_port) ) {
		    my_xlog(LOG_HTTP, "accel: Host %s found in string map\n", host);
		    return(map);
		}
		break;
	case MAP_REGEX_CS:
	case MAP_REGEX:
		if ( src && !regexec(&map->preg, src, nmatch, pmatch, 0) ) {
		    my_xlog(LOG_HTTP, "accel: Host %s found in regex map\n", host);
		    return(map);
		}
		break;
	case MAP_ACL:
		if ( rq_match_named_acl_by_index(rq, map->acl_index)
		    && !regexec(&map->preg, src, nmatch, pmatch, 0) ) {
		    my_xlog(LOG_HTTP, "accel: Host %s found in acl map\n", host);
		    return(map);
		}
		break;
	default:
		my_log("Here is unknown map type %d\n", map->type);
		break;
	    }
	    map = map->next;
	}
    } else /* We failed to find Host */
	return(NULL);
    if ( !map ) {
	if ( !default_map ) goto done;
	my_log("Default used\n");
	map = default_map;
    }
    res = map;
done:
    return(res);
}

void
parse_map_file(char *p)
{

    p += 4;
    while ( *p && isspace(*p) ) p++;
    strncpy(map_file, p, sizeof(map_file) - 1);
    verb_printf("accel: use %s as mapfile\n", map_file);
}

void
parse_map(char *p)
{
char		*s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;

    /* map from[:port] to1[:port1] to2[:port2] ... */
    p += 3; while (*p && isspace(*p) ) p++;
    s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    p = s;
    if ( strlen(buf) ) {
        u_short port = 80;
	char	*path;

        if ( ( o = strchr(buf, ':') ) ) {
	    port = atoi(o+1);
	    *o = 0;
	}
	printf("host=%s, port=%d\n", buf, port);
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
	map->type = MAP_STRING;
	map->from_host = strdup(buf);
	map->from_port = port;
do_next_host:
	while (*p && isspace(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		struct map *this = maps;
		while ( this->next ) this = this->next;
		this->next = map;
	    }
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	p = s;
	if ( strlen(buf) ) {
	    u_short 	port = 80;
	    struct	to_host	*to_host, *next;
	    char	*path = NULL;

	    if ( ( o = strchr(buf, '/') ) ) {
		path = strdup(o);
 	    }
	    if ( ( o = strchr(buf, ':') ) ) {
		port = atoi(o+1);
		*o = 0;
	    }
	    printf("mapped to %s, port=%d path=%s\n", buf, port, path?path:"NULL");
	    to_host = new_to_host();
	    if ( !to_host ) {
		free(path);
		free_maps(map);
		goto done;
	    }
	    bzero(to_host, sizeof(*to_host));
	    to_host->name = strdup(buf);
	    to_host->port = port;
	    to_host->path = path;
	    if ( !map->to_hosts )
	    	map->to_hosts = to_host;
	      else {
		next = map->to_hosts;
		while ( next->next ) next = next->next;
		next->next = to_host;
	    }
	    map->hosts++;
        }

        goto do_next_host;
    }
 done:;
}

void
parse_map_acl(char *p)
{
char		*s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;
int		first = TRUE;
int		acl_index;

    /* map_acl	ACLNAME SRC DST backup ... */

    p += 7; while (*p && isspace(*p) ) p++;
    s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    p = s;

    /* get acl name */
    acl_index = acl_index_by_name(buf);
    if ( !acl_index ) {
	verb_printf("ACCEL: Can't find ACL %s\n", buf);
	return;
    }
    while (*p && isspace(*p) ) p++;
    s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    if ( !strlen(buf) ) {
	verb_printf("ACCEL: Wrong map_acl line\n");
	return;
    }
    map = new_map();
    if ( !map ) goto done;
    bzero(map, sizeof(*map));
    map->type = MAP_ACL;
    map->acl_index = acl_index;
    while (*p && isspace(*p) ) p++;
    s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    if ( !strlen(buf) ) {
	verb_printf("ACCEL: Wrong map_acl line\n");
	return;
    }
    if (regcomp(&map->preg, buf, REG_EXTENDED|REG_ICASE)) {
	verb_printf("Cant regcomp %s\n", buf);
	free(map);
	goto done;
    }
    p = s;
do_next_host:
    while (*p && isspace(*p) ) p++;
    if ( !*p ) {
	if ( !maps ) maps = map;
	  else {
	    struct map *this = maps;
	    while ( this->next ) this = this->next;
	    this->next = map;
	}
	place_map_in_hash(map);
	goto done;
    }
    s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
    *d++ = *s++;
    *d = 0;
    p = s;
    if ( strlen(buf) ) {
	struct	to_host	*to_host, *next;

	printf("mapped to %s\n", buf);
	to_host = new_to_host();
	if ( !to_host ) {
	    free_maps(map);
	    goto done;
	}
	bzero(to_host, sizeof(*to_host));
	if ( !first ) to_host->port = 80;
	if ( !first && ( o = strchr(buf, ':') ) ) {
	    to_host->port = atoi(o+1);
	    *o = 0;
	}
	to_host->name = strdup(buf);
	if ( !map->to_hosts )
	    map->to_hosts = to_host;
	  else {
	    /* all hosts except first are analyzed for :port	*/
	    next = map->to_hosts;
	    while ( next->next ) next = next->next;
	    next->next = to_host;
	}
	map->hosts++;
	first = FALSE;
    }

    goto do_next_host;

done:;
}

void
parse_map_regex(char *p)
{
char		*s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;
int		first = TRUE;

    /* map_regex SRC DEST backup1[:port1] ... */
    p += 9; while (*p && isspace(*p) ) p++;
    s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    p = s;
    if ( strlen(buf) ) {
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
	map->type = MAP_REGEX;
	if (regcomp(&map->preg, buf, REG_EXTENDED|REG_ICASE)) {
	    verb_printf("Cant regcomp %s\n", buf);
	    free(map);
	    goto done;
	}
do_next_host:
	while (*p && isspace(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		struct map *this = maps;
		while ( this->next ) this = this->next;
		this->next = map;
	    }
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	p = s;
	if ( strlen(buf) ) {
	    struct	to_host	*to_host, *next;

 	    printf("mapped to %s\n", buf);
	    to_host = new_to_host();
	    if ( !to_host ) {
		free_maps(map);
		goto done;
	    }
	    bzero(to_host, sizeof(*to_host));
	    if ( !first ) to_host->port = 80;
	    if ( !first && ( o = strchr(buf, ':') ) ) {
		to_host->port = atoi(o+1);
		*o = 0;
	    }
	    to_host->name = strdup(buf);
	    if ( !map->to_hosts )
	    	map->to_hosts = to_host;
	      else {
		/* all hosts except first are analyzed for :port	*/
		next = map->to_hosts;
		while ( next->next ) next = next->next;
		next->next = to_host;
	    }
	    map->hosts++;
	    first = FALSE;
        }

        goto do_next_host;
    }
 done:;
}

void
parse_map_charset(char *p)
{
char			*s, *d, *o, *forw, *back;
char			buf[MAXHOSTNAMELEN+10];
struct	map		*map;
struct	charset		*source_charset = NULL, *destination_charset = NULL;
struct	string_list	*to_ser, *to_cli;
int			i;

    /* map_charset src_charset dst_charset from[:port] to1[:port1] to2[:port2] ... */
    p += 11;
    while (*p && isspace(*p) ) p++; s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) ) *d++ = *s++; *d=0;
    p = s;
    /* src charset */
    printf("parse_map_charset: src charset: %s\n", buf);
    if ( charsets )
	source_charset = lookup_charset_by_name(charsets, buf);
    if ( !source_charset ) {
	verb_printf("accel: parse_map_charset: unknown charset %s\n", buf);
	goto done;
    }
    while (*p && isspace(*p) ) p++; s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) ) *d++=*s++; *d=0;
    p = s;
    /* dst charset */
    printf("parse_map_charset: dst charset: %s\n", buf);
    if ( charsets )
	destination_charset = lookup_charset_by_name(charsets, buf);
    if ( !destination_charset ) {
	verb_printf("accel: parse_map_charset: unknown charset %s\n", buf);
	goto done;
    }
    if ( !source_charset->Table || !destination_charset->Table ) {
	verb_printf("accel: parse_map_charset: some charset doesn't have Table\n");
	goto done;
    }
    while (*p && isspace(*p) ) p++; s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) ) *d++ = *s++;*d=0;
    p = s;
    if ( strlen(buf) ) {
        u_short port = 80;
	char	*path;

        if ( ( o = strchr(buf, ':') ) ) {
	    port = atoi(o+1);
	    *o = 0;
	}
	printf("host=%s, port=%d\n", buf, port);
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
	map->type = MAP_STRING_CS;
	map->from_host = strdup(buf);
	map->from_port = port;
	forw = malloc(128);
	back = malloc(128);
	if ( !forw || !back ) {
	    if ( forw ) free(forw);
	    if ( back ) free(back);
	    free_maps(map);
	    goto done;
	}
	for(i=0;i<128;i++) {
	    u_char *src = source_charset->Table;
	    u_char *dst = destination_charset->Table;
	    u_char sc, dc;

	    sc = src[i];
	    forw[sc-128] = dst[i];
	    back[dst[i]-128] = sc;
	}
	map->cs_to_server_table = alloc_l_string_list();
	map->cs_to_client_table = alloc_l_string_list();
	if ( !map->cs_to_server_table || !map->cs_to_client_table) {
	    if ( forw ) free(forw);
	    if ( back ) free(back);
	    free_maps(map);
	    goto done;
	}
	lock_l_string_list(map->cs_to_server_table);
	lock_l_string_list(map->cs_to_client_table);
	to_ser = malloc(sizeof(*to_ser));
	to_cli = malloc(sizeof(*to_cli));
	if ( !to_ser || !to_cli ) {
	    if ( forw ) free(forw);
	    if ( back ) free(back);
	    free_maps(map);
	    goto done;
	}
	bzero(to_ser, sizeof(*to_ser));
	bzero(to_cli, sizeof(*to_cli));
	to_ser->string = forw;
	to_cli->string = back;
	map->cs_to_server_table->list = to_ser;
	map->cs_to_client_table->list = to_cli;
	if ( source_charset->Name ) {
	    map->src_cs_name = strdup(source_charset->Name);
	}
do_next_host:
	while (*p && isspace(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		struct map *this = maps;
		while ( this->next ) this = this->next;
		this->next = map;
	    }
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	p = s;
	if ( strlen(buf) ) {
	    u_short 	port = 80;
	    struct	to_host	*to_host, *next;
	    char	*path = NULL;

	    if ( ( o = strchr(buf, '/') ) ) {
		path = strdup(o);
 	    }
	    if ( ( o = strchr(buf, ':') ) ) {
		port = atoi(o+1);
		*o = 0;
	    }
	    printf("mapped to %s, port=%d path=%s\n", buf, port, path?path:"NULL");
	    to_host = new_to_host();
	    if ( !to_host ) {
		free(path);
		free_maps(map);
		goto done;
	    }
	    bzero(to_host, sizeof(*to_host));
	    to_host->name = strdup(buf);
	    to_host->port = port;
	    to_host->path = path;
	    if ( !map->to_hosts )
	    	map->to_hosts = to_host;
	      else {
		next = map->to_hosts;
		while ( next->next ) next = next->next;
		next->next = to_host;
	    }
	    map->hosts++;
        }

        goto do_next_host;
    }
 done:;
}

void
parse_map_regex_charset(char *p)
{
char			*s, *d, *o, *ss, *dd, *forw, *back;
char			buf[MAXHOSTNAMELEN+10];
struct	map		*map;
int			first = TRUE, i;
struct	charset		*source_charset = NULL, *destination_charset = NULL;
struct	string_list	*to_ser, *to_cli;

    /* map_regex_charset CLIENTCHARSET SERVERCHARSET SRC DEST backup1[:port1] ... */
    p += 17; while (*p && isspace(*p) ) p++;
    s = p; d = buf;
    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    p = s;
    if ( strlen(buf) ) {
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
	map->type = MAP_REGEX_CS;
	if ( charsets )
	    source_charset = lookup_charset_by_name(charsets, buf);
	if ( !source_charset ) {
	    verb_printf("ACCEL:Source charset: UNKNOWN %s\n", buf);
	    free_maps(map);
	    goto done;
	} else
	    verb_printf("ACCEL:Source charset: %s\n", buf);
	while (*s && isspace(*s) ) s++;
	d = buf;
	while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
	    *d++ = *s++;
	*d = 0;
	destination_charset = lookup_charset_by_name(charsets, buf);
	if ( !destination_charset ) {
	    verb_printf("ACCEL:Destination charset: UNKNOWN %s\n", buf);
	    free_maps(map);
	    goto done;
	} else
	    verb_printf("ACCEL:Destination charset: %s\n", buf);
	if ( !source_charset->Table || !destination_charset->Table ) {
	    verb_printf("ACCEL:One of the charsets have no Table\n", buf);
	    free_maps(map);
	    goto done;
	}
	/* we have default->src and default->dst table	*/
	/* and we must build src->dst and reverse	*/
	forw = malloc(128);
	if ( !forw ) {
	    verb_printf("ACCEL:no mem for forw\n");
	    free_maps(map);
	    goto done;
	}
	back = malloc(128);
	if ( !back ) {
	    verb_printf("ACCEL:no mem for back\n", buf);
	    free(forw);
	    free_maps(map);
	    goto done;
	}
	for(i=0;i<128;i++) {
	    u_char *src = source_charset->Table;
	    u_char *dst = destination_charset->Table;
	    u_char sc, dc;

	    sc = src[i];
	    forw[sc-128] = dst[i];
	    back[dst[i]-128] = sc;
	}
	map->cs_to_server_table = alloc_l_string_list();
	if ( !map->cs_to_server_table ) {
	    verb_printf("Can't alloc recode table\n");
	    free_maps(map);
	    goto done;
	}
	lock_l_string_list(map->cs_to_server_table);
	map->cs_to_client_table = alloc_l_string_list();
	if ( !map->cs_to_client_table ) {
	    verb_printf("Can't alloc recode table\n");
	    free_maps(map);
	    goto done;
	}
	lock_l_string_list(map->cs_to_client_table);

	to_ser = malloc(sizeof(*to_ser));
	if ( to_ser )
	    bzero(to_ser, sizeof(*to_ser));
	  else {
	    verb_printf("Can't alloc recode table\n");
	    free(forw);
	    free(back);
	    free_maps(map);
	    goto done;
	}
	to_cli = malloc(sizeof(*to_cli));
	if ( to_ser )
	    bzero(to_cli, sizeof(*to_cli));
	  else {
	    verb_printf("Can't alloc recode table\n");
	    free(forw);
	    free(back);
	    free(to_ser);
	    free_maps(map);
	    goto done;
	}
	to_ser->string = forw;
	to_cli->string = back;
	map->cs_to_server_table->list = to_ser;
	map->cs_to_client_table->list = to_cli;
	if ( source_charset->Name ) {
	    map->src_cs_name = strdup(source_charset->Name);
	}
	while (*s && isspace(*s) ) s++;
	d = buf;
	while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
	    *d++ = *s++;
	*d = 0;
	p = s;
	if (regcomp(&map->preg, buf, REG_EXTENDED|REG_ICASE)) {
	    verb_printf("Cant regcomp %s\n", buf);
	    free_maps(map);
	    goto done;
	}

do_next_host:
	while (*p && isspace(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		struct map *this = maps;
		while ( this->next ) this = this->next;
		this->next = map;
	    }
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	p = s;
	if ( strlen(buf) ) {
	    struct	to_host	*to_host, *next;

 	    printf("mapped to %s\n", buf);
	    to_host = new_to_host();
	    if ( !to_host ) {
		free_maps(map);
		goto done;
	    }
	    bzero(to_host, sizeof(*to_host));
	    if ( !first ) to_host->port = 80;
	    if ( !first && ( o = strchr(buf, ':') ) ) {
		to_host->port = atoi(o+1);
		*o = 0;
	    }
	    to_host->name = strdup(buf);
	    if ( !map->to_hosts )
	    	map->to_hosts = to_host;
	      else {
		/* all hosts except first are analyzed for :port	*/
		next = map->to_hosts;
		while ( next->next ) next = next->next;
		next->next = to_host;
	    }
	    map->hosts++;
	    first = FALSE;
        }

        goto do_next_host;
    }
 done:;
}
char*
build_destination(char *src, regmatch_t *pmatch, char *target)
{
regmatch_t	*curr = pmatch+1;
int		length = 0, subs = 0, n;
char		*result = NULL, *s, *d, esc, doll;

    if ( !src || !target || !pmatch )
	return(NULL);
    while ( curr->rm_so > -1 ) {
	length = curr->rm_eo - curr->rm_so + 1;
	subs++;
	curr++;
    }
    length += strlen(target)+1;
    result = malloc(length);
    if ( !result ) return(NULL);
    /* build */
    if ( !subs ) {
	/* just copy */
	strcpy(result, target);
	return(result);
    }
    esc = doll = 0;
    s = target;
    d = result;
    while ( *s ) {
	if ( (*s == '\\') && !esc ) {
	    esc = TRUE;
	    s++;
	    continue;
	}
	if ( (*s == '$') && esc ) {
	    esc = FALSE;
	    *d = '$';
	    s++;d++;
	    continue;
	}
	if ( (*s == '\\') && esc ) {
	    esc = FALSE;
	    *d = '\\';
	    s++;d++;
	    continue;
	}
	esc = FALSE;
	if ( *s == '$' ) {
	    doll = TRUE;
	    s++;
	    continue;
	}
	if ( isdigit(*s) && doll ) {
	    /* insert n-th subexpression */
	    n = *s - '0';
	    if ( ( n > 0 ) && ( n < MAXMATCH) ) {
		int	copylen;
		curr = &pmatch[n];
		copylen = curr->rm_eo - curr->rm_so;

		memcpy(d, src+curr->rm_so, copylen);
		d+=copylen;
	    }
	    s++;
	    doll = FALSE;
	    continue;
	}
	doll = FALSE;
	*d = *s;
	s++;d++;
    }
    *d = 0;
    return(result);
}
char*
build_src(struct request *rq)
{
char			*url = NULL, *host;
int			urllen;
u_short			port;

    if ( !rq || !rq->av_pairs) return(NULL);
    if ( rq->original_host ) {
	host = rq->original_host;
    } else
	host = attr_value(rq->av_pairs, "host");
    if ( !host ) return(NULL);
    /* now build url for regex matching				*/
    if ( rq->url.path) {
	char	*dd;

	urllen = strlen(host)
		+strlen(rq->url.path) + 20;
	url = malloc(urllen);
	if ( dd = strchr(host, ':') ) {
	    u_short host_port;
	    *dd = 0;
	    host_port = atoi(dd+1);
	    if ( host_port ) port = host_port;
	} else
	    port = 80;
	if ( url ) {
	    if ( port != 80 )
		sprintf(url, "http://%s:%d%s", host,port,
				rq->url.path);
	      else
		sprintf(url, "http://%s%s", host,
				rq->url.path);
	}
	if ( dd ) *dd = ':';
    }
    return(url);
}
void
insert_rewrite_location(char *p)
{
char	*t, *token, *ptr;
char	*acl = NULL, *src = NULL, *dst = NULL;
char	*src_buf = NULL, *dst_buf = NULL;
int	acl_index;
rewrite_location_t	*new, *next;

    if ( !p ) return;
    /* must be in form ACL SRC DST */
    t = p;
    while ( ( token = (char*)strtok_r(t, "\t ", &ptr) ) ) {
	t = NULL;

	if ( !acl ) {
	    acl = token;
	    acl_index = acl_index_by_name(token);
	    if ( !acl_index ) verb_printf("ACCEL: Unknown ACL %s\n", acl);
	} else
	if ( !src ) {
	    src = token;
	    src_buf = strdup(src);
	} else
	if ( !dst ) {
	    dst = token;
	    dst_buf = strdup(dst);
	}
    }
    if ( acl_index && src_buf && dst_buf ) {
	/* 1. create new rewr_location	*/
	new = malloc(sizeof(*new));
	if ( new ) {
	    bzero(new, sizeof(*new));
	    /* 2. fill all fields	*/
	    new->acl_index = acl_index;
	    new->dst = dst_buf; dst_buf = NULL;
	    if ( regcomp(&new->preg, src_buf, REG_EXTENDED|REG_ICASE) ) {
		verb_printf("ACCEL: Can't compile regex %s\n", src_buf);
		goto error;
	    }
	    /* 3. insert in list	*/
	    if ( !rewrite_location )
		rewrite_location = new;
	      else {
		next = rewrite_location;
		while ( next->next ) next = next->next;
		next->next = new;
	    }
	    /* done */
	}
    } else {
	verb_printf("ACCEL: wrong rewrite_location directive; %s\n", p);
    }
done:
    if ( dst_buf ) free(dst_buf);
    if ( src_buf ) free(src_buf);
    return;
error:
    if ( new ) {
	if ( new->dst ) free(new->dst);
	free(new);
    }
    goto done;
}
void
free_rewrite_location(rewrite_location_t *list)
{
rewrite_location_t	*next;

    while ( list ) {
	next = list->next;
	regfree(&list->preg);
	if ( list->dst ) free(list->dst);
	free(list);
	list = next;
    }
}

void
check_map_file_age()
{
    if ( global_sec_timer - map_file_check_time > 60 )
	reload_map_file();
}

void
reload_map_file()
{
struct	stat	sb;
int		rc;
FILE		*mf;
char		buf[1024], *s, *d, *o;
struct	map	*map;
    /* the worst thing we can get if we go without locks
       for map_file_check_time is: rare case when two threads
       will reload maps. This will not lead to anything bad
    */
    map_file_check_time = global_sec_timer;

    rc = stat(map_file, &sb);
    if ( rc == -1 ) {
	verb_printf("accel: Can't stat %s: %s\n", map_file, strerror(errno));
	my_log("accel: Can't stat %s: %s\n", map_file, strerror(errno));
	return;
    }
    if ( sb.st_mtime <= map_file_mtime )
	return;
    WRLOCK_ACCEL_CONFIG ;
    map_file_mtime = sb.st_mtime;
    my_log("accel: reload mapfile\n");
    mf = fopen(map_file, "r");
    if ( !mf ) {
	verb_printf("accel: Can't fopen %s: %s", map_file, strerror(errno));
	goto done;
    }
    if ( map_hash_table ) {
	free(map_hash_table);
	map_hash_table = NULL;
    }
    if ( maps ) {
       free_maps(maps);
       maps = NULL;
    }
    if ( default_map ) {
	free_maps(default_map);
	default_map = NULL;
    }
    if ( refr_patts ) {
	free_refresh_patterns(refr_patts);
	refr_patts = NULL;
    }
    if ( rewrite_location ) {
	free_rewrite_location(rewrite_location);
	rewrite_location = NULL;
    }
    if ( use_host_hash ) {
	map_hash_table = calloc(use_host_hash, sizeof(*map_hash_table));
    }
    other_maps_chain = NULL;

    while ( fgets(buf, sizeof(buf) - 1, mf) ) {
      char *p;
	buf[sizeof(buf)-1] = 0;
	if ( (p = strchr(buf,'\n')) ) *p = 0;
	verb_printf("accel: got line: %s\n", buf);
	p = buf; while ( *p && isspace(*p) ) p++;
	if ( *p == '#' ) continue;
	if ( !strncasecmp(p, "dead_timeout", 12) ) {
	    p += 12;
	    while (*p && isspace(*p) ) p++;
	    dead_timeout = atoi(p);
	} else
	if ( !strncasecmp(p, "sleep_timeout", 13) ) {
	    p += 13;
	    while (*p && isspace(*p) ) p++;
	    sleep_timeout = atoi(p);
	} else
	if ( !strncasecmp(p, "refresh_pattern", 15) ) {
	    p += 15;
	    verb_printf("%s will use refresh pattern\n", module_name);
	    parse_refresh_pattern(&refr_patts, p);
	} else
	if ( !strncasecmp(p, "rewrite_location", 16) ) {
	    verb_printf("%s will rewrite 'Location:' host\n", module_name);
	    p += 16;
	    insert_rewrite_location(p);
	} else
	if ( !strncasecmp(p, "use_host_hash", 13) ) {
	    p += 13;
	    while (*p && isspace(*p) ) p++;
	    use_host_hash = atoi(p);
	    if ( use_host_hash ) {
		if ( map_hash_table )
		    free(map_hash_table);
		map_hash_table = calloc(use_host_hash, sizeof(*map_hash_table));
	    }
	} else
	if ( !strncasecmp(p, "rewrite_host", 12) ) {
	    p += 12; while (*p && isspace(*p) ) p++;
	    if ( !strcasecmp(p, "yes") ) {
		rewrite_host = TRUE;
		verb_printf("%s will rewrite 'Host:' header\n", module_name);
	    } else {
		rewrite_host = FALSE;
		verb_printf("%s won't rewrite 'Host:' header\n", module_name);
	    }
	} else
	if ( !strncasecmp(p, "default", 7) ) {
	    /* allocate default map */
	    p += 7;while (*p && isspace(*p) ) p++;
	    s = p; d = buf;
	    while ( *s && !isspace(*s) && ( d - buf < sizeof(buf) ) )
		*d++ = *s++;
	    *d = 0;
	    p = s;
	    if ( strlen(buf) ) {
		u_short 	port = 80;
		struct	to_host	*to_host;

		if ( ( o = strchr(buf, ':') ) ) {
		    port = atoi(o+1);
		    *o = 0;
		}
		printf("default host=%s, port=%d\n", buf, port);
		map = new_map();
		if ( !map ) goto done;
		bzero(map, sizeof(*map));
		map->from_host = strdup(buf);
		map->from_port = port;
		map->type = MAP_STRING;
		if ( default_map ) free_maps(default_map);
		default_map = map;
		to_host = new_to_host();
		if ( !to_host ) {
		    free_maps(default_map);
		    default_map = NULL;
		    continue;
	        }
		bzero(to_host, sizeof(*to_host));
		to_host->name = strdup(buf);
		to_host->port = port;
		to_host->next = map->to_hosts;
		default_map->to_hosts = to_host;
		default_map->hosts++;
	    }
	} else
	if ( !strncasecmp(p, "map_regex_charset", 17) )
	    parse_map_regex_charset(p);
	else
	if ( !strncasecmp(p, "map_charset", 11) )
	    parse_map_charset(p);
	else
	if ( !strncasecmp(p, "map_regex", 9) )
	    parse_map_regex(p);
	else
	if ( !strncasecmp(p, "map_acl", 7) )
	    parse_map_acl(p);
	else
	if ( !strncasecmp(p, "map", 3) )
	    parse_map(p);
    }

done:
    UNLOCK_ACCEL_CONFIG ;
}
