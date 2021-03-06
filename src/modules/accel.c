/*
Copyright (C) 1999 Igor Khasilev, igor@paco.net

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

#include	"../oops.h"
#include	"../modules.h"

#define	MODULE_NAME "accel"
#define	MODULE_INFO "WWW-accelerator"

#if	defined(MODULES)
char            module_type   = MODULE_REDIR ;
char            module_name[] = MODULE_NAME ;
char            module_info[] = MODULE_INFO ;
int             mod_load(void);
int             mod_unload(void);
int             mod_config_beg(int), mod_config_end(int), mod_config(char*, int), mod_run(void);
int             redir(int, struct group*, struct request*, int*, int);
int             redir_connect(int*, struct request*, int*, int);
int             redir_rewrite_header(char **, struct request*, int*, int);
int             redir_control_request(int, struct group*, struct request*, int*, int);
#define         MODULE_STATIC
#else
static  char    module_type   = MODULE_REDIR ;
static  char    module_name[] = MODULE_NAME ;
static  char    module_info[] = MODULE_INFO ;
static  int     mod_load();
static  int     mod_unload();
static  int     mod_config_beg(int), mod_config_end(int), mod_config(char*, int), mod_run();
static  int     redir(int, struct group*, struct request*, int*, int);
static  int     redir_connect(int*, struct request*, int*, int);
static  int     redir_rewrite_header(char **, struct request*, int*, int);
static  int     redir_control_request(int, struct group*, struct request*, int*, int);
#define         MODULE_STATIC   static
#endif

struct	redir_module	accel = {
        {
        NULL, NULL,
        MODULE_NAME,
        mod_load,
        mod_unload,
        mod_config_beg,
        mod_config_end,
        mod_config,
        NULL,
        MODULE_REDIR,
        MODULE_INFO,
        mod_run
        },
        redir,
        redir_connect,
        redir_rewrite_header,
        redir_control_request
};

static  pthread_rwlock_t	accel_lock;
#define RDLOCK_ACCEL_CONFIG     pthread_rwlock_rdlock(&accel_lock)
#define WRLOCK_ACCEL_CONFIG     pthread_rwlock_wrlock(&accel_lock)
#define UNLOCK_ACCEL_CONFIG     pthread_rwlock_unlock(&accel_lock)

#define MAP_STRING              1
#define MAP_REGEX               2
#define MAP_STRING_CS           3
#define MAP_REGEX_CS            4
#define MAP_ACL                 5
#define MAP_EXTERNAL            6
#define MAP_EXTERNAL_REGEX      7

char	*mapnames[9] = {
        "?",
        "string",
        "regex",
        "string+charset",
        "regex+charset",
        "acl",
        "external",
        "external+regex"
        "?"};

#define MAXMATCH                10
#define INIT_PMATCH(p)          do {\
                                int i;\
                                        for(i=0;i<MAXMATCH;i++)\
                                        p[i].rm_so = p[i].rm_eo = -1;\
                                } while(0)
#define NMYPORTS        8
static  myport_t        myports[NMYPORTS];      /* my ports             */
static  int             nmyports;               /* actual number        */
static  char            *myports_string = NULL;
static  char            *access_string	= NULL;

static	refresh_pattern_t	*refr_patts;

struct	to_host {
        struct	to_host	*next;
        char		*name;
        u_short		port;
        char		*path;		/* if we have to prepend path	*/
        char		failed;		/* TRUE or FALSE 		*/
        time_t		last_failed;	/* when failed to connect 	*/
};

#define MAP_REVERSE     1
#define MAP_CANPURGE    2
#define MAP_CANPURGE_R  4

struct	map {
    struct map              *next;
    int                     type;
    char                    *from_host;
    regex_t                 preg;                   /* regex if MAP_REGEX                   */
    int                     acl_index;              /* acl index if type MAP_ACL            */
    u_short                 from_port;
    int                     hosts;
    pthread_mutex_t         last_lock;
    struct      to_host     *to_hosts;
    struct      to_host     *last_used;
    l_string_list_t         *cs_to_server_table;    /* translation from client to server    */
    l_string_list_t         *cs_to_client_table;    /* translation from server to client    */
    char                    *src_cs_name;           /* source charset name                  */
    struct map              *next_in_hash;          /* link in hash     table for usual maps,
                                                       next map for acl, regex maps         */
    struct map              *next_in_reverse_hash;  /* link in reverse_hash                 */
    int                     ortho;                  /* something orthogonal to hash function*/
    int                     reverse_ortho;          /* something orthogonal to hash function*/
    char                    *config_line;           /* original config line                 */
    int                     flags;                  /* flags like 'reverse'                 */
    time_t                  site_purged;            /* when site was purged                 */
};

typedef struct	rewrite_location_ {
    struct  rewrite_location_   *next;
    int                         acl_index;
    regex_t                     preg;
    char                        *dst;
} rewrite_location_t ;

typedef struct  map_hash_ {
        struct  map     *next;
} map_hash_t;

static  struct  map         *maps, *default_map, *new_map(void), *last_map;
static  struct  map         *find_map(struct request*, size_t, regmatch_t*, char*);
static  struct  map         *lookup_map(size_t, regmatch_t*, char*, u_short);
static  int                 set_purge_date_r(size_t, regmatch_t*, char*, u_short, time_t);
static  struct  map         *other_maps_chain;
static  map_hash_t          *map_hash_table;
static  map_hash_t          *reverse_hash_table;
static  struct to_host      *new_to_host(void);
static  int                 rewrite_host;
static  int                 use_host_hash;
static  void                free_maps(struct map *);
static  void                place_map_in_hash(struct map*);
static  void                place_map_in_reverse_hash(struct map*);
static  int                 parse_access(char *string, myport_t *ports, int number);
static  void                parse_map(char*);
static  void                parse_map_acl(char*);
static  void                parse_map_external(char*);
static  void                parse_map_external_regex(char*);
static  void                parse_map_regex(char*);
static  void                parse_map_regex_charset(char*);
static  void                parse_map_charset(char*);
static  void                parse_map_file(char*);
static  void                check_map_file_age(void);
static  void                reload_map_file(void);
static  void                set_canpurge(char*);
static  void                set_canpurge_r(char*);
static  int                 on_my_port(struct request *);
static  int                 sleep_timeout, dead_timeout;
static  char                *build_destination(char*,regmatch_t*, char*);
static  char                *build_src(struct request *);
static  rewrite_location_t  *rewrite_location;
static  void                insert_rewrite_location(char*);
static  void                free_rewrite_location(rewrite_location_t*);

static  char            map_file[MAXPATHLEN];
static  time_t          map_file_mtime = 0, map_file_check_time = 0;
static  int             deny_proxy_requests;
static  int             ip_lookup;



/* can be in the form aaa.bbb.ccc.ddd:port
   or port
*/

static int
parse_access(char *string, myport_t *ports, int number)
{
char            buf[20], *p, *d, *t;
u_short         port;
myport_t        *pptr=ports;
int             nres=0, rc, one=-1, so;
struct          sockaddr_in     sin_addr;

    if ( !ports || !string ) return(0);
    while( string && *string && (nres < number) ) {
        p = string;
        while ( *p && IS_SPACE(*p) ) p++;
        if ( !*p ) return(nres);
        d = buf;
        while ( *p && !IS_SPACE(*p) ) {
            *d++ = *p++;
        }
        *d = 0;
        string = p;
        if ( (t = (char*)strchr(buf, ':')) != 0 ) {
            *t = 0;
            port = (u_short)atoi(t+1);
            bzero(&sin_addr, sizeof(sin_addr));
            str_to_sa(buf, (struct sockaddr*)&sin_addr);
        } else {
            port = (u_short)atoi(buf);
            bzero(&sin_addr, sizeof(sin_addr));
        }
        nres++;
        pptr->port = port;
        pptr->in_addr = sin_addr.sin_addr;
        pptr++;
    }
    return(nres);
}



static unsigned
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

static unsigned
ortho_hash_function(char *s)
{
unsigned int j = 0;

    if ( use_host_hash <= 0 ) return(0);

    while (*s) {
        j += *(s++);
    }

    return( j );
}

static void
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
    /* also place in reverse hash */
    place_map_in_reverse_hash(map);
}

static void
place_map_in_reverse_hash(struct map *map)
{
unsigned        b, o;
struct map      *this;
char            host_tmp[MAXHOSTNAMELEN], *s, *d;

    if ( !map || !reverse_hash_table ) return;

    if ( !map->to_hosts || !map->to_hosts->name ) return;
    d = host_tmp; s = map->to_hosts->name;
    while ( *s && (d - host_tmp < MAXHOSTNAMELEN) ) *d++ = tolower(*s++);
    *d = 0;
    b = hash_function(host_tmp);
    o = ortho_hash_function(host_tmp);
    map->reverse_ortho = o;

    if ( !reverse_hash_table[b].next ) reverse_hash_table[b].next = map;
      else {
        this = reverse_hash_table[b].next;
        while ( this->next_in_reverse_hash ) this = this->next_in_reverse_hash;
        this->next_in_reverse_hash = map;
    }
}

int
mod_load(void)
{
    pthread_rwlock_init(&accel_lock, NULL);
    nmyports = 0;
    maps = NULL;
    default_map = NULL;
    sleep_timeout = 30;
    dead_timeout = 20;
    refr_patts = NULL;
    rewrite_location = NULL;
    rewrite_host = TRUE;
    map_file[0] = 0;
    use_host_hash = 0;
    map_hash_table = NULL;
    reverse_hash_table = NULL;
    other_maps_chain = NULL;
    myports_string = NULL;
    access_string  = NULL;
    deny_proxy_requests = 1;
    ip_lookup = TRUE;

    printf("Accel started\n");

    return(MOD_CODE_OK);
}

int
mod_unload(void)
{
    verb_printf("banners stopped\n");
    return(MOD_CODE_OK);
}

int
mod_config_beg(int i)
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
        free(reverse_hash_table);
        map_hash_table = NULL;
    }
    other_maps_chain = NULL;
    sleep_timeout = 600;
    dead_timeout = 20;
    map_file_mtime = 0;
    map_file_check_time = 0;
    if ( myports_string ) free(myports_string);
    myports_string = NULL;
    if ( access_string ) free(access_string);
    access_string = NULL;
    
    deny_proxy_requests = 1;
    ip_lookup = TRUE;
    UNLOCK_ACCEL_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_run(void)
{
    WRLOCK_ACCEL_CONFIG ;
    if ( myports_string ) {
        nmyports = parse_myports(myports_string, &myports[0], NMYPORTS);
        verb_printf("%s will use %d ports\n", MODULE_NAME, nmyports);
    }
    UNLOCK_ACCEL_CONFIG ;

    if ( access_string != NULL ){     
        nmyports = parse_access(access_string, &myports[0], NMYPORTS);
        verb_printf("%s will use %d ports for access\n", MODULE_NAME, nmyports);
    }

    return(MOD_CODE_OK);
}

int
mod_config_end(int i)
{
    if ( use_host_hash > 0 ) {
        map_hash_table = calloc(use_host_hash, sizeof(*map_hash_table));
        reverse_hash_table = calloc(use_host_hash, sizeof(*map_hash_table));
    }
    if ( map_file )
        reload_map_file();
    return(MOD_CODE_OK);
}

int
mod_config(char *config, int i)
{
char    *p = config;

    WRLOCK_ACCEL_CONFIG ;
    while( *p && IS_SPACE(*p) ) p++;

    if ( !strncasecmp(p, "myport", 6) ) {
        p += 6;
        while (*p && IS_SPACE(*p) ) p++;
        myports_string = strdup(p);
        /*nmyports = parse_myports(p, &myports, NMYPORTS);*/
        verb_printf("%s will use %d ports\n", MODULE_NAME, nmyports);
    } else
    if ( !strncasecmp(p, "access", 6) ) {
        p += 6;
        while (*p && IS_SPACE(*p) ) p++;
        access_string = strdup(p);
        verb_printf("%s will use %d ports for access\n", MODULE_NAME, nmyports);
    } else
    if ( !strncasecmp(p, "rewrite_host", 12) ) {
        p += 12; while (*p && IS_SPACE(*p) ) p++;
        if ( !strcasecmp(p, "yes") ) {
            rewrite_host = TRUE;
            verb_printf("%s will rewrite 'Host:' header\n", MODULE_NAME);
        } else {
            rewrite_host = FALSE;
            verb_printf("%s won't rewrite 'Host:' header\n", MODULE_NAME);
        }
    } else
    if ( !strncasecmp(p, "dead_timeout", 12) ) {
        p += 12;
        while (*p && IS_SPACE(*p) ) p++;
        dead_timeout = atoi(p);
    } else
    if ( !strncasecmp(p, "use_host_hash", 13) ) {
        p += 13;
        while (*p && IS_SPACE(*p) ) p++;
        use_host_hash = atoi(p);
    } else
    if ( !strncasecmp(p, "proxy_requests", 14) ) {
        p += 14;
        while (*p && IS_SPACE(*p) ) p++;
        deny_proxy_requests = !strncasecmp(p, "deny", 4);
    } else
    if ( !strncasecmp(p, "ip_lookup", 9) ) {
        p += 9;
        while (*p && IS_SPACE(*p) ) p++;
        ip_lookup = strncasecmp(p, "no", 2);
    } else
    if ( !strncasecmp(p, "sleep_timeout", 13) ) {
        p += 13;
        while (*p && IS_SPACE(*p) ) p++;
        sleep_timeout = atoi(p);
    } else
    if ( !strncasecmp(p, "file", 4) )
        parse_map_file(p);
    UNLOCK_ACCEL_CONFIG ;


    return(MOD_CODE_OK);
}

static struct	map
*new_map(void)
{
struct	map	*res;

    res = malloc(sizeof(*res));
    if ( !res ) return(NULL);
    bzero(res, sizeof(*res));
    pthread_mutex_init(&res->last_lock, NULL);
    return(res);
}

static struct to_host
*new_to_host(void)
{
struct	to_host	*res;

    res = malloc(sizeof(*res));
    if ( !res ) return(NULL);
    bzero(res, sizeof(*res));
    return(res);
}

static void
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
            if ( host->path ) free(host->path);
            free(host);
            host = next_host;
        }
        pthread_mutex_destroy(&map->last_lock);
        if ( map->config_line ) free(map->config_line);
        free(map);
        map = next_map;
    }
}

int
redir_rewrite_header(char **hdr, struct request *rq, int *flags, int instance)
{
struct  map         *map;
struct  url         url, new_url;
char                *p, *new_location = NULL, *src = NULL, *new_l_val = NULL;
regmatch_t          pmatch[MAXMATCH];
rewrite_location_t  *rl;

    if ( !rewrite_location
         || !hdr || !*hdr || !rq ) return(MOD_CODE_OK);
    if ( !(**hdr == 'L' || **hdr == 'l' ) ) return(MOD_CODE_OK);
    if ( strncasecmp(*hdr, "Location:", 9) ) return(MOD_CODE_OK);

    p = (*hdr) + 9;
    while ( *p && IS_SPACE(*p) ) p++;
    if ( !*p )
        return(MOD_CODE_OK);

    RDLOCK_ACCEL_CONFIG ;

    bzero(&url, sizeof(url));
    bzero(&new_url, sizeof(new_url));

    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "redir_rewrite_header(): called for `%s'.\n", *hdr);

    src = build_src(rq);
    INIT_PMATCH(pmatch);
    map = find_map(rq, MAXMATCH, pmatch, src);

    if ( !map )
        goto done;

    rl = rewrite_location;
    while ( rl ) {
        /* if the source match acl	*/
        if ( rl->acl_index && url_match_named_acl_by_index(src, rl->acl_index) ) {
            /* if 'Location:' value match rl->preg	*/
            INIT_PMATCH(pmatch);
            if ( !regexec(&rl->preg, p, MAXMATCH, (regmatch_t*)&pmatch, 0) ) {
                /* here it is  */
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

   We connect to 'dst' in map if there are no backups. Otherwise we connect
   to backups
*/

int
redir_connect(int *resulting_so, struct request *rq, int *flags, int instance)
{
struct	map             *map;
struct	to_host         *host;
int                     max_attempts, so = -1, rc;
struct	sockaddr_in     server_sa;
regmatch_t              pmatch[MAXMATCH];
char                    *src = NULL, *destination = NULL;
struct  url             tmp_url;

    /* this lock can be long (if we can't connect immediately) */
    bzero(&tmp_url, sizeof(tmp_url));
    RDLOCK_ACCEL_CONFIG ;
    if ( !rq  ) goto done;;
    if ( !resulting_so ) goto done;

    src = build_src(rq);
    INIT_PMATCH(pmatch);
    map = find_map(rq, MAXMATCH, pmatch, src);
    if ( !map || !map->hosts ) goto done;
    /* connect using next server */
    max_attempts = map->hosts;
    if ( max_attempts > 1 ) /* we skip firsh host (dst) */
        max_attempts--;
    pthread_mutex_lock(&map->last_lock);
    host = map->last_used;
    if ( !host ) {
        if ( (map->hosts > 1) && map->to_hosts->next ) {
            /* skip dst - we use only backups to connect to destination */
            host = map->to_hosts->next;
        } else
        host = map->to_hosts;
    }
    map->last_used = host->next;
    /* if host marked as failed and sleep_timeout passed - try it */
    if ( host->failed && (global_sec_timer - host->last_failed > sleep_timeout) )
        host->failed = FALSE;
    pthread_mutex_unlock(&map->last_lock);
    if ( !host ) goto done;	/* something wrong */

    so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( so < 0 )
        goto done;

    if ( bind(so,(struct sockaddr*)&rq->conn_from_sa,sizeof(struct sockaddr)) == -1 ) {
      my_xlog(OOPS_LOG_SEVERE,"redir_connect(): bind: can't bind to connect_from IP in accel module\n");
      goto done;
    }

    while ( max_attempts ) {
        if ( !host->failed ) {
            char        *use_name;
            u_short     use_port;
            /* we can try this */
            /* if map is regex then first record can be regex			*/
            /* in this case we can use host and port from rewritten request	*/
            if ( ((map->type == MAP_REGEX)
                ||(map->type==MAP_ACL)
                ||(map->type==MAP_REGEX_CS))
                  && (host == map->to_hosts) ) {
                destination = build_destination(src,pmatch, map->to_hosts->name);
                parse_raw_url(destination, &tmp_url);
                IF_FREE(destination); destination = NULL;
                use_name = tmp_url.host;
                use_port = tmp_url.port;
                if ( !use_port ) use_port = 80;
            } else {
                use_name = host->name;
                use_port = host->port;
                /* Added by Tolyar */
                if ( !map->from_port || !use_port ) use_port = rq->url.port;
            }
            my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "redir_connect(): Connecting to %s:%d\n", use_name, use_port);
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
            if ( ERRNO == EINPROGRESS ) {
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
                my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "redir_connect(): Connect failed.\n");
            }
            if ( so != -1 ) {
                close(so);
                so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if ( so < 0 )
                    goto done;
            }
            host->failed = TRUE;
            host->last_failed = global_sec_timer;
        } else {
            my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "redir_connect(): Host %s failed %d ago. Sleep_timeout=%d\n",
                host->name?host->name:"???", 
                global_sec_timer-host->last_failed,
                sleep_timeout);
        }
  try_next_host:
        free_url(&tmp_url); bzero(&tmp_url, sizeof(tmp_url));
        host = host->next;
        if ( !host ) host = map->to_hosts;
        max_attempts--;
    }
    UNLOCK_ACCEL_CONFIG ;
    if ( so >= 0 )
        close(so);
    IF_FREE(src);
    IF_FREE(destination);
    free_url(&tmp_url);
    return(MOD_CODE_ERR);
done:
    UNLOCK_ACCEL_CONFIG ;
    IF_FREE(src);
    IF_FREE(destination);
    free_url(&tmp_url);
    return(MOD_CODE_OK);
}

int
redir(int so, struct group *group, struct request *rq, int *flags, int instance)
{
struct	map		*map;
regmatch_t		pmatch[MAXMATCH];
char            *destination = NULL, *src = NULL, *ohost;
struct	av		*host_av;

    if ( (rq->meth == METH_PURGE_SITE) || (rq->meth == METH_PURGE_SITE_R) ) {
        return(redir_control_request(so, group, rq, flags, instance));
    };

    check_map_file_age();

    RDLOCK_ACCEL_CONFIG ;
    my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "accel/redir(): called.\n");
    if ( !rq ) goto done;

    src = build_src(rq);
    INIT_PMATCH(pmatch);
    map = find_map(rq, MAXMATCH, pmatch, src);
    if ( map && map->to_hosts)
        goto map_found;

    if ( deny_proxy_requests ) {
        if ( rq && on_my_port(rq) && rq->url.host ) {
            struct	output_object	*output;
            UNLOCK_ACCEL_CONFIG ;
            say_bad_request(so, "Access denied", "No proxy requests allowed", ERR_ACC_DENIED, rq);
            if ( flags ) *flags |= MOD_AFLAG_OUT;
            return(MOD_CODE_ERR);
        }
    }
    goto done;
map_found:

    if ( map->config_line ) my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "accel/redir(): request matched to %s map `%s'.\n",
        mapnames[map->type], map->config_line);

    if ( map->site_purged != 0 )
        my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "accel/redir(): map->site_purged != 0\n");

    rq->site_purged = map->site_purged;
    
    IF_FREE ( rq->original_host );
    rq->original_host = NULL;
    IF_FREE ( rq->original_path );
    rq->original_path = NULL;

    ohost = attr_value(rq->av_pairs, "host:");
    if ( ohost ) /* we was able to extract Host: */
	rq->original_host = strdup(ohost);

    if ( rq->url.path ) rq->original_path = strdup(rq->url.path);

    /* Now! rewrite url */
    if ( rq->url.host ) free(rq->url.host);
    rq->url.host = NULL;
    
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
	if ( map->src_cs_name ) {
	    strncpy(rq->src_charset, map->src_cs_name, sizeof(rq->src_charset)-1 );
	    rq->src_charset[sizeof(rq->src_charset)-1] = 0;
	}
case MAP_STRING:
	/* 1. rewrite host part			*/
	if ( TEST(map->flags, MAP_REVERSE) && ohost) {
	    rq->url.host = strdup(ohost);
	} else
	if ( map->to_hosts->name ) {
	    rq->url.host = strdup(map->to_hosts->name);
	}

	/* 2. rewrite port part			*/

	/*Changed by Tolyar*/

	if ( map->from_port ) rq->url.port = map->to_hosts->port;
	else rq->url.port=0;
	
	if ( (!rq->url.port) && (rq->original_host != NULL) )
	{
		char *tmp_port;
		if ( (tmp_port=index(rq->original_host,':')) != NULL && isdigit(*(tmp_port+1)) )
		    rq->url.port=map->to_hosts->port + (u_short)atoi(tmp_port+1);
		  else 
		    rq->url.port=map->to_hosts->port + 80;
	};
	
	/*End of Changes*/

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
case MAP_EXTERNAL:
        /* Prepare answer with Location:        */
        {
	    struct	output_object	*output;
	    output = malloc(sizeof(*output));
	    if ( output ) {
                char redirected[] = "redirected by accel\n";
                char *new_location;
                int  location_len = 0;

		bzero(output, sizeof(*output));
		output->body = alloc_buff(128);
		put_av_pair(&output->headers,"HTTP/1.0", "302 Moved Temporarily");
		put_av_pair(&output->headers,"Expires:", "Thu, 01 Jan 1970 00:00:01 GMT");
		put_av_pair(&output->headers,"Content-Type:", "text/html");

	        /* 1. rewrite host part			*/
	        if ( TEST(map->flags, MAP_REVERSE) && ohost) {
	            rq->url.host = strdup(ohost);
	        } else
	        if ( map->to_hosts->name ) {
	            rq->url.host = strdup(map->to_hosts->name);
	        }

	        /* 2. rewrite port part			*/

	        /*Changed by Tolyar*/

	        if ( map->from_port ) rq->url.port = map->to_hosts->port;
	        else rq->url.port=0;
	
	        if ( (!rq->url.port) && (rq->original_host != NULL) ) {
		    char *tmp_port;
		    if ( (tmp_port=index(rq->original_host,':')) != NULL && isdigit(*(tmp_port+1)) )
		        rq->url.port=map->to_hosts->port + (u_short)atoi(tmp_port+1);
		      else 
		        rq->url.port=map->to_hosts->port + 80;
	        };
	
	        /*End of Changes*/

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

                /* New location now is in the rq.url */
                location_len += strlen(rq->url.proto) + 
                                strlen(rq->url.host) +
                                strlen(rq->url.path) +
                                10 /* port */ +
                                3  /* ://  */ +
                                1  /* \0   */ + 10;
                new_location = malloc(location_len);
                if (rq->url.port != 80 )
                        snprintf(new_location,location_len - 1, "%s://%s:%d%s", rq->url.proto,
                                                       rq->url.host,
                                                       rq->url.port,
                                                       rq->url.path);
                   else 
                        snprintf(new_location,location_len - 1, "%s://%s%s",rq->url.proto,
                                                       rq->url.host,
                                                       rq->url.path);

                put_av_pair(&output->headers,"Location:", new_location);

		if ( output->body ) {
		    attach_data(redirected, sizeof(redirected), output->body);
		}

		process_output_object(so, output, rq);
		free_output_obj(output);
                IF_FREE(new_location);
		if ( flags ) *flags |= MOD_AFLAG_OUT;
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
	if ( map->src_cs_name ) {
	    strncpy(rq->src_charset, map->src_cs_name, sizeof(rq->src_charset)-1 );
	    rq->src_charset[sizeof(rq->src_charset)-1] = 0;
	}
case MAP_ACL:
case MAP_REGEX:
	/* if this is map_regex - build rewritten url*/
	if ( map->to_hosts && map->to_hosts->name)
	    destination = build_destination(src,pmatch, map->to_hosts->name);
	if ( destination ) {
	    struct url	url;

	    bzero(&url, sizeof(url));
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "accel/redir(): new dest: %s\n", destination);
	    /* we must split new destination */
	    if ( !parse_raw_url(destination, &url) ) {
		/* it is ok 				  */
		/* 1. if there was no port in destination */
		if ( !url.port ) url.port = 80;
		url.httpv = rq->url.httpv;
		rq->url.httpv = NULL;
		if ( TEST(map->flags, MAP_REVERSE) && ohost ) {
		    IF_FREE(url.host);
		    url.host = strdup(ohost);
		}
		free_url(&rq->url);
		memcpy(&rq->url, &url, sizeof(url));
	    }
	    free(destination);
	}
	break;

default:
	my_xlog(OOPS_LOG_SEVERE, "accel/redir(): Unknown MAP type %d\n", map->type);
	goto done;
    }

    if ( !rq->original_host ) /* there was no host: ? */
	rq->original_host = strdup(rq->url.host);

    /* rewrite 'Host:' (if configured)				*/
    if ( rewrite_host && (host_av = lookup_av_by_attr(rq->av_pairs, "host:") ) ) {
	if (host_av->val) free(host_av->val);
	if ( rq->url.port == 80 )
	    host_av->val = strdup(rq->url.host);
	else {
	    char *new_host_v = xmalloc(strlen(rq->url.host) + 20, "");
	    if ( new_host_v ) {
		sprintf(new_host_v, "%s:%d", rq->url.host, rq->url.port);
		host_av->val = new_host_v;
	    } else
		host_av->val = strdup(rq->url.host);
	}
    }
    if ( !TEST(rq->flags, RQ_HAS_HOST) && rq->url.host) {
	/* insert Host: header */
	if ( rq->url.port == 80 )
	    put_av_pair(&rq->av_pairs, "Host:", rq->url.host);
	else {
	    char *new_host_v = xmalloc(strlen(rq->url.host) + 20, "");
	    if ( new_host_v ) {
		sprintf(new_host_v, "%s:%d", rq->url.host, rq->url.port);
		put_av_pair(&rq->av_pairs, "Host:", new_host_v);
		xfree(new_host_v);
	    } else
		put_av_pair(&rq->av_pairs, "Host:", rq->url.host);
	}
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

int
redir_control_request(int so, struct group *group, struct request *rq, int *flags, int instance)
{
char                    *host;
struct  map             *m = 0;
regmatch_t              pmatch[MAXMATCH];

    if ( (rq->meth != METH_PURGE_SITE) && (rq->meth != METH_PURGE_SITE_R) )
        return(MOD_CODE_OK);
    if ( !rq->url.host ) {
        say_bad_request(so, "Access denied", "Site not allowed for PURGE_SITE", ERR_ACC_DENIED, rq);
        if ( flags ) SET(*flags, MOD_AFLAG_BRK|MOD_AFLAG_OUT);
        return(MOD_CODE_ERR);
    }
    /* lookup proper map */
    if ( rq->meth == METH_PURGE_SITE ) {
        m = lookup_map(0, NULL, rq->url.host, rq->url.port);
        if ( !m ) {
            say_bad_request(so, "Access denied", "Site not allowed for PURGE_SITE", ERR_ACC_DENIED, rq);
            if ( flags ) SET(*flags, MOD_AFLAG_BRK|MOD_AFLAG_OUT);
            return(MOD_CODE_ERR);
        }
        if ( !TEST(m->flags, MAP_CANPURGE) ) {
            say_bad_request(so, "Access denied", "Site not allowed for PURGE_SITE", ERR_ACC_DENIED, rq);
            if ( flags ) SET(*flags, MOD_AFLAG_BRK|MOD_AFLAG_OUT);
            return(MOD_CODE_ERR);
        }
        m->site_purged = global_sec_timer;
        if ( flags ) SET(*flags, MOD_AFLAG_OUT);
        write(so, "HTTP/1.0 200 PURGED OK\n\n", 24);
        return(MOD_CODE_OK);
    }
    if ( rq->meth == METH_PURGE_SITE_R ) {
        /* we must set new date on EVERY map which have given destination */
        int res = set_purge_date_r(0, NULL, rq->url.host, rq->url.port, global_sec_timer);
        if ( flags ) SET(*flags, MOD_AFLAG_OUT);
        if ( res == 0 ) {
            write(so, "HTTP/1.0 200 PURGED NOT OK\n\n", 28);
        } else {
            write(so, "HTTP/1.0 200 PURGED OK\n\n", 24);
        }
        return(MOD_CODE_OK);
    }
    return(MOD_CODE_OK);
}

static int
on_my_port(struct request *rq)
{
u_short	port;

    if ( rq ) {
	port = ntohs(rq->my_sa.sin_port);
    } else
	return(FALSE);
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
	    return(FALSE);  /* not my */
	}
	return(TRUE);
    }
    return(FALSE);
}

static struct map *
find_map(struct request *rq, size_t nmatch, regmatch_t pmatch[], char *src)
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

    my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "find_map(): it's my.\n");
    /* first - take destination from 'Host:'		*/
    if ( rq->original_host ) {
        host = rq->original_host;
    } else
        host = attr_value(rq->av_pairs, "host");
    if ( host ) {
        char	host_buf[MAXHOSTNAMELEN], *o;

        strncpy(host_buf, host, sizeof(host_buf) - 1);
        host_buf[sizeof(host_buf) - 1] = 0;
        if ( (o = strchr(host_buf, ':')) ) {
            *o = 0;
            port = (u_short)atoi(o+1);
        } else
            port = 80;
        /* now host_buf contain host part	*/
        if ( (use_host_hash) > 0 && map_hash_table ) {
            char	*t;
            unsigned 	b,o;
            struct map	*this;

            /* lowercase host			*/
            t = host_buf; while ( *t ) { *t = tolower(*t); t++; }
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
        		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Found in hash.\n");
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
        	case MAP_EXTERNAL:
                case MAP_STRING_CS:
                case MAP_STRING:
        	    if ( !strcasecmp(host_buf, map->from_host) && (port == map->from_port) ) {
        	        my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Host %s found in string map.\n", host);
        	        return(map);
        	    }
        	    break;

        	case MAP_REGEX_CS:
        	case MAP_REGEX:
        	    if ( src && !regexec(&this->preg, src, nmatch, pmatch, 0) ) {
        		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Host %s found in regex map.\n", host);
        		goto hash_found;
        	    }
        	    break;
        	case MAP_ACL:
        	    if ( rq_match_named_acl_by_index(rq, this->acl_index)
        		&& !regexec(&this->preg, src, nmatch, pmatch, 0) ) {
        		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Host %s found in acl map.\n", host);
        		goto hash_found;
        	    }
        	    break;
        	}
        	this = this->next_in_hash;
            }
        hash_found:
            if ( this ) return(this);
            goto try_addresses;
        }
        while(map) {
            switch( map->type ) {
        case MAP_EXTERNAL:
        case MAP_STRING_CS:
        case MAP_STRING:
        	if ( !strcasecmp(host_buf, map->from_host) && (port == map->from_port) ) {
        	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Host %s found in string map.\n", host);
        	    return(map);
        	}
        	break;
        case MAP_REGEX_CS:
        case MAP_REGEX:
        	if ( src && !regexec(&map->preg, src, nmatch, pmatch, 0) ) {
        	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Host %s found in regex map.\n", host);
        	    return(map);
        	}
        	break;
        case MAP_ACL:
        	if ( rq_match_named_acl_by_index(rq, map->acl_index)
        	    && !regexec(&map->preg, src, nmatch, pmatch, 0) ) {
        	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Host %s found in acl map.\n", host);
        	    return(map);
        	}
        	break;
        default:
        	my_xlog(OOPS_LOG_SEVERE, "find_map(): Here is unknown map type %d\n", map->type);
        	break;
            }
            map = map->next;
        }
    }
 try_addresses:
    if ( ip_lookup == FALSE )
        goto try_default;
    /* If we didn't find hostname from host - try addresses   */
    map = maps;
    while ( map ) {
        if ( map->from_host ) {
            str_to_sa(map->from_host, (struct sockaddr*)&map_sa);
            if ( (map_sa.sin_addr.s_addr == rq->my_sa.sin_addr.s_addr) &&
        	(!map->from_port || (map->from_port == ntohs(rq->my_sa.sin_port)) ) ) {
        	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "find_map(): Map found by addr: %s\n", map->from_host);
        	break;
            }
        }
        map = map->next;
    }
 try_default:
    if ( !map ) {
        if ( !default_map ) goto done;
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "find_map(): Default used.\n");
        map = default_map;
    }
    res = map;
 done:
    return(res);
}

static int
set_purge_date_r(size_t nmatch, regmatch_t pmatch[], char *src, u_short port, time_t date)
{
char    *host;
char    host_buf[MAXHOSTNAMELEN], *o;
int     res = 0;

    strncpy(host_buf, src, sizeof(host_buf) - 1);

    host_buf[sizeof(host_buf) - 1] = 0;

    /* now host_buf contain host part	*/
    if ( (use_host_hash) > 0 && reverse_hash_table ) {
        char            *t;
        unsigned        b,o;
        struct map      *this;

        /* lowercase host                       */
        t = host_buf;
        while ( *t ) {
            *t = tolower(*t); t++;
        }
        b = hash_function(host_buf);
        o = ortho_hash_function(host_buf);
        if ( reverse_hash_table[b].next ) {
            /* check this line of hash table */
            this = reverse_hash_table[b].next;
            while ( this ) {
                if ( this->reverse_ortho != o ) {
                    this = this->next_in_hash;
                    continue;
                }
                if ( !strcmp(host_buf, this->to_hosts->name)
                     && (port == this->to_hosts->port)
                     && TEST(this->flags, MAP_CANPURGE_R) ) {
                    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "lookup_map(): Found in reverse hash.\n");
                    this->site_purged = date;
                    res++;
                }
                this = this->next_in_reverse_hash;
            }
        }
        return(res);
    }
    return(0);
}

static struct map *
lookup_map(size_t nmatch, regmatch_t pmatch[], char *src, u_short port)
{
struct  map             *res = NULL, *map = maps;
char                    *host;
char    host_buf[MAXHOSTNAMELEN], *o;

    strncpy(host_buf, src, sizeof(host_buf) - 1);

    host_buf[sizeof(host_buf) - 1] = 0;

    /* now host_buf contain host part	*/
    if ( (use_host_hash) > 0 && map_hash_table ) {
        char            *t;
        unsigned        b,o;
        struct map      *this;

        /* lowercase host                       */
        t = host_buf;
        while ( *t ) {
            *t = tolower(*t); t++;
        }
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
                        my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "lookup_map(): Found in hash.\n");
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
            case MAP_EXTERNAL:
            case MAP_STRING_CS:
            case MAP_STRING:
                if ( !strcasecmp(host_buf, map->from_host) && (port == map->from_port) ) {
                    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "lookup_map(): Host %s found in string map.\n", host_buf);
                    return(map);
                }
                break;

            case MAP_REGEX_CS:
            case MAP_REGEX:
                if ( src && !regexec(&this->preg, src, nmatch, pmatch, 0) ) {
                    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "lookup_map(): Host %s found in regex map.\n", host_buf);
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
    case MAP_EXTERNAL:
    case MAP_STRING_CS:
    case MAP_STRING:
    	if ( !strcasecmp(host_buf, map->from_host) && (port == map->from_port) ) {
    	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Host %s found in string map.\n", host_buf);
    	    return(map);
    	}
    	break;
    case MAP_REGEX_CS:
    case MAP_REGEX:
    	if ( src && !regexec(&map->preg, src, nmatch, pmatch, 0) ) {
    	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "find_map(): Host %s found in regex map.\n", host_buf);
    	    return(map);
    	}
    	break;
    default:
    	my_xlog(OOPS_LOG_SEVERE, "find_map(): Here is unknown map type %d\n", map->type);
    	break;
        }
        map = map->next;
    }
    res = map;
 done:
    return(res);
 }

static void
parse_map_file(char *p)
{

    p += 4;
    while ( *p && IS_SPACE(*p) ) p++;
    strncpy(map_file, p, sizeof(map_file) - 1);
    map_file[sizeof(map_file) - 1] = 0;
    verb_printf("parse_map_file(): Use %s as mapfile.\n", map_file);
}

static  void
set_canpurge(char *p)
{
/* "canpurge line"
   look up map to which line can be matched, then set
   flag in this map that it can contain time for site_purge
*/
struct  map *m;
char        *pptr;
u_short     port = 80;

    p+=8;
    while (*p && IS_SPACE(*p) ) p++;
    if ( *p == 0 ) return;
    if ( pptr = strchr(p, ':') ) {
        *pptr = 0;
        port = atoi(pptr+1);
    }
    m = lookup_map(0, NULL, p, port);
    if ( m ) {
        m->flags |= MAP_CANPURGE;
    }
}

static  void
set_canpurge_r(char *p)
{
/* "canpurge line"
   look up map to which line can be matched, then set
   flag in this map that it can contain time for site_purge
*/
struct  map *m;
char        *pptr;
u_short     port = 80;
char        host_buf[MAXHOSTNAMELEN];

    p+=10;
    while (*p && IS_SPACE(*p) ) p++;
    if ( *p == 0 ) return;
    if ( pptr = strchr(p, ':') ) {
        *pptr = 0;
        port = atoi(pptr+1);
    }

    strncpy(host_buf, p, sizeof(host_buf) - 1);

    host_buf[sizeof(host_buf) - 1] = 0;

    /* now host_buf contain host part	*/
    if ( (use_host_hash) > 0 && reverse_hash_table ) {
        char            *t;
        unsigned        b,o;
        struct map      *this;

        /* lowercase host                       */
        t = host_buf;
        while ( *t ) {
            *t = tolower(*t); t++;
        }
        b = hash_function(host_buf);
        o = ortho_hash_function(host_buf);
        if ( reverse_hash_table[b].next ) {
            /* check this line of hash table */
            this = reverse_hash_table[b].next;
            while ( this ) {
                if ( this->reverse_ortho != o ) {
                    this = this->next_in_hash;
                    continue;
                }
                if ( !strcmp(host_buf, this->to_hosts->name)
                     && (port == this->to_hosts->port) ) {
                    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "lookup_map(): Found in reverse hash.\n");
                    this->flags |= MAP_CANPURGE_R;
                }
                this = this->next_in_reverse_hash;
            }
        }
    }
}

static  void
parse_map(char *p)
{
char		*s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;
char		*config_line = NULL;
int		flags = 0;

    /* map from[:port] to1[:port1] to2[:port2] ... */
    p += 3;
    if ( *p == '/' ) {
        p++;
        /* switch */
        if ( tolower(*p) == 'r' )
            flags |= MAP_REVERSE;
        while (*p && !IS_SPACE(*p) ) p++;
    }
    while (*p && IS_SPACE(*p) ) p++;
    config_line = strdup(p);
    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;
    if ( strlen(buf) ) {
        u_short port = 80;

        if ( (o = strchr(buf, ':')) ) {
	    port = (u_short)atoi(o+1);
	    *o = 0;
	}
	verb_printf("parse_map(): host = %s, port = %d\n", buf, port);
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
	map->type = MAP_STRING;
	map->from_host = strdup(buf);
	map->from_port = port;
	map->config_line = config_line; config_line = NULL;
	map->flags = flags;
do_next_host:
	while (*p && IS_SPACE(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		last_map->next = map;
	    }
            last_map = map;
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	while ( *s && !IS_SPACE(*s) ) s++;
	p = s;
	if ( strlen(buf) ) {
	    u_short 	port = 80;
	    struct	to_host	*to_host, *next;
	    char	*path = NULL;

	    if ( (o = strchr(buf, '/')) ) {
		path = strdup(o);
		*o = 0;
 	    }
	    if ( (o = strchr(buf, ':')) ) {
		port = (u_short)atoi(o+1);
		*o = 0;
	    }
	    verb_printf("parse_map(): Mapped to %s, port = %d path = %s\n", buf, port, path?path:"NULL");
	    to_host = new_to_host();
	    if ( !to_host ) {
		IF_FREE(path);
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
    if ( config_line ) free(config_line);
}

static void
parse_map_external(char *p)
{
char		*s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;
char		*config_line = NULL;
int		flags = 0;

    /* map_external from[:port] to1[:port1] to2[:port2] ... */
    p += 12;
    if ( *p == '/' ) {
	p++;
	/* switch */
	if ( tolower(*p) == 'r' )
	    flags |= MAP_REVERSE;
	while (*p && !IS_SPACE(*p) ) p++;
    }
    while (*p && IS_SPACE(*p) ) p++;
    config_line = strdup(p);
    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;
    if ( strlen(buf) ) {
        u_short port = 80;

        if ( (o = strchr(buf, ':')) ) {
	    port = (u_short)atoi(o+1);
	    *o = 0;
	}
	verb_printf("parse_map(): host = %s, port = %d\n", buf, port);
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
	map->type = MAP_EXTERNAL;
	map->from_host = strdup(buf);
	map->from_port = port;
	map->config_line = config_line; config_line = NULL;
	map->flags = flags;
do_next_host:
	while (*p && IS_SPACE(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		last_map->next = map;
	    }
            last_map = map;
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	while ( *s && !IS_SPACE(*s) ) s++;
	p = s;
	if ( strlen(buf) ) {
	    u_short 	port = 80;
	    struct	to_host	*to_host, *next;
	    char	*path = NULL;

	    if ( (o = strchr(buf, '/')) ) {
		path = strdup(o);
		*o = 0;
 	    }
	    if ( (o = strchr(buf, ':')) ) {
		port = (u_short)atoi(o+1);
		*o = 0;
	    }
	    verb_printf("parse_map(): Mapped to %s, port = %d path = %s\n", buf, port, path?path:"NULL");
	    to_host = new_to_host();
	    if ( !to_host ) {
		IF_FREE(path);
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
    if ( config_line ) free(config_line);
}

static void
parse_map_acl(char *p)
{
char		*s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;
int		first = TRUE;
int		acl_index;
char		*config_line = NULL;


    /* map_acl	ACLNAME SRC DST backup ... */

    p += 7; while (*p && IS_SPACE(*p) ) p++;
    config_line = strdup(p);

    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;

    /* get acl name */
    acl_index = acl_index_by_name(buf);
    if ( !acl_index ) {
	verb_printf("parse_map_acl(): Can't find ACL %s\n", buf);
	goto done;
    }
    while (*p && IS_SPACE(*p) ) p++;
    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    if ( !strlen(buf) ) {
	verb_printf("parse_map_acl(): Wrong map_acl line\n");
	goto done;
    }
    map = new_map();
    if ( !map ) goto done;
    bzero(map, sizeof(*map));
    map->type = MAP_ACL;
    map->acl_index = acl_index;
    map->config_line = config_line; config_line = NULL;
    while (*p && IS_SPACE(*p) ) p++;
    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    if ( !strlen(buf) ) {
	verb_printf("parse_map_acl(): Wrong map_acl line\n");
	free_maps(map);
	goto done;
    }
    if (regcomp(&map->preg, buf, REG_EXTENDED|REG_ICASE)) {
	verb_printf("parse_map_acl(): Cant regcomp %s\n", buf);
	free(map);
	goto done;
    }
    p = s;
do_next_host:
    while (*p && IS_SPACE(*p) ) p++;
    if ( !*p ) {
	if ( !maps ) maps = map;
	  else {
	    last_map->next = map;
	}
        last_map = map;
	place_map_in_hash(map);
	goto done;
    }
    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
    *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;
    if ( strlen(buf) ) {
	struct	to_host	*to_host, *next;

	verb_printf("parse_map_acl(): mapped to %s\n", buf);
	to_host = new_to_host();
	if ( !to_host ) {
	    free_maps(map);
	    goto done;
	}
	bzero(to_host, sizeof(*to_host));
	if ( !first ) to_host->port = 80;
	if ( !first && ( o = strchr(buf, ':') ) ) {
	    to_host->port = (u_short)atoi(o+1);
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
    if ( config_line ) free(config_line);
}

static void
parse_map_regex(char *p)
{
char		*s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;
int		first = TRUE;
char		*config_line = NULL;
int		flags = 0;

    /* map_regex SRC DEST backup1[:port1] ... */
    p += 9;
    if ( *p == '/' ) {
	p++;
	/* switch */
	if ( tolower(*p) == 'r' )
	    flags |= MAP_REVERSE;
	while (*p && !IS_SPACE(*p) ) p++;
    }
    while (*p && IS_SPACE(*p) ) p++;
    config_line = strdup(p);
    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;
    if ( strlen(buf) ) {
        map = new_map();
        if ( !map ) goto done;
        bzero(map, sizeof(*map));
        map->config_line = config_line; config_line = NULL;
        map->type = MAP_REGEX;
        map->flags |= flags;
        if (regcomp(&map->preg, buf, REG_EXTENDED|REG_ICASE)) {
            verb_printf("parse_map_regex(): Cant regcomp %s\n", buf);
            free(map);
            goto done;
        }
do_next_host:
	while (*p && IS_SPACE(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		last_map->next = map;
	    }
            last_map = map;
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	while ( *s && !IS_SPACE(*s) ) s++;
	p = s;
	if ( strlen(buf) ) {
	    struct	to_host	*to_host, *next;

 	    verb_printf("parse_map_regex(): mapped to %s\n", buf);
	    to_host = new_to_host();
	    if ( !to_host ) {
		free_maps(map);
		goto done;
	    }
	    bzero(to_host, sizeof(*to_host));
	    if ( !first ) to_host->port = 80;
	    if ( !first && ( o = strchr(buf, ':') ) ) {
		to_host->port = (u_short)atoi(o+1);
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
    if ( config_line ) free(config_line);
}

static void
parse_map_external_regex(char *p)
{
char		*s, *d, *o;
char		buf[MAXHOSTNAMELEN+10];
struct	map	*map;
int		first = TRUE;
char		*config_line = NULL;
int		flags = 0;

    /* map_regex SRC DEST backup1[:port1] ... */
    p += 9;
    if ( *p == '/' ) {
	p++;
	/* switch */
	if ( tolower(*p) == 'r' )
	    flags |= MAP_REVERSE;
	while (*p && !IS_SPACE(*p) ) p++;
    }
    while (*p && IS_SPACE(*p) ) p++;
    config_line = strdup(p);
    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;
    if ( strlen(buf) ) {
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
        map->config_line = config_line; config_line = NULL;
	map->type = MAP_EXTERNAL_REGEX;
	map->flags |= flags;
	if (regcomp(&map->preg, buf, REG_EXTENDED|REG_ICASE)) {
	    verb_printf("parse_map_regex(): Cant regcomp %s\n", buf);
	    free(map);
	    goto done;
	}
do_next_host:
	while (*p && IS_SPACE(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		last_map->next = map;
	    }
            last_map = map;
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	while ( *s && !IS_SPACE(*s) ) s++;
	p = s;
	if ( strlen(buf) ) {
	    struct	to_host	*to_host, *next;

 	    verb_printf("parse_map_regex(): mapped to %s\n", buf);
	    to_host = new_to_host();
	    if ( !to_host ) {
		free_maps(map);
		goto done;
	    }
	    bzero(to_host, sizeof(*to_host));
	    if ( !first ) to_host->port = 80;
	    if ( !first && ( o = strchr(buf, ':') ) ) {
		to_host->port = (u_short)atoi(o+1);
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
    if ( config_line ) free(config_line);
}

static void
parse_map_charset(char *p)
{
char			*s, *d, *o, *forw, *back;
char			buf[MAXHOSTNAMELEN+10];
struct	map		*map;
struct	charset		*source_charset = NULL, *destination_charset = NULL;
struct	string_list	*to_ser, *to_cli;
int			i;
char		*config_line = NULL;


    /* map_charset src_charset dst_charset from[:port] to1[:port1] to2[:port2] ... */
    p += 11;
    while (*p && IS_SPACE(*p) ) p++; s = p; d = buf;
    config_line = strdup(p);
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) ) *d++ = *s++; *d=0;
    p = s;
    /* src charset */
    verb_printf("parse_map_charset(): src charset: %s\n", buf);
    if ( charsets )
	source_charset = lookup_charset_by_name(charsets, buf);
    if ( !source_charset ) {
	verb_printf("parse_map_charset(): Unknown charset %s\n", buf);
	goto done;
    }
    while (*p && IS_SPACE(*p) ) p++; s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) ) *d++=*s++; *d=0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;
    /* dst charset */
    verb_printf("parse_map_charset(): dst charset: %s\n", buf);
    if ( charsets )
	destination_charset = lookup_charset_by_name(charsets, buf);
    if ( !destination_charset ) {
	verb_printf("parse_map_charset(): Unknown charset %s\n", buf);
	goto done;
    }
    if ( !source_charset->Table || !destination_charset->Table ) {
	verb_printf("parse_map_charset(): Some charset doesn't have a table.\n");
	goto done;
    }
    while (*p && IS_SPACE(*p) ) p++; s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) ) *d++ = *s++;*d=0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;
    if ( strlen(buf) ) {
        u_short port = 80;

        if ( (o = strchr(buf, ':')) ) {
	    port = (u_short)atoi(o+1);
	    *o = 0;
	}
	verb_printf("parse_map_charset(): host=%s, port=%d\n", buf, port);
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
	map->type = MAP_STRING_CS;
	map->from_host = strdup(buf);
	map->from_port = port;
        map->config_line = config_line; config_line = NULL;
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
	    u_char sc;

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
	while (*p && IS_SPACE(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		last_map->next = map;
	    }
            last_map = map;
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	while ( *s && !IS_SPACE(*s) ) s++;
	p = s;
	if ( strlen(buf) ) {
	    u_short 	port = 80;
	    struct	to_host	*to_host, *next;
	    char	*path = NULL;

	    if ( (o = strchr(buf, '/')) ) {
		path = strdup(o);
		*o = 0;
 	    }
	    if ( (o = strchr(buf, ':')) ) {
		port = (u_short)atoi(o+1);
		*o = 0;
	    }
	    verb_printf("parse_map_charset(): Mapped to %s, port = %d path = %s\n", buf, port, path?path:"NULL");
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
    if ( config_line ) free(config_line);
}

static void
parse_map_regex_charset(char *p)
{
char			*s, *d, *o, *forw, *back;
char			buf[MAXHOSTNAMELEN+10];
struct	map		*map;
int			first = TRUE, i;
struct	charset		*source_charset = NULL, *destination_charset = NULL;
struct	string_list	*to_ser, *to_cli;
char		*config_line = NULL;


    /* map_regex_charset CLIENTCHARSET SERVERCHARSET SRC DEST backup1[:port1] ... */
    p += 17; while (*p && IS_SPACE(*p) ) p++;
    config_line = strdup(p);
    s = p; d = buf;
    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
        *d++ = *s++;
    *d = 0;
    while ( *s && !IS_SPACE(*s) ) s++;
    p = s;
    if ( strlen(buf) ) {
	map = new_map();
	if ( !map ) goto done;
	bzero(map, sizeof(*map));
	map->type = MAP_REGEX_CS;
        map->config_line = config_line; config_line = NULL;
	if ( charsets )
	    source_charset = lookup_charset_by_name(charsets, buf);
	if ( !source_charset ) {
	    verb_printf("parse_map_regex_charset(): Source charset: UNKNOWN %s\n", buf);
	    free_maps(map);
	    goto done;
	} else
	    verb_printf("parse_map_regex_charset(): Source charset: %s\n", buf);
	while (*s && IS_SPACE(*s) ) s++;
	d = buf;
	while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
	    *d++ = *s++;
	*d = 0;
	while ( *s && !IS_SPACE(*s) ) s++;
	destination_charset = lookup_charset_by_name(charsets, buf);
	if ( !destination_charset ) {
	    verb_printf("parse_map_regex_charset(): Destination charset: UNKNOWN %s\n", buf);
	    free_maps(map);
	    goto done;
	} else
	    verb_printf("parse_map_regex_charset(): Destination charset: %s\n", buf);
	if ( !source_charset->Table || !destination_charset->Table ) {
	    verb_printf("parse_map_regex_charset(): One of the charsets have no table.\n", buf);
	    free_maps(map);
	    goto done;
	}
	/* we have default->src and default->dst table	*/
	/* and we must build src->dst and reverse	*/
	forw = malloc(128);
	if ( !forw ) {
	    verb_printf("parse_map_regex_charset(): No mem for forw.\n");
	    free_maps(map);
	    goto done;
	}
	back = malloc(128);
	if ( !back ) {
	    verb_printf("parse_map_regex_charset(): No mem for back.\n", buf);
	    free(forw);
	    free_maps(map);
	    goto done;
	}
	for(i=0;i<128;i++) {
	    u_char *src = source_charset->Table;
	    u_char *dst = destination_charset->Table;
	    u_char sc;

	    sc = src[i];
	    forw[sc-128] = dst[i];
	    back[dst[i]-128] = sc;
	}
	map->cs_to_server_table = alloc_l_string_list();
	if ( !map->cs_to_server_table ) {
	    verb_printf("parse_map_regex_charset(): Can't alloc recode table.\n");
	    free_maps(map);
	    goto done;
	}
	lock_l_string_list(map->cs_to_server_table);
	map->cs_to_client_table = alloc_l_string_list();
	if ( !map->cs_to_client_table ) {
	    verb_printf("parse_map_regex_charset(): Can't alloc recode table.\n");
	    free_maps(map);
	    goto done;
	}
	lock_l_string_list(map->cs_to_client_table);

	to_ser = malloc(sizeof(*to_ser));
	if ( to_ser )
	    bzero(to_ser, sizeof(*to_ser));
	  else {
	    verb_printf("parse_map_regex_charset(): Can't alloc recode table.\n");
	    free(forw);
	    free(back);
	    free_maps(map);
	    goto done;
	}
	to_cli = malloc(sizeof(*to_cli));
	if ( to_ser )
	    bzero(to_cli, sizeof(*to_cli));
	  else {
	    verb_printf("parse_map_regex_charset(): Can't alloc recode table.\n");
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
	while (*s && IS_SPACE(*s) ) s++;
	d = buf;
	while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
	    *d++ = *s++;
	*d = 0;
	while ( *s && !IS_SPACE(*s) ) s++;
	p = s;
	if (regcomp(&map->preg, buf, REG_EXTENDED|REG_ICASE)) {
	    verb_printf("parse_map_regex_charset(): Cant regcomp %s\n", buf);
	    free_maps(map);
	    goto done;
	}

do_next_host:
	while (*p && IS_SPACE(*p) ) p++;
	if ( !*p ) {
	    if ( !maps ) maps = map;
	      else {
		last_map->next = map;
	    }
            last_map = map;
	    place_map_in_hash(map);
	    goto done;
	}
	s = p; d = buf;
	while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
	*d++ = *s++;
	*d = 0;
	while ( *s && !IS_SPACE(*s) ) s++;
	p = s;
	if ( strlen(buf) ) {
	    struct	to_host	*to_host, *next;

 	    verb_printf("parse_map_regex_charset(): Mapped to %s\n", buf);
	    to_host = new_to_host();
	    if ( !to_host ) {
		free_maps(map);
		goto done;
	    }
	    bzero(to_host, sizeof(*to_host));
	    if ( !first ) to_host->port = 80;
	    if ( !first && ( o = strchr(buf, ':') ) ) {
		to_host->port = (u_short)atoi(o+1);
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
    if ( config_line ) free(config_line);
}

static char*
build_destination(char *src, regmatch_t *pmatch, char *target)
{
regmatch_t	*curr = pmatch+1;
int		length = 0, subs = 0, n;
char		*result = NULL, *s, *d, esc, doll;

    if ( !src || !target || !pmatch )
	return(NULL);
    while ( (curr->rm_so > -1) && (curr->rm_so <= curr->rm_eo) ) {
	length += curr->rm_eo - curr->rm_so + 1;
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
	if ( IS_DIGIT(*s) && doll ) {
	    /* insert n-th subexpression */
	    n = *s - '0';
	    if ( ( n > 0 ) && (n<=subs) && ( n < MAXMATCH) ) {
		int	copylen;
		curr = &pmatch[n];

		if ( curr->rm_so != -1 ) {
		    copylen = curr->rm_eo - curr->rm_so;

		    if ( copylen > 0 ) {
			memcpy(d, src+curr->rm_so, copylen);
			d+=copylen;
		    }
		}
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

static char*
build_src(struct request *rq)
{
char			*url = NULL, *host, *path;
int			urllen;
u_short			port=80;

    if ( !rq || !rq->av_pairs) return(NULL);
    if ( rq->original_host ) {
	host = rq->original_host;
    } else {
        /* If we have absolute URI, then it have precedence     */
        /* 12.04.2001                                           */
        if ( rq->url.host )
                host = rq->url.host;
            else
                host = attr_value(rq->av_pairs, "host");
    }
    if ( !host ) return(NULL);
    if ( rq->original_path ) {
	path = rq->original_path;
    } else
	path = rq->url.path;
    if ( !path ) return(NULL);

    /* now build url for regex matching				*/
    if ( path ) {
	char	*dd;

	urllen = strlen(host)
		+strlen(path) + 20;
	url = malloc(urllen);
	if ( (dd = strchr(host, ':')) ) {
	    u_short host_port;
	    *dd = 0;
	    host_port = (u_short)atoi(dd+1);
	    if ( host_port ) port = host_port;
	} else
	    port = 80;
	if ( url ) {
	    if ( port != 80 )
		sprintf(url, "http://%s:%d%s", host,port,
				path);
	      else
		sprintf(url, "http://%s%s", host,
				path);
	}
	if ( dd ) *dd = ':';
    }
    return(url);
}

static void
insert_rewrite_location(char *p)
{
char	*t, *token, *ptr;
char	*acl = NULL, *src = NULL, *dst = NULL;
char	*src_buf = NULL, *dst_buf = NULL;
int	acl_index=0;
rewrite_location_t	*new, *next;

    if ( !p ) return;
    /* must be in form ACL SRC DST */
    t = p;
    while ( (token = (char*)strtok_r(t, "\t ", &ptr)) ) {
	t = NULL;

	if ( !acl ) {
	    acl = token;
	    acl_index = acl_index_by_name(token);
	    if ( !acl_index ) verb_printf("insert_rewrite_location(): Unknown ACL %s\n", acl);
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
		verb_printf("insert_rewrite_location(): Can't compile regex %s\n", src_buf);
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
	verb_printf("insert_rewrite_location(): wrong rewrite_location directive; %s\n", p);
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

static void
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

static void
check_map_file_age(void)
{
    if ( global_sec_timer - map_file_check_time > 60 )
	reload_map_file();
}

static void
reload_map_file(void)
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
	verb_printf("reload_map_file(): Can't stat %s: %m\n", map_file);
	my_xlog(OOPS_LOG_SEVERE, "reload_map_file(): Can't stat %s: %m\n", map_file);
	return;
    }
    if ( sb.st_mtime <= map_file_mtime )
	return;
    WRLOCK_ACCEL_CONFIG ;
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "reload_map_file(): reload mapfile.\n");
    mf = fopen(map_file, "r");
    if ( !mf ) {
	verb_printf("reload_map_file(): Can't fopen %s: %m", map_file);
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "reload_map_file(): Can't fopen %s: %m\n", map_file);
	goto done;
    }
    map_file_mtime = sb.st_mtime;
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
        reverse_hash_table = calloc(use_host_hash, sizeof(*map_hash_table));
    }
    other_maps_chain = NULL;

    while ( fgets(buf, sizeof(buf) - 1, mf) ) {
      char *p;
	buf[sizeof(buf)-1] = 0;
	if ( (p = strchr(buf,'\n')) ) *p = 0;
	verb_printf("reload_map_file(): got line: %s\n", buf);
	p = buf; while ( *p && IS_SPACE(*p) ) p++;
	if ( *p == '#' ) continue;
	if ( !strncasecmp(p, "dead_timeout", 12) ) {
	    p += 12;
	    while (*p && IS_SPACE(*p) ) p++;
	    dead_timeout = atoi(p);
	} else
	if ( !strncasecmp(p, "sleep_timeout", 13) ) {
	    p += 13;
	    while (*p && IS_SPACE(*p) ) p++;
	    sleep_timeout = atoi(p);
	} else
	if ( !strncasecmp(p, "refresh_pattern", 15) ) {
	    p += 15;
	    verb_printf("reload_map_file(): %s will use refresh pattern.\n", MODULE_NAME);
	    parse_refresh_pattern(&refr_patts, p);
	} else
	if ( !strncasecmp(p, "rewrite_location", 16) ) {
	    verb_printf("reload_map_file(): %s will rewrite 'Location:' host.\n", MODULE_NAME);
	    p += 16;
	    insert_rewrite_location(p);
	} else
	if ( !strncasecmp(p, "use_host_hash", 13) ) {
	    p += 13;
	    while (*p && IS_SPACE(*p) ) p++;
	    use_host_hash = atoi(p);
	    if ( use_host_hash ) {
		if ( map_hash_table )
		    free(map_hash_table);
		map_hash_table = calloc(use_host_hash, sizeof(*map_hash_table));
		if ( reverse_hash_table )
		    free(reverse_hash_table);
		reverse_hash_table = calloc(use_host_hash, sizeof(*map_hash_table));
	    }
	} else
        if ( !strncasecmp(p, "ip_lookup", 9) ) {
            p += 9;
            while (*p && IS_SPACE(*p) ) p++;
            ip_lookup = strncasecmp(p, "no", 2);
        } else
	if ( !strncasecmp(p, "rewrite_host", 12) ) {
	    p += 12; while (*p && IS_SPACE(*p) ) p++;
	    if ( !strcasecmp(p, "yes") ) {
		rewrite_host = TRUE;
		verb_printf("reload_map_file(): %s will rewrite 'Host:' header.\n", MODULE_NAME);
	    } else {
		rewrite_host = FALSE;
		verb_printf("reload_map_file(): %s won't rewrite 'Host:' header.\n", MODULE_NAME);
	    }
	} else
	if ( !strncasecmp(p, "default", 7) ) {
	    /* allocate default map */
	    p += 7; while (*p && IS_SPACE(*p) ) p++;
	    s = p; d = buf;
	    while ( *s && !IS_SPACE(*s) && ( d - buf < sizeof(buf) ) )
		*d++ = *s++;
	    *d = 0;
	    p = s;
	    if ( strlen(buf) ) {
		u_short 	port = 80;
		struct	to_host	*to_host;

		if ( (o = strchr(buf, ':')) ) {
		    port = (u_short)atoi(o+1);
		    *o = 0;
		}
		verb_printf("reload_map_file(): default host = %s, port = %d\n", buf, port);
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
	if ( !strncasecmp(p, "map_external", 12) )
	    parse_map_external(p);
	else
	if ( !strncasecmp(p, "map_external_regex", 18) )
	    parse_map_external_regex(p);
	else
        if ( !strncasecmp(p, "canpurge/r", 10) )
            set_canpurge_r(p);
        else
        if ( !strncasecmp(p, "canpurge", 8) )
            set_canpurge(p);
        else
        if ( !strncasecmp(p, "map", 3) )
            parse_map(p);
    }
    if ( mf ) fclose(mf);
done:
    UNLOCK_ACCEL_CONFIG ;
}
