/*
  fastredir module for oops by john gladkih, 23/04/2000
  based on redir.c from oops 1.3.8 (same logic & config)
*/

#include	"../oops.h"
#include	"../modules.h"

#define	MODULE_NAME	"fastredir"
#define	MODULE_INFO	"Fast Substring URL Redirector"

#if	defined(MODULES)
char		module_type   = MODULE_REDIR ;
char		module_name[] = MODULE_NAME ;
char		module_info[] = MODULE_INFO ;
int		mod_load();
int		mod_unload();
int		mod_config_beg(int), mod_config_end(int), mod_config(char*, int), mod_run();
int		redir(int so, struct group *group, struct request *rq, int *flags, int);
#define		MODULE_STATIC
#else
static	char	module_type   = MODULE_REDIR ;
static	char	module_name[] = MODULE_NAME ;
static	char	module_info[] = MODULE_INFO ;
static	int	mod_load();
static	int	mod_unload();
static	int	mod_config_beg(int), mod_config_end(int), mod_config(char*, int), mod_run();
static	int	redir(int so, struct group *group, struct request *rq, int *flags, int);
#define		MODULE_STATIC	static
#endif

struct	redir_module	fastredir = {
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
        NULL,
        NULL
};

#define RULE_DENY       0
#define RULE_ALLOW      1

struct	redir_rule {
	char			*redirect;	/* if not null send HTTP redirect */
	char			*substring;	/* original, not compiled	  */
	internal_doc_t		*internal;
	struct	redir_rule	*next;
        char                    flags;
};

static unsigned char nospam1x1gif[] = {
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x03, 0x00,
    0x03, 0x00, 0x80, 0xff, 0x00, 0xc0, 0xc0, 0xc0,
    0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x00, 0x02, 0x03, 0x84,
    0x7f, 0x05, 0x00, 0x3b
};

static unsigned char nospam468x60gif[] = {
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xd4, 0x01,
    0x3c, 0x00, 0xa1, 0x00, 0x00, 0xe5, 0xe5, 0xe5,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x21, 0xf9, 0x04, 0x01, 0x0a, 0x00, 0x01,
    0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x01,
    0x3c, 0x00, 0x00, 0x02, 0xd4, 0x44, 0x8e, 0xa9,
    0xcb, 0xed, 0x0f, 0xa3, 0x9c, 0xb4, 0xda, 0x8b,
    0xb3, 0xde, 0xbc, 0xfb, 0x0f, 0x86, 0xe2, 0x48,
    0x96, 0xe6, 0x89, 0xa6, 0xea, 0xca, 0xb6, 0xee,
    0x0b, 0xc7, 0xf2, 0x4c, 0xd7, 0xf6, 0x8d, 0xe7,
    0xfa, 0xce, 0xf7, 0xfe, 0x0f, 0x0c, 0x0a, 0x87,
    0xc4, 0xa2, 0xf1, 0x88, 0x4c, 0x2a, 0x97, 0xcc,
    0xa6, 0xf3, 0x09, 0x8d, 0x4a, 0xa7, 0xd4, 0xaa,
    0xf5, 0x8a, 0xcd, 0x6a, 0xb7, 0xdc, 0xae, 0xf7,
    0x0b, 0x0e, 0x8b, 0xc7, 0xe4, 0xb2, 0xf9, 0x8c,
    0x4e, 0xab, 0xd7, 0xec, 0xb6, 0xfb, 0x0d, 0x8f,
    0xcb, 0xe7, 0xf4, 0xba, 0xfd, 0x8e, 0xcf, 0xeb,
    0xf7, 0xfc, 0xbe, 0xff, 0x0f, 0x18, 0x28, 0x38,
    0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xa8, 0xb8,
    0xc8, 0xd8, 0xe8, 0xf8, 0x08, 0x19, 0x29, 0x39,
    0x49, 0x59, 0x69, 0x79, 0x89, 0x99, 0xa9, 0xb9,
    0xc9, 0xd9, 0xe9, 0xf9, 0x09, 0x1a, 0x2a, 0x3a,
    0x4a, 0x5a, 0x6a, 0x7a, 0x8a, 0x9a, 0xaa, 0xba,
    0xca, 0xda, 0xea, 0xfa, 0x0a, 0x1b, 0x2b, 0x3b,
    0x4b, 0x5b, 0x6b, 0x7b, 0x8b, 0x9b, 0xab, 0xbb,
    0xcb, 0xdb, 0xeb, 0xfb, 0x0b, 0x1c, 0x2c, 0x3c,
    0x4c, 0x5c, 0x6c, 0x7c, 0x8c, 0x9c, 0xac, 0xbc,
    0xcc, 0xdc, 0xec, 0xfc, 0x0c, 0x1d, 0x2d, 0x3d,
    0x4d, 0x5d, 0x6d, 0x7d, 0x8d, 0x9d, 0xad, 0xbd,
    0xcd, 0xdd, 0xed, 0xfd, 0x0d, 0x1e, 0x2e, 0x3e,
    0x4e, 0x5e, 0x6e, 0x7e, 0x8e, 0x9e, 0xae, 0xbe,
    0xce, 0xde, 0xee, 0xfe, 0x0e, 0x1f, 0x6f, 0x57,
    0x00, 0x00, 0x3b                                                            
};

static unsigned char nospam_close[]="<html></html><SCRIPT LANGUAGE=\"JavaScript\"><!--window.close()//--></SCRIPT>";
static unsigned char nospam_empty[]="<br>";
static unsigned char nospam_js[]="<script></script>";

static internal_doc_t	redir_internals[] = {
    {"nospam1x1",    "image/gif", sizeof(nospam1x1gif), 3600, nospam1x1gif},
    {"nospam468x60", "image/gif", sizeof(nospam468x60gif), 3600, nospam468x60gif},
    {"nospam_close", "text/html", sizeof(nospam_close)-1, 3600, nospam_close},
    {"nospam_empty", "text/html", sizeof(nospam_empty)-1, 3600, nospam_empty},
    {"nospam_js",    "application/x-javascript", sizeof(nospam_js)-1, 3600, nospam_js},
    {""}
};

static	pthread_rwlock_t	redir_lock;
#define	RDLOCK_REDIR_CONFIG	pthread_rwlock_rdlock(&redir_lock)
#define	WRLOCK_REDIR_CONFIG	pthread_rwlock_wrlock(&redir_lock)
#define	UNLOCK_REDIR_CONFIG	pthread_rwlock_unlock(&redir_lock)

typedef	enum	{RewriteIt, BounceIt} rw_mode_t;

#define	NMYPORTS	4
#define NREDIRCONFIGS   16

typedef struct  redir_config_   {
        myport_t	myports[NMYPORTS];	/* my ports		*/
        char		*myports_string;
        int		nmyports;		/* actual number	*/
        char		redir_rules_file[MAXPATHLEN];
        char		redir_template[MAXPATHLEN];
        char		*template;
        int		template_size;
        time_t		template_mtime, template_check_time;
        time_t		rules_mtime, rules_check_time;
        rw_mode_t       rewrite_mode;
        struct redir_rule *redir_rules;			/* list of rules */
} redir_config_t;

redir_config_t          redir_configs[NREDIRCONFIGS];



static	void		  free_rules(struct redir_rule*);
static	void		  reload_redir_rules(int), check_rules_age(int);
static	void		  reload_redir_template(int), check_template_age(int);
#if	!defined(HAVE_STRCASESTR)
static	char *		  strcasestr( char *, char * );
#endif

static	char		  *default_template = "\
		<body bgcolor=white>Requested URL forbidden<p>\n\
		<hr>\n\
		Generated by fastredir module for oops.</body>";
static	int	default_template_size;

MODULE_STATIC
int
mod_load()
{
int     i;

    printf("fast redirector started\n");
    pthread_rwlock_init(&redir_lock, NULL);
    for(i=0;i<NREDIRCONFIGS;i++) {
        redir_configs[i].redir_rules_file[0] = 0;
        redir_configs[i].redir_template[0] = 0;
        redir_configs[i].template = NULL;
        redir_configs[i].template_size = 0;
        redir_configs[i].template_mtime = 
        redir_configs[i].template_check_time =
        redir_configs[i].rules_mtime = 
        redir_configs[i].rules_check_time = 0;
        redir_configs[i].redir_rules = NULL;
        redir_configs[i].nmyports = 0;
        redir_configs[i].rewrite_mode = RewriteIt;
        redir_configs[i].myports_string = NULL;
    }
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload()
{
    verb_printf("fast redirector stopped\n");
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_beg(int instance)
{
int     i = instance;

    WRLOCK_REDIR_CONFIG ;
    if ( (i < 0) || (i >= NREDIRCONFIGS) ) i=0;
    redir_configs[i].redir_rules_file[0] = 0;
    redir_configs[i].redir_template[0] = 0;
    if ( redir_configs[i].template ) free(redir_configs[i].template);
    redir_configs[i].template = NULL;
    redir_configs[i].template_size = 0;
    redir_configs[i].template_mtime = redir_configs[i].template_check_time =
    redir_configs[i].rules_mtime = redir_configs[i].rules_check_time = 0;
    if ( redir_configs[i].redir_rules ) {
	free_rules(redir_configs[i].redir_rules);
	redir_configs[i].redir_rules = NULL;
    }
    redir_configs[i].nmyports = 0;
    if ( redir_configs[i].myports_string ) free(redir_configs[i].myports_string);
    redir_configs[i].myports_string = NULL;
    redir_configs[i].rewrite_mode = RewriteIt;
    UNLOCK_REDIR_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_end(int instance)
{
int     i;
    for(i=0;i<NREDIRCONFIGS;i++) {
        /* reloads will lock themself */
        if ( redir_configs[i].redir_rules_file[0] )
	    reload_redir_rules(i);
        if ( redir_configs[i].redir_template[0] )
	    reload_redir_template(i);
        }
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_run()
{
int i;
    WRLOCK_REDIR_CONFIG;
    for(i=0;i<NREDIRCONFIGS;i++)
    if ( redir_configs[i].myports_string ) {
	redir_configs[i].nmyports = 
	        parse_myports(redir_configs[i].myports_string, 
	        &redir_configs[i].myports[0], NMYPORTS);
	verb_printf("%s will use %d ports\n", module_name, redir_configs[i].nmyports);
    }
    UNLOCK_REDIR_CONFIG;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config(char *config, int instance)
{
char	*p = config;
int     i = instance;

    if ( (i<0) || (i>=NREDIRCONFIGS) ) i = 0;

    WRLOCK_REDIR_CONFIG ;
    while( *p && IS_SPACE(*p) ) p++;
    if ( !strncasecmp(p, "file", 4) ) {
	p += 4;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(redir_configs[i].redir_rules_file, p, sizeof(redir_configs[i].redir_rules_file) -1 );
    } else
    if ( !strncasecmp(p, "template", 8) ) {
	p += 8;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(redir_configs[i].redir_template, p, sizeof(redir_configs[i].redir_template) -1 );
    } else
    if ( !strncasecmp(p, "myport", 6) ) {
	p += 6;
	while (*p && IS_SPACE(*p) ) p++;
	redir_configs[i].myports_string = strdup(p);
    }
    if ( !strncasecmp(p, "mode", 4) ) {
	p += 4;
	while (*p && IS_SPACE(*p) ) p++;
	if ( !strcasecmp(p, "bounce") )
	    redir_configs[i].rewrite_mode = BounceIt;
    }
    UNLOCK_REDIR_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
redir(int so, struct group *group, struct request *rq, int *flags, int instance)
{
char	*url = NULL, *decoded_url = NULL;
int	url_len, rc;
struct	redir_rule	*rr;
struct	output_object	*oobj = NULL;
struct	buff		*body = NULL;
int                     i = instance;

    if ( (i<0) || (i>=NREDIRCONFIGS) ) i=0;
    my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "fastredir(): redir called.\n");
    if ( !rq ) return(MOD_CODE_OK);
    if ( redir_configs[i].nmyports > 0 ) {
	int		n = redir_configs[i].nmyports;
	myport_t 	*mp = redir_configs[i].myports;
	u_short		port = ntohs(rq->my_sa.sin_port);

	/* if this is not on my port */
	while( n ) {
	    if (    mp->port == port
	         && (  (mp->in_addr.s_addr == INADDR_ANY)
	             ||(mp->in_addr.s_addr == rq->my_sa.sin_addr.s_addr) ) )
	         break;
	    n--;mp++;
	}
	if ( !n ) return(MOD_CODE_OK);	/* not my */
    }
    /* 1. build URL: proto://host/path
          note: port is not included!!!
     */
    if ( !rq->url.proto || !rq->url.host || !rq->url.path )
	return(MOD_CODE_OK);
    if ( !rq->original_host && rq->url.host )
	rq->original_host = strdup(rq->url.host);
    if ( !rq->original_path && rq->url.path )
	rq->original_path = strdup(rq->url.path);
    url_len = strlen(rq->url.proto) + strlen(rq->url.host) + strlen(rq->url.path);
    url_len += 3 /* :// */ + 1 /* \0 */;
    url = malloc(url_len);
    if ( !url )
	return(MOD_CODE_OK);
    sprintf(url,"%s://%s%s", rq->url.proto, rq->url.host, rq->url.path);
    decoded_url = dehtmlize(url);
    check_rules_age(i);
    check_template_age(i);
    RDLOCK_REDIR_CONFIG ;
    rr = redir_configs[i].redir_rules;
    while ( rr ) {
	if ( strcasestr(decoded_url?decoded_url:url, rr->substring) != NULL ) {
	    if ( rr->substring ) my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "%s matched %s\n", url, rr->substring);
	    /* matched */

            if ( TEST(rr->flags, RULE_ALLOW) ) {
                goto done;
            }
            
	    if ( rr->redirect ) {
		/* we must redirect to that URL in rr->redirect */
		if ( ((redir_configs[i].rewrite_mode == BounceIt) || rr->internal )
		      && (oobj = malloc(sizeof(*oobj)))) {
		    bzero(oobj, sizeof(*oobj));
		    if (  rr->internal ) {
			char		buf[80];
			internal_doc_t	*internal = rr->internal;

			put_av_pair(&oobj->headers, "HTTP/1.0", "200 Internal document");
			put_av_pair(&oobj->headers, "Content-Type:", internal->content_type);
			sprintf(buf, "%d", internal->content_len);
			put_av_pair(&oobj->headers, "Content-Length:", buf);
			if ( internal->expire_shift != -1 ) {
			    mk1123time(global_sec_timer + internal->expire_shift, buf, sizeof(buf));
			    put_av_pair(&oobj->headers, "Expires:", buf);
			} else
			    put_av_pair(&oobj->headers, "Expires:", "Thu, 01 Jan 1970 00:00:01 GMT");
			if ( internal->body ) {
			    oobj->body = alloc_buff(internal->content_len);
			    if ( oobj->body )
				attach_data((char*)internal->body, internal->content_len, oobj->body);
			}
		    } else {
			put_av_pair(&oobj->headers, "HTTP/1.0", "302 Moved temporary");
			put_av_pair(&oobj->headers,"Expires:", "Thu, 01 Jan 1970 00:00:01 GMT");
			put_av_pair(&oobj->headers,"Location:", rr->redirect);
			put_av_pair(&oobj->headers,"Content-Type:", "text/html");
		    }
		    process_output_object(so, oobj, rq);
		    if ( flags ) *flags |= MOD_AFLAG_OUT|MOD_AFLAG_BRK;
		    goto done;
		} else {
		    char	*new_dest = NULL;
		    struct url	new_url;
		    int		rc;
		    /* we hawe to rewrite url or malloc oobj failed */
		    new_dest = rr->redirect ;
		    if ( !new_dest ) goto done;
		    bzero(&new_url, sizeof(new_url));
		    rc = parse_raw_url(new_dest, &new_url);
		    if ( !rc ) {
			struct av	*host_av;

			new_url.httpv = rq->url.httpv;
			rq->url.httpv = NULL;
			free_url(&rq->url);
			if ( !new_url.port ) new_url.port = 80;
			memcpy(&rq->url, &new_url, sizeof(new_url));
			/* We also have to rewrite Host: header in request */
			if ( rq->av_pairs && (host_av = lookup_av_by_attr(rq->av_pairs, "host:"))) {
			    IF_FREE(host_av->val);
			    host_av->val = strdup(rq->url.host);
			}
		    }
		    goto done;
		}
	    }
	    if ( redir_configs[i].template && (redir_configs[i].template_size > 0) ) {
		/* send template body */
		oobj = malloc(sizeof(*oobj));
		if ( oobj ) {
		    bzero(oobj, sizeof(*oobj));
		    body = alloc_buff(redir_configs[i].template_size);
		}
		if ( body ) {
		    char *tptr, *tptrend, *proc;

		    oobj->body = body;
		    tptr = redir_configs[i].template;
		    tptrend = redir_configs[i].template + redir_configs[i].template_size;
		    rc = 0;
		    while ( tptr < tptrend && !rc ) {
			proc = strchr(tptr, '%');
			if ( !proc ) {
			    rc = attach_data(tptr, tptrend-tptr, body);
			    break;
			}
			rc = attach_data(tptr, proc-tptr, body);
			switch(*(proc+1)) {
			case 'r':
			case 'R':
				if ( rr->substring )
					rc = attach_data(rr->substring,
						strlen(rr->substring), body);
				tptr = proc+2;
				continue;
			case 'u':
			case 'U':
				rc = attach_data(url,
					strlen(decoded_url), body);
				tptr = proc+2;
				continue;
			case '%':
				rc = attach_data("%", 1, body);
				tptr = proc+2;
				continue;
			default:
				rc = attach_data("%", 1, body);
				tptr = proc+2;
				continue;
			}
		    }
		    if ( !rc ) {
			put_av_pair(&oobj->headers, "HTTP/1.0", "403 Forbidden");
			put_av_pair(&oobj->headers,"Expires:", "Thu, 01 Jan 1970 00:00:01 GMT");
			put_av_pair(&oobj->headers,"Content-Type:", "text/html");
			process_output_object(so, oobj, rq);
		    }
		}
		if ( flags ) *flags |= MOD_AFLAG_OUT|MOD_AFLAG_BRK;
		goto done;
	    }
	    /* otherwise send some default ban message */
	    oobj = malloc(sizeof(*oobj));
	    if ( oobj ) {
		bzero(oobj, sizeof(*oobj));
		body = alloc_buff(128);
		if ( body ) {
		    oobj->body = body;
		    attach_data(default_template, default_template_size, body);
		    put_av_pair(&oobj->headers, "HTTP/1.0", "403 Forbidden");
		    put_av_pair(&oobj->headers,"Expires:", "Thu, 01 Jan 1970 00:00:01 GMT");
		    put_av_pair(&oobj->headers,"Content-Type:", "text/html");
		    process_output_object(so, oobj, rq);
		}
	    }
	    if ( flags ) *flags |= MOD_AFLAG_OUT|MOD_AFLAG_BRK;
	    goto done;
	}
	rr = rr->next;
    }
done:
    UNLOCK_REDIR_CONFIG ;
    if ( oobj ) free_output_obj(oobj);
    if ( url ) free(url);
    IF_FREE(decoded_url);
    return(MOD_CODE_OK);
}

void
free_rules(struct redir_rule *rr)
{
struct redir_rule *next;

    while(rr) {
	next = rr->next;
	if (rr->redirect) free(rr->redirect);
	if (rr->substring) free(rr->substring);
	free(rr);
	rr = next;
    }
}

void
reload_redir_rules(int i)
{
struct stat sb;
int			rc;
FILE			*rf;
char			buf[1024], reg[1024], red[1024];
struct	redir_rule	*new_rr, *last;

    if ( (i<0) || (i>=NREDIRCONFIGS)) i = 0;
    rc = stat(redir_configs[i].redir_rules_file, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= redir_configs[i].rules_mtime )
	    return;
	rf = fopen(redir_configs[i].redir_rules_file, "r");
	if ( !rf ) {
	    verb_printf("Can't fopen(%s): %m\n", redir_configs[i].redir_rules_file);
	    return;
	}
	WRLOCK_REDIR_CONFIG ;
	if ( redir_configs[i].redir_rules ) {
	   free_rules(redir_configs[i].redir_rules);
	   redir_configs[i].redir_rules = NULL;
	}
	while ( fgets(buf, sizeof(buf) - 1, rf) ) {
	    char *p = buf;
	    /* got line, parse it */
	    verb_printf("got line: %s", buf);
	    if ( buf[0] == '#' ) continue;
	    /* line can contain regex part and redirection url			*/
	    /* and line can contain only regex, in which case we will send 	*/
	    /* template								*/
	    buf[sizeof(buf)-1] = 0;
	    if ( (p = strchr(buf,'\n')) ) *p = 0;
	    rc = sscanf(buf, "%s %s", (char *)&reg, (char *)&red);
	    if ( rc == 2 ) {
		verb_printf("substr: %s, redirect to :%s\n", reg, red);
		new_rr = malloc(sizeof(*new_rr));
		bzero(new_rr, sizeof(*new_rr));
		if ( new_rr ) {
		    char	*rr_url, *rr_orig;
		    rr_orig = malloc(strlen(reg)+1);
		    if ( !rr_orig ) {
			free(new_rr);
			continue;
		    }
		    strcpy(rr_orig, reg);
		    rr_url = malloc(strlen(red)+1);
		    if ( !rr_url ) {
			if ( rr_orig ) free(rr_orig);
			free(new_rr);
			continue;
		    }
		    strcpy(rr_url, red);
		    new_rr->redirect = rr_url;
		    new_rr->substring = rr_orig;
		    if ( !strncasecmp(rr_url, "internal:", 9) && (strlen(rr_url)>9))
			new_rr->internal = find_internal(rr_url+9, redir_internals);
                    if ( !strcasecmp(rr_url, "allow") ) {
                        SET(new_rr->flags, RULE_ALLOW);
                    }
		    last = redir_configs[i].redir_rules;
		    if ( !last ) {
			redir_configs[i].redir_rules = new_rr;
		    } else {
			while ( last->next ) last = last->next;
			last->next = new_rr;
		    }
		}
		verb_printf("rule inserted\n");
		continue;
	    }
	    if ( rc == 1 ) {
		char *rr_orig;
		verb_printf("substr: %s, use template\n", reg);
		new_rr = malloc(sizeof(*new_rr));
		bzero(new_rr, sizeof(*new_rr));
		if ( new_rr ) {
		    rr_orig = malloc(strlen(reg)+1);
		    if ( !rr_orig ) {
			free(new_rr);
			continue;
		    }
		    strcpy(rr_orig, reg);
		    new_rr->substring = rr_orig;
		    last = redir_configs[i].redir_rules;
		    if ( !last ) {
			redir_configs[i].redir_rules = new_rr;
		    } else {
			while ( last->next ) last = last->next;
			last->next = new_rr;
		    }
		}
		verb_printf("rule inserted\n");
		continue;
	    } else {
		verb_printf("unrecognized format: %s\n", buf);
	    }
	}
	fclose(rf);
	redir_configs[i].rules_mtime = sb.st_mtime;
	redir_configs[i].rules_check_time = global_sec_timer;
	UNLOCK_REDIR_CONFIG ;
    }
}

void
reload_redir_template(int i)
{
struct stat sb;
int	rc, size;
char	*in_mem;

    if ( (i<0) || (i>=NREDIRCONFIGS)) i = 0;
    rc = stat(redir_configs[i].redir_template, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= redir_configs[i].template_mtime )
	    return;
	if ( !redir_configs[i].redir_template[0] )
	    return;
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "Loading template from '%s'\n", redir_configs[i].redir_template);

	size   = sb.st_size;
	WRLOCK_REDIR_CONFIG ;
	if ( redir_configs[i].template ) xfree(redir_configs[i].template);
	redir_configs[i].template = NULL;

	in_mem = malloc(size+1);
	if ( in_mem ) {
	    int fd = open(redir_configs[i].redir_template, O_RDONLY);
	    if ( fd != -1 ) {
		if ( read(fd, in_mem, size) == size ) {
		    redir_configs[i].template	= in_mem;
		    redir_configs[i].template_size	= size;
		    redir_configs[i].template_mtime	= sb.st_mtime;
		    redir_configs[i].template[size]	= 0; /* so we can use str... functions */
    		    redir_configs[i].template_check_time = global_sec_timer;
		} else {
		    verb_printf("Read failed: %m\n");
		    xfree(in_mem);
		}
		close(fd);
	    } /* fd != -1 */ else {
		verb_printf("Open(%s) failed: %m\n", redir_configs[i].redir_template);
		xfree(in_mem);
	    }
	} /* if in_mem */
	UNLOCK_REDIR_CONFIG;
    } /* stat() != -1 */
}

void
check_template_age(int i)
{
    if ( global_sec_timer - redir_configs[i].template_check_time < 60 ) /* once per minute */
	return;
    reload_redir_template(i);
}

void
check_rules_age(int i)
{
    if ( global_sec_timer - redir_configs[i].rules_check_time < 60 ) /* once per minute */
	return;
    reload_redir_rules(i);
}

#if	!defined(HAVE_STRCASESTR)
static char *
strcasestr( char *s, char *find )
{
    char c, sc;
    size_t len;

    if ( s == NULL || find == NULL )
	return NULL;

    if( (c = *find++) != 0 ) {
	len = strlen( find );
	do {
	    do {
		if( (sc = *s++) == 0 )
		    return NULL;
	    } while ( toupper( sc ) != toupper( c ) );
	} while ( strncasecmp( s, find, len ) != 0 );
	s--;
    }
    return (char *)s;
}
#endif /* !HAVE_STRCASESTR */
