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

#define	MODULE_NAME	"redir"
#define	MODULE_INFO	"Regex URL Redirector"

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
static  int     mod_load();
static  int     mod_unload();
static  int     mod_config_beg(int), mod_config_end(int), mod_config(char*, int), 
                mod_run();
static	int	redir(int so, struct group *group, struct request *rq, int *flags, int);
#define		MODULE_STATIC	static
#endif

struct  redir_module    redir_mod = {
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
	char			*orig_regex;	/* original, not compiled	  */
	regex_t			preg;
	internal_doc_t		*internal;
	struct	redir_rule	*next;
        char                    flags;
};

/*
static unsigned char nospam1x1gif[] = {
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x03, 0x00,
    0x03, 0x00, 0x80, 0xff, 0x00, 0xc0, 0xc0, 0xc0,
    0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x00, 0x02, 0x03, 0x84,
    0x7f, 0x05, 0x00, 0x3b
};
*/

static unsigned char nospam1x1gif[] = {
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
	0x01, 0x00, 0xf0, 0x00, 0x00, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x64,
	0x00, 0x01, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x4c,
	0x01, 0x00, 0x3b
};

static unsigned char nospam468x60gif[] = {
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xD4, 0x01,
    0x3C, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0x21, 0xF9, 0x04, 0x09, 0x00,
    0x00, 0x01, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
    0xD4, 0x01, 0x3C, 0x00, 0x00, 0x02, 0xD3, 0x8C,
    0x8F, 0xA9, 0xCB, 0xED, 0x0F, 0xA3, 0x9C, 0xB4,
    0xDA, 0x8B, 0xB3, 0xDE, 0xBC, 0xFB, 0x0F, 0x86,
    0xE2, 0x48, 0x96, 0xE6, 0x89, 0xA6, 0xEA, 0xCA,
    0xB6, 0xEE, 0x0B, 0xC7, 0xF2, 0x4C, 0xD7, 0xF6,
    0x8D, 0xE7, 0xFA, 0xCE, 0xF7, 0xFE, 0x0F, 0x0C,
    0x0A, 0x87, 0xC4, 0xA2, 0xF1, 0x88, 0x4C, 0x2A,
    0x97, 0xCC, 0xA6, 0xF3, 0x09, 0x8D, 0x4A, 0xA7,
    0xD4, 0xAA, 0xF5, 0x8A, 0xCD, 0x6A, 0xB7, 0xDC,
    0xAE, 0xF7, 0x0B, 0x0E, 0x8B, 0xC7, 0xE4, 0xB2,
    0xF9, 0x8C, 0x4E, 0xAB, 0xD7, 0xEC, 0xB6, 0xFB,
    0x0D, 0x8F, 0xCB, 0xE7, 0xF4, 0xBA, 0xFD, 0x8E,
    0xCF, 0xEB, 0xF7, 0xFC, 0xBE, 0xFF, 0x0F, 0x18,
    0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98,
    0xA8, 0xB8, 0xC8, 0xD8, 0xE8, 0xF8, 0x08, 0x19,
    0x29, 0x39, 0x49, 0x59, 0x69, 0x79, 0x89, 0x99,
    0xA9, 0xB9, 0xC9, 0xD9, 0xE9, 0xF9, 0x09, 0x1A,
    0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A, 0x8A, 0x9A,
    0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA, 0x0A, 0x1B,
    0x2B, 0x3B, 0x4B, 0x5B, 0x6B, 0x7B, 0x8B, 0x9B,
    0xAB, 0xBB, 0xCB, 0xDB, 0xEB, 0xFB, 0x0B, 0x1C,
    0x2C, 0x3C, 0x4C, 0x5C, 0x6C, 0x7C, 0x8C, 0x9C,
    0xAC, 0xBC, 0xCC, 0xDC, 0xEC, 0xFC, 0x0C, 0x1D,
    0x2D, 0x3D, 0x4D, 0x5D, 0x6D, 0x7D, 0x8D, 0x9D,
    0xAD, 0xBD, 0xCD, 0xDD, 0xED, 0xFD, 0x0D, 0x1E,
    0x2E, 0x3E, 0x4E, 0x5E, 0x6E, 0x7E, 0x8E, 0x9E,
    0xAE, 0xBE, 0xCE, 0xDE, 0xEE, 0xFE, 0x0E, 0x6F,
    0x57, 0x00, 0x00, 0x3B
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

#define	MAXMATCH	10
#define INIT_PMATCH(p)          do {\
				    int i;\
				    for(i=0;i<MAXMATCH;i++)\
				    p[i].rm_so = p[i].rm_eo = -1;\
				} while(0)


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

static  redir_config_t          redir_configs[NREDIRCONFIGS];

static	void		  free_rules(struct redir_rule*);
static	void		  reload_redir_rules(int), check_rules_age(int);
static	void		  reload_redir_template(int), check_template_age(int);
static	char		  *build_destination(char*, regmatch_t *, char*);

static	char		  *default_template = "\
		<body bgcolor=white>Requested URL forbidden<p>\n\
		<hr>\n\
		Generated by redir module for oops.</body>";
static	int	default_template_size;

MODULE_STATIC
int
mod_load()
{
int     i;

    printf("Redirector started\n");
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
    default_template_size = strlen(default_template);

    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload()
{
    verb_printf("redir stopped\n");
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
regmatch_t		pmatch[MAXMATCH];
int                     i = instance;

    if ( (i<0) || (i>=NREDIRCONFIGS) ) i=0;
    my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "redir(): redir called.\n");
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
    INIT_PMATCH(pmatch);
    while ( rr ) {
	if ( !regexec(&rr->preg, decoded_url?decoded_url:url, MAXMATCH, (regmatch_t*)&pmatch, 0) ) {
	    if ( rr->orig_regex ) my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "redir(): %s matched %s\n", url, rr->orig_regex);
	    /* matched */

            if ( TEST(rr->flags, RULE_ALLOW) ) {
                goto done;
            }

	    if ( rr->redirect ) {
		if ( ((redir_configs[i].rewrite_mode == BounceIt) 
		       || rr->internal ) 
		     && (oobj = malloc(sizeof(*oobj)) ) ) {
		    /* we must redirect to that URL in rr->redirect */
		    char	*new_dest = NULL;
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
			new_dest = build_destination(url, (regmatch_t*)&pmatch, rr->redirect);
			if ( new_dest )
			     put_av_pair(&oobj->headers,"Location:", new_dest);
			else
			     put_av_pair(&oobj->headers,"Location:", rr->redirect);
			put_av_pair(&oobj->headers,"Content-Type:", "text/html");
		    }
		    process_output_object(so, oobj, rq);
		    IF_FREE(new_dest);
		    if ( flags ) *flags |= MOD_AFLAG_OUT|MOD_AFLAG_BRK;
		    goto done;
		} else {
		    char	*new_dest = NULL;
		    struct url	new_url;
		    int		rc;
		    /* we hawe to rewrite url or malloc oobj failed */
		    new_dest = build_destination(url, (regmatch_t*)&pmatch, rr->redirect);
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
		    IF_FREE(new_dest);
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
				if ( rr->orig_regex )
					rc = attach_data(rr->orig_regex,
						strlen(rr->orig_regex), body);
				tptr = proc+2;
				continue;
			case 'u':
			case 'U':
				rc = attach_data(url,
					strlen(url), body);
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
	if (rr->orig_regex) free(rr->orig_regex);
	regfree(&rr->preg);
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
	    rc = sscanf(buf, "%s %s", (char*)&reg, (char*)&red);
	    if ( rc == 2 ) {
		verb_printf("regex: %s, redirect to :%s\n", reg, red);
		new_rr = malloc(sizeof(*new_rr));
		bzero(new_rr, sizeof(*new_rr));
		if ( new_rr ) {
		    char	*rr_url, *rr_orig;
		    if ( regcomp(&new_rr->preg, reg, REG_ICASE|REG_EXTENDED) ) {
			free(new_rr);
			continue;
		    }
		    rr_orig = malloc(strlen(reg)+1);
		    if ( !rr_orig ) {
			regfree(&new_rr->preg);
			free(new_rr);
			continue;
		    }
		    strcpy(rr_orig, reg);
		    rr_url = malloc(strlen(red)+1);
		    if ( !rr_url ) {
			if ( rr_orig ) free(rr_orig);
			regfree(&new_rr->preg);
			free(new_rr);
			continue;
		    }
		    strcpy(rr_url, red);
		    new_rr->redirect = rr_url;
		    if ( !strncasecmp(rr_url, "internal:", 9) && (strlen(rr_url)>9))
			new_rr->internal = find_internal(rr_url+9, redir_internals);
                    if ( !strcasecmp(rr_url, "allow") ) {
                        SET(new_rr->flags, RULE_ALLOW);
                    }
		    new_rr->orig_regex = rr_orig;
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
		verb_printf("regex: %s, use template\n", reg);
		new_rr = malloc(sizeof(*new_rr));
		bzero(new_rr, sizeof(*new_rr));
		if ( new_rr ) {
		    if ( regcomp(&new_rr->preg, reg, REG_NOSUB|REG_ICASE|REG_EXTENDED) ) {
			free(new_rr);
			continue;
		    }
		    rr_orig = malloc(strlen(reg)+1);
		    if ( !rr_orig ) {
			regfree(&new_rr->preg);
			free(new_rr);
			continue;
		    }
		    strcpy(rr_orig, reg);
		    new_rr->orig_regex = rr_orig;
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
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "reload_redir_template(): Loading template from `%s'\n", redir_configs[i].redir_template);

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
		    verb_printf("reload_redir_template(): Read failed: %m\n");
		    xfree(in_mem);
		}
		close(fd);
	    } /* fd != -1 */ else {
		verb_printf("reload_redir_template(): Open(%s) failed: %m\n", redir_configs[i].redir_template);
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

char*
build_destination(char *src, regmatch_t *pmatch, char *target)
{
char		*result = NULL, *s, *d, esc, doll;
regmatch_t      *curr = pmatch+1;
int		length = 0, subs = 0, n;

    if ( !src || !pmatch ) return(NULL);
    while ( curr->rm_so > -1 ) {
	length += curr->rm_eo - curr->rm_so + 1;
	subs++;
	curr++;
    }
    length += strlen(target) + 1;
    result = malloc(length);
    if ( !result ) return(NULL);
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
	        int     copylen;
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

