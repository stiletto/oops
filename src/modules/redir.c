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
int		mod_config_beg(), mod_config_end(), mod_config(), mod_run();
int		redir(int so, struct group *group, struct request *rq, int *flags);
#else
static	char	module_type   = MODULE_REDIR ;
static	char	module_name[] = MODULE_NAME ;
static	char	module_info[] = MODULE_INFO ;
static  int     mod_load();
static  int     mod_unload();
static  int     mod_config_beg(), mod_config_end(), mod_config(), mod_run();
static	int	redir(int so, struct group *group, struct request *rq, int *flags);
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


struct	redir_rule {
	char			*redirect;	/* if not null send HTTP redirect */
	char			*orig_regex;	/* original, not compiled	  */
	regex_t			preg;
	internal_doc_t		*internal;
	struct	redir_rule	*next;
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

#define	NMYPORTS	4
static	myport_t	myports[NMYPORTS];	/* my ports		*/
static	char		*myports_string;
int			nmyports;		/* actual number	*/

static	char		redir_rules_file[MAXPATHLEN];
static	char		redir_template[MAXPATHLEN];
static	char		*template;
static	int		template_size;
static	time_t		template_mtime, template_check_time;
static	time_t		rules_mtime, rules_check_time;

static	struct redir_rule *redir_rules;			/* list of rules */
static	void		  free_rules(struct redir_rule*);
static	void		  reload_redir_rules(void), check_rules_age(void);
static	void		  reload_redir_template(void), check_template_age(void);
static	char		  *build_destination(char*, regmatch_t *, char*);

static	char		  *default_template = "\
		<body bgcolor=white>Requested URL forbidden<p>\n\
		<hr>\n\
		Generated by redir module for oops.</body>";
static	int	default_template_size;
static	enum	{RewriteIt, BounceIt} rewrite_mode = RewriteIt;

int
mod_load()
{
    printf("Redirector started\n");
    pthread_rwlock_init(&redir_lock, NULL);
    redir_rules_file[0] = 0;
    redir_template[0] = 0;
    template = NULL;
    template_size = 0;
    template_mtime = template_check_time =
    rules_mtime = rules_check_time = 0;
    redir_rules = NULL;
    nmyports = 0;
    myports_string = NULL;
    default_template_size = strlen(default_template);
    return(MOD_CODE_OK);
}

int
mod_unload()
{
    verb_printf("redir stopped\n");
    return(MOD_CODE_OK);
}

int
mod_config_beg()
{
    WRLOCK_REDIR_CONFIG ;
    redir_rules_file[0] = 0;
    redir_template[0] = 0;
    if ( template ) free(template); template = NULL;
    template_size = 0;
    template_mtime = template_check_time =
    rules_mtime = rules_check_time = 0;
    if ( redir_rules ) {
	free_rules(redir_rules);
	redir_rules = NULL;
    }
    nmyports = 0;
    if ( myports_string ) free(myports_string);
    myports_string = NULL;
    rewrite_mode = RewriteIt;
    UNLOCK_REDIR_CONFIG ;
    return(MOD_CODE_OK);
}

int
mod_config_end()
{
    /* reloads will lock themself */
    if ( redir_rules_file[0] )
	reload_redir_rules();
    if ( redir_template[0] )
	reload_redir_template();
    return(MOD_CODE_OK);
}

int
mod_run()
{
    WRLOCK_REDIR_CONFIG;
    if ( myports_string ) {
	nmyports = parse_myports(myports_string, &myports[0], NMYPORTS);
	verb_printf("%s will use %d ports\n", module_name, nmyports);
    }
    UNLOCK_REDIR_CONFIG;
    return(MOD_CODE_OK);
}

int
mod_config(char *config)
{
char	*p = config;

    WRLOCK_REDIR_CONFIG ;
    while( *p && IS_SPACE(*p) ) p++;
    if ( !strncasecmp(p, "file", 4) ) {
	p += 4;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(redir_rules_file, p, sizeof(redir_rules_file) -1 );
    } else
    if ( !strncasecmp(p, "template", 8) ) {
	p += 8;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(redir_template, p, sizeof(redir_template) -1 );
    } else
    if ( !strncasecmp(p, "myport", 6) ) {
	p += 6;
	while (*p && IS_SPACE(*p) ) p++;
	myports_string = strdup(p);
    }
    if ( !strncasecmp(p, "mode", 4) ) {
	p += 4;
	while (*p && IS_SPACE(*p) ) p++;
	if ( !strcasecmp(p, "bounce") )
	    rewrite_mode = BounceIt;
    }
    UNLOCK_REDIR_CONFIG ;
    return(MOD_CODE_OK);
}

int
redir(int so, struct group *group, struct request *rq, int *flags)
{
char	*url;
int	url_len, rc;
struct	redir_rule	*rr;
struct	output_object	*oobj = NULL;
struct	buff		*body = NULL;
regmatch_t		pmatch[MAXMATCH];

    my_xlog(LOG_DBG|LOG_INFORM, "redir(): redir called.\n");
    if ( !rq ) return(MOD_CODE_OK);
    if ( nmyports > 0 ) {
	int		n = nmyports;
	myport_t 	*mp = myports;
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
    check_rules_age();
    check_template_age();
    RDLOCK_REDIR_CONFIG ;
    rr = redir_rules;
    INIT_PMATCH(pmatch);
    while ( rr ) {
	if ( !regexec(&rr->preg, url, MAXMATCH, (regmatch_t*)&pmatch, 0) ) {
	    if ( rr->orig_regex ) my_xlog(LOG_DBG|LOG_INFORM, "redir(): %s matched %s\n", url, rr->orig_regex);
	    /* matched */
	    if ( rr->redirect ) {
		if ( ((rewrite_mode == BounceIt) || rr->internal ) 
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
	    if ( template && (template_size > 0) ) {
		/* send template body */
		oobj = malloc(sizeof(*oobj));
		if ( oobj ) {
		    bzero(oobj, sizeof(*oobj));
		    body = alloc_buff(template_size);
		}
		if ( body ) {
		    char *tptr, *tptrend, *proc;

		    oobj->body = body;
		    tptr = template;
		    tptrend = template + template_size;
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
reload_redir_rules(void)
{
struct stat sb;
int			rc;
FILE			*rf;
char			buf[1024], reg[1024], red[1024];
struct	redir_rule	*new_rr, *last;

    rc = stat(redir_rules_file, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= rules_mtime )
	    return;
	rf = fopen(redir_rules_file, "r");
	if ( !rf ) {
	    verb_printf("Can't fopen(%s): %m\n", redir_rules_file);
	    return;
	}
	WRLOCK_REDIR_CONFIG ;
	if ( redir_rules ) {
	   free_rules(redir_rules);
	   redir_rules = NULL;
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
		    new_rr->orig_regex = rr_orig;
		    last = redir_rules;
		    if ( !last ) {
			redir_rules = new_rr;
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
		    last = redir_rules;
		    if ( !last ) {
			redir_rules = new_rr;
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
	rules_mtime = sb.st_mtime;
	rules_check_time = global_sec_timer;
	UNLOCK_REDIR_CONFIG ;
    }
}

void
reload_redir_template(void)
{
struct stat sb;
int	rc, size;
char	*in_mem;

    rc = stat(redir_template, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= template_mtime )
	    return;
	if ( !redir_template[0] )
	    return;
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "reload_redir_template(): Loading template from `%s'\n", redir_template);

	size   = sb.st_size;
	WRLOCK_REDIR_CONFIG ;
	if ( template ) xfree(template);
	template = NULL;

	in_mem = malloc(size+1);
	if ( in_mem ) {
	    int fd = open(redir_template, O_RDONLY);
	    if ( fd != -1 ) {
		if ( read(fd, in_mem, size) == size ) {
		    template	= in_mem;
		    template_size	= size;
		    template_mtime	= sb.st_mtime;
		    template[size]	= 0; /* so we can use str... functions */
    		    template_check_time = global_sec_timer;
		} else {
		    verb_printf("reload_redir_template(): Read failed: %m\n");
		    xfree(in_mem);
		}
		close(fd);
	    } /* fd != -1 */ else {
		verb_printf("reload_redir_template(): Open(%s) failed: %m\n", redir_template);
		xfree(in_mem);
	    }
	} /* if in_mem */
	UNLOCK_REDIR_CONFIG;
    } /* stat() != -1 */
}

void
check_template_age(void)
{
    if ( global_sec_timer - template_check_time < 60 ) /* once per minute */
	return;
    reload_redir_template();
}

void
check_rules_age(void)
{
    if ( global_sec_timer - rules_check_time < 60 ) /* once per minute */
	return;
    reload_redir_rules();
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

