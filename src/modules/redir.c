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
char	module_name[] = "redir" ;
char	module_info[] = "Regex URL Redirector" ;

struct	redir_rule {
	char			*redirect;	/* if not null send HTTP redirect */
	char			*orig_regex;	/* original, not compiled	  */
	regex_t			preg;
	struct	redir_rule	*next;
};

static	rwl_t	redir_lock;
#define	RDLOCK_REDIR_CONFIG	rwl_rdlock(&redir_lock)
#define	WRLOCK_REDIR_CONFIG	rwl_wrlock(&redir_lock)
#define	UNLOCK_REDIR_CONFIG	rwl_unlock(&redir_lock)

#define	NMYPORTS	4
static	myport_t	myports[NMYPORTS];	/* my ports		*/
int			nmyports;		/* actual number	*/

static	char		redir_rules_file[MAXPATHLEN];
static	char		redir_template[MAXPATHLEN];
static	char		*template;
static	int		template_size;
static	time_t		template_mtime, template_check_time;
static	time_t		rules_mtime, rules_check_time;

static	struct redir_rule *redir_rules;			/* list of rules */
static	void		  free_rules(struct redir_rule*);
static	void		  reload_redir_rules(), check_rules_age();
static	void		  reload_redir_template(), check_template_age();

static	char		  *default_template = "\
		<body bgcolor=white>Requested URL forbidden<p>\n\
		<hr>\n\
		Generated by redir module for oops.</body>";
static	int	default_template_size;
int
mod_load()
{
    verb_printf("redirector started\n");
    rwl_init(&redir_lock);
    redir_rules_file[0] = 0;
    redir_template[0] = 0;
    template = NULL;
    template_size = 0;
    template_mtime = template_check_time =
    rules_mtime = rules_check_time = 0;
    redir_rules = NULL;
    nmyports = 0;
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
mod_config(char *config)
{
char	*p = config;

    WRLOCK_REDIR_CONFIG ;
    while( *p && isspace(*p) ) p++;
    if ( !strncasecmp(p, "file", 4) ) {
	p += 4;
	while (*p && isspace(*p) ) p++;
	strncpy(redir_rules_file, p, sizeof(redir_rules_file) -1 );
    } else
    if ( !strncasecmp(p, "template", 8) ) {
	p += 8;
	while (*p && isspace(*p) ) p++;
	strncpy(redir_template, p, sizeof(redir_template) -1 );
    } else
    if ( !strncasecmp(p, "myport", 6) ) {
	p += 6;
	while (*p && isspace(*p) ) p++;
	nmyports = parse_myports(p, &myports, NMYPORTS);
	verb_printf("%s will use %d ports\n", module_name, nmyports);
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

    my_log("redir called\n");
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
    while ( rr ) {
	if ( !regexec(&rr->preg, url, 0,  NULL, 0) ) {
	    if ( rr->orig_regex ) my_log("%s matched %s\n", url, rr->orig_regex);
	    /* matched */
	    if ( rr->redirect ) {
		/* we must redirect to that URL in rr->redirect */
		oobj = malloc(sizeof(*oobj));
		bzero(oobj, sizeof(*oobj));
		if ( oobj ) {
		    bzero(oobj, sizeof(*oobj));
		    put_av_pair(&oobj->headers, "HTTP/1.0", "302 Moved temporary");
		    put_av_pair(&oobj->headers,"Expires:", "Thu, 01 Jan 1970 00:00:01 GMT");
		    put_av_pair(&oobj->headers,"Location:", rr->redirect);
		    put_av_pair(&oobj->headers,"Content-Type:", "text/html");
		    process_output_object(so, oobj, rq);
		}
		if ( flags ) *flags |= MOD_AFLAG_OUT|MOD_AFLAG_BRK;
		goto done;
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
reload_redir_rules()
{
struct stat sb;
int			rc, size;
FILE			*rf;
char			buf[1024], reg[1024], red[1024];
struct	redir_rule	*new_rr, *last;

    rc = stat(redir_rules_file, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= rules_mtime )
	    return;
	rf = fopen(redir_rules_file, "r");
	if ( !rf ) {
	    verb_printf("Can't fopen(%s): %s\n", redir_rules_file, strerror(errno));
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
	    rc = sscanf(buf, "%s %s", &reg, &red);
	    if ( rc == 2 ) {
		verb_printf("regex: %s, redirect to :%s\n", reg, red);
		new_rr = malloc(sizeof(*new_rr));
		bzero(new_rr, sizeof(*new_rr));
		if ( new_rr ) {
		    char	*rr_url, *rr_orig;
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
		    rr_url = malloc(strlen(red)+1);
		    if ( !rr_url ) {
			if ( rr_orig ) free(rr_orig);
			regfree(&new_rr->preg);
			free(new_rr);
			continue;
		    }
		    strcpy(rr_url, red);
		    new_rr->redirect = rr_url;
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
		    char	*rr_url;
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
reload_redir_template()
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
	my_log("Loading template from '%s'\n", redir_template);

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
		    verb_printf("Read failed: %s\n", strerror(errno));
		    xfree(in_mem);
		}
		close(fd);
	    } /* fd != -1 */ else {
		verb_printf("Open(%s) failed: %s\n", redir_template,strerror(errno));
		xfree(in_mem);
	    }
	} /* if in_mem */
	UNLOCK_REDIR_CONFIG;
    } /* stat() != -1 */
}
void
check_template_age()
{
    if ( global_sec_timer - template_check_time < 60 ) /* once per minute */
	return;
    reload_redir_template();
}
void
check_rules_age()
{
    if ( global_sec_timer - rules_check_time < 60 ) /* once per minute */
	return;
    reload_redir_rules();
}
