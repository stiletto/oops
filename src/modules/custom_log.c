#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<stdarg.h>
#include	<strings.h>
#include	<netdb.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<signal.h>
#include	<locale.h>
#include	<time.h>
#include	<string.h>

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

#include "../oops.h"
#include "../modules.h"

#define	RDLOCK_CL	rwl_rdlock(&cloglock)
#define	WRLOCK_CL	rwl_wrlock(&cloglock)
#define	UNLOCK_CL	rwl_unlock(&cloglock)

#define	LOGBUFSZ	64000
#define	FLAG_BUFF	1

typedef	struct	logfile_ {
	struct	logfile_	*next;
	char			*format;
	FILE			*file;
	char			*path;
	int			flags;
	/* dp */
	char			*buff;
	int			curr_size;
	int			allocated;
} logfile_t;

static	logfile_t	*logfiles, *current_config = NULL;
static	rwl_t		cloglock;
static	void		close_logfiles();
static	void		process_log_record(logfile_t*, int, struct request*, struct mem_obj*);

char	module_type = MODULE_LOG;
char	module_info[] ="Customized access log.";
char	module_name[] ="CustomLog";

int
mod_log(int elapsed, struct request *rq, struct mem_obj *obj)
{
logfile_t *curr;

    RDLOCK_CL;
    curr = logfiles;
    while ( curr ) {
	process_log_record(curr, elapsed, rq, obj);
	curr = curr->next;
    }
    UNLOCK_CL;
    return(MOD_CODE_OK);
}

void
process_log_record(logfile_t *curr, int elapsed, struct request *rq,
				    struct mem_obj *obj)
{
    if ( !curr || !rq || !curr->file || !curr->format )
	return;
    RDLOCK_CL;
    {
	char	res[256], *s, *d, *w;

	res[0] = 0;
	/* now scan format line */
	s = curr->format;
	d = res;
	while ( *s && (d - res < sizeof(res) - 1) ) {
	    if ( *s == '%' ) {
		char	aux[128]; /* for {...} data	*/

		aux[0] = 0;

		s++;
	        if ( *s == '{' ) {
		    char *ss, *dd;
		    ss = ++s;
		    dd = aux;
		    while ( dd - aux < sizeof(aux) - 1 ) {
			if ( *ss == '\\' ) {
			    ss++;
			    *dd = *ss; *dd = 0;
			    continue;
			}
			if ( *ss == '}' )
			    break;
			*dd = *ss;
			ss++;
			dd++; *dd = 0;
		    }
		    s = ++ss;
	        }
		switch ( *s ) {
		case 'B':
		case 'b':
		    /* bytes sent (actualy received)	*/
		    {
		    char w[20];
		    sprintf(w,"%u", rq->received);
		    strncat(d, w, sizeof(res)-(d-res)-2);
		    d+= MIN(strlen(w), sizeof(res)-(d-res)-2) - 1;
		    }
		    break;
		case 'A':
		    /* local host (ip)			*/
		    w = my_inet_ntoa(&rq->my_sa);
		    if ( w ) {
			char	m[20];
			sprintf(m, "%s:%u", w, ntohs(rq->my_sa.sin_port));
			strncat(d, m, sizeof(res)-(d-res)-2);
			d+= MIN(strlen(m), sizeof(res)-(d-res)-2) - 1;
			free(w);
		    }
		    break;
		case 'a':
		case 'h':
		    /* remote host (ip)			*/
		    w = my_inet_ntoa(&rq->client_sa);
		    if ( w ) {
			strncat(d, w, sizeof(res)-(d-res)-2);
			d+= MIN(strlen(w), sizeof(res)-(d-res)-2) - 1;
			free(w);
		    }
		    break;
		case 'i':
		    /* request header			*/
		    if ( aux[0] && rq->av_pairs ) {
			char	*value = attr_value(rq->av_pairs, aux);
			if ( value ) {
			     strncat(d, value, sizeof(res)-(d-res)-2);
			     d+= MIN(strlen(value), sizeof(res)-(d-res)-2) - 1;
			} else {
			    strncat(d, "-", sizeof(res)-(d-res)-2);
			    d+= MIN(1, sizeof(res)-(d-res)-2) - 1;
			}
		    } else {
			strncat(d, "-", sizeof(res)-(d-res)-2);
			d+= MIN(1, sizeof(res)-(d-res)-2) - 1;
		    }
		    break;
		case 'l':
		    /* remote logname (not supported)	*/
		    strncat(d, "-", sizeof(res)-(d-res)-2);
		    d+= MIN(1, sizeof(res)-(d-res)-2) - 1;
		    break;
		case 't':
		    /* time				*/
		    {
		    char	w[128];
		    struct tm 	tm;
		    time_t	now;
		    now = global_sec_timer;
		    localtime_r(&now, &tm);
		    if ( aux[0] ) /* use supplied format*/
			strftime(w, sizeof(w), aux, &tm);
		    else
			strftime(w, sizeof(w), "%d/%b/%Y:%T %Z", &tm);
		    strncat(d, w, sizeof(res)-(d-res)-2);
		    d+= MIN(strlen(w), sizeof(res)-(d-res)-2) - 1;
		    }
		    break;
		case 'u':
		    /* remote user from auth 		*/
		    if ( rq->proxy_user ) {
			strncat(d, rq->proxy_user, sizeof(res)-(d-res)-2);
			d+= MIN(strlen(rq->proxy_user), sizeof(res)-(d-res)-2) - 1;
		    } else {
			strncat(d, "-", sizeof(res)-(d-res)-2);
			d+= MIN(1, sizeof(res)-(d-res)-2) - 1;
		    }
		    break;
		case 'r':
		    /* 'meth proto://hostpath httpv'	*/
		    if ( rq ) {
		      char	*w, *method, *proto, *host, *path, *httpv;
		      int	wlen;

			method = rq->method; if ( !method ) method = "NULL";
			proto = rq->url.proto; if ( !proto ) proto = "NULL";
			host = rq->url.host; if ( !host ) host = "NULL";
			path = rq->url.path; if ( !path ) path = "/";
			httpv = rq->url.httpv; if ( !httpv ) httpv = "HTTP/1.0";

			wlen =	strlen(method) + strlen(proto) +
				strlen(host) + strlen(path) + strlen(httpv);

			w = malloc(wlen + 10);
			if ( w ) {
			    sprintf(w, "%s %s://%s%-.128s %s", method,
			    		proto, host, path, httpv);
			    strncat(d, w, sizeof(res)-(d-res)-2);
			    d+= MIN(strlen(w), sizeof(res)-(d-res)-2) - 1;
			    free(w);
			} else {
			    strncat(d, "-", sizeof(res)-(d-res)-2);
			    d+= MIN(1, sizeof(res)-(d-res)-2) - 1;
			}
		    }
		    break;
		case 's':
		    /* status				*/
		    if ( rq->code ) {
			char	w[16];
			sprintf(w, "%d", rq->code);
			strncat(d, w, sizeof(res)-(d-res)-2);
			d+= MIN(strlen(w), sizeof(res)-(d-res)-2) - 1;
		    } else {
			strncat(d, "-", sizeof(res)-(d-res)-2);
			d+= MIN(1, sizeof(res)-(d-res)-2) - 1;
		    }
		    break;
		case 'm':
		    /* HIT/MISS/... 		*/
		    /* Date: Thu, 23 Mar 2000 12:23:09 +0200
		       From: Oleg Drokin <green@ccssu.ccssu.crimea.ua>
		    */
		    if ( rq->tag ) {
			strncat(d, rq->tag, sizeof(res)-(d-res)-2);
			d+= MIN(strlen(rq->tag), sizeof(res)-(d-res)-2) - 1;
		    } else {
			strncat(d, "NONE", sizeof(res)-(d-res)-2);
			d+= MIN(4,sizeof(res)-(d-res)-2);
		    }
		    break;
		case 'k':
		    /* Hierarchy (DIRECT/NONE/... 		*/
		    /* Date: Thu, 23 Mar 2000 12:23:09 +0200
		       From: Oleg Drokin <green@ccssu.ccssu.crimea.ua>
		    */
		    if ( rq->hierarchy ) {
			strncat(d, rq->hierarchy, sizeof(res)-(d-res)-2);
			d+= MIN(strlen(rq->hierarchy), sizeof(res)-(d-res)-2) - 1;
		    } else {
			strncat(d, "NONE", sizeof(res)-(d-res)-2);
			d+= MIN(4,sizeof(res)-(d-res)-2);
		    }
		    break;
		case 'R':
		    /* Log original url (for accel.c)			*/
		    /* 'meth proto://hostpath httpv'			*/
		    /* Date: Tue, 21 Mar 2000 15:58:53 +0300		*/
		    /* From: Dmitry Perfilyev <dp@zenon.net>		*/

		    if ( rq ) {
		    char      *w, *method, *proto, *original_host, *original_path, *httpv;
		    int       wlen;

			method = rq->method; if ( !method ) method = "NULL";
			proto = rq->url.proto; if ( !proto ) proto = "NULL";
			original_host = rq->original_host;
			if ( !original_host ) original_host= "NULL";
			original_path = rq->original_path;
			if ( !original_path ) original_path = "/";
			httpv = rq->url.httpv;
			if ( !httpv ) httpv = "HTTP/1.0";

			wlen =  strlen(method) + strlen(proto)
			    + strlen(original_host) + strlen(original_path) 
			    + strlen(httpv);

			w = malloc(wlen + 10);
			if ( w ) {
			    sprintf(w, "%s %s://%s%-.128s %s", method,
			    proto, original_host, original_path, httpv);
			    strncat(d, w, sizeof(res)-(d-res)-2);
			    d+= MIN(strlen(w), sizeof(res)-(d-res)-2) - 1;
			    free(w);
			} else {
			    strncat(d, "-", sizeof(res)-(d-res)-2);
			    d+= MIN(1, sizeof(res)-(d-res)-2) - 1;
			}
		    }
		    break;
		default:
		    *d = *s;
		}
	    } else {
		*d = *s;
	    }
	    s++;
	    d++; *d = 0;
	}
	/* dp */
	if ( curr->buff && TEST(curr->flags, FLAG_BUFF) ) {
	    int	strl = strlen(res);
	    if ( ( curr->curr_size + strl + 1 ) >= curr->allocated ) {
		fwrite(curr->buff,curr->curr_size,1,curr->file);
		fflush(curr->file);
		curr->curr_size = 0;
	    }
	    bcopy(res,curr->buff+curr->curr_size,strl);
	    *(curr->buff+curr->curr_size+strl) = '\n';
	    curr->curr_size += strl+1;
	} else
	    fprintf(curr->file, "%s\n", res);
    }
    UNLOCK_CL;
}

void
close_logfiles()
{
logfile_t	*curr = logfiles, *next;

    while(curr) {
	next = curr->next;
	if ( curr->format ) free(curr->format);
	if ( curr->path ) free(curr->path);
	if ( curr->file ) fclose(curr->file);
	if ( curr->buff ) free(curr->buff);
	free (curr);
	curr = next;
    }
    logfiles = NULL;
}

logfile_t*
new_logfile(char *path)
{
logfile_t	*new = NULL;

    if ( !path ) return(NULL);

    new = (logfile_t*)calloc(1, sizeof(*new));
    if ( new ) {
	new->path = strdup(path);
	new->next = logfiles;
	logfiles = new;
    }
    return(new);
}

int
mod_reopen()
{
logfile_t	*curr;

    RDLOCK_CL;
    curr = logfiles;
    while(curr) {
	if ( curr->path ) my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "mod_reopen(): Reopen %s\n", curr->path);
	if ( curr->file ) fclose(curr->file);
	if ( curr->path ) curr->file = fopen(curr->path, "a");
	if ( curr->file ) setbuf(curr->file, NULL);
	curr = curr->next;
    }
    UNLOCK_CL;
    return(MOD_CODE_OK);
}

int
mod_load()
{
    printf("CustomLog started\n");
    logfiles = NULL;
    rwl_init(&cloglock);
    return(MOD_CODE_OK);
}

int
mod_unload()
{
    printf("mod_unload(): CustomLog stopped\n");
    return(MOD_CODE_OK);
}

int
mod_config_beg()
{
    WRLOCK_CL;
    close_logfiles();
    current_config = NULL;
    UNLOCK_CL;
    return(MOD_CODE_OK);
}

int
mod_config_end()
{
    return(MOD_CODE_OK);
}

int
mod_run()
{
logfile_t *curr;

    WRLOCK_CL;
    curr = logfiles;
    if ( oops_user ) set_euser(oops_user);
    while ( curr ) {
	/* go open */
	if ( curr->path ) {
	    curr->file = fopen(curr->path, "a");
	    if ( curr->file ) {
		setbuf(curr->file, NULL);
		if ( curr->allocated )
		    curr->buff = malloc(curr->allocated);
	    } else
		my_xlog(LOG_SEVERE, "mod_run(): custom_log: fopen(%s): %s\n",
			curr->path, strerror(errno));
	}
	curr = curr->next;
    }
    if ( oops_user ) set_euser(NULL);
    UNLOCK_CL;
    return(MOD_CODE_OK);
}

int
mod_config(char* config)
{
char	*p = config;

    while( *p && IS_SPACE(*p) ) p++;

    if ( !strncasecmp(p, "path", 4) ) {
	char	*path = p+4;

	while ( *path && IS_SPACE(*path) ) path++;
	if ( !*path ) {
	    verb_printf("mod_config(): Wrong line `%s'.\n", config);
	}
	/* new logfile */
	current_config = new_logfile(path);
	return(MOD_CODE_OK);
    }
    if ( !strncasecmp(p, "buffered", 8) ) {
	if ( current_config ) {
	    int	allocated;

	    current_config->flags |= FLAG_BUFF;
	    current_config->allocated = LOGBUFSZ;
	    if ( (strlen(p) > 8) && ((allocated=atoi(p+8))>0))
		current_config->allocated = allocated;
	    current_config->curr_size = 0;
	} else {
	    verb_printf("mod_config(): No current logfile.\n");
	}
	return(MOD_CODE_OK);
    }
    if ( !strncasecmp(p, "format", 6) ) {
	if ( current_config ) {
	    char *format, *d, f[128];

	    p += 6;
	    while ( *p && IS_SPACE(*p) ) p++;
	    if ( *p ) {
		format = p++;
		d = f; *d = 0;
		while ( *p && (*p!='\"') && (d-f<sizeof(f)) ) {
		    if ( *p == '\\' ) { *d = *(p+1); p++; }
		      else
			*d = *p;
		    p++;
		    d++;
		}
		*d = 0;
		verb_printf("mod_config(): found format: `%s'.\n", f);
		current_config->format = strdup(f);
	    }
	}
    }
    return(MOD_CODE_OK);
}
