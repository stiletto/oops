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

char	module_type   = MODULE_ERR ;
char	module_name[] = "err" ;
char	module_info[] = "Error reporting module" ;

#define	LANG_EN	0
#define	LANG_RU	1

static	char	 	err_lang[16];
static	char	 	err_template[MAXPATHLEN];
static	int		curr_lang;
static	char		*template;
static	int		template_size;
static	time_t		template_mtime;
static	time_t		template_check_time;
static	rwl_t		err_config_lock;
static	void		check_template_age();
static	void		reload_template();

#define	WRLOCK_ERR_CONFIG	rwl_wrlock(&err_config_lock)
#define	RDLOCK_ERR_CONFIG	rwl_rdlock(&err_config_lock)
#define	UNLOCK_ERR_CONFIG	rwl_unlock(&err_config_lock)

char	*messages[2][8] = {

	/*-- LANG_EN --*/
	{ "Bad formed url",
	  "Bad port",
	  "Access denied to this domain",
	  "DNS error, can't resolve",
	  "INternal error",
	  "Access Denied",
	  "Data transfer error",
	  "Denied by ACL"
	},

	/*-- LANG RU --*/
	{"������� �������������� URL",
	 "����������� ����",
	 "� ������ ������ ��������",
	 "������ DNS, ���������� ���������� ����� ������",
	 "���������� ������",
	 "������ ��������",
	 "������ �������� ������",
	 "������ �������� ACL"}
};

int
mod_load()
{
    printf("Err_report started\n");
    err_lang[0]	    = 0;
    err_template[0] = 0;
    curr_lang = LANG_EN;
    template = NULL;
    template_size = 0;
    template_mtime = 0;
    template_check_time = 0;
    rwl_init(&err_config_lock);
    return(MOD_CODE_OK);
}
int
mod_unload()
{
    WRLOCK_ERR_CONFIG ;
    printf("Err_report stopped\n");
    return(MOD_CODE_OK);
}

int
mod_config_beg()
{
    WRLOCK_ERR_CONFIG ;
    err_lang[0]	    = 0;
    err_template[0] = 0;
    curr_lang = LANG_EN;
    if ( template ) xfree(template);
    template = NULL;
    template_size = 0;
    template_mtime = 0;
    template_check_time = 0;
    UNLOCK_ERR_CONFIG ;
}

int
mod_config_end()
{

    WRLOCK_ERR_CONFIG ;
    if ( !strcasecmp(err_lang, "ru") ) {
	printf("Setting Language to 'ru'\n");
	curr_lang = LANG_RU;
    }
    if ( err_template[0] ) {
	reload_template();
    }
    UNLOCK_ERR_CONFIG ;
}

int
mod_config(char *config)
{
char	*p = config;

    WRLOCK_ERR_CONFIG ;

    while( *p && isspace(*p) ) p++;
    if ( !strncasecmp(p, "lang", 4) ) {
	p += 4;
	while (*p && isspace(*p) ) p++;
	strncpy(err_lang, p, sizeof(err_lang) -1 );
    } else
    if ( !strncasecmp(p, "template", 8) ) {
	p += 8;
	while (*p && isspace(*p) ) p++;
	strncpy(err_template, p, sizeof(err_template) -1 );
    }
done:
    UNLOCK_ERR_CONFIG ;
    return(MOD_CODE_OK);
}

int
err(int so, char *msg, char *reason, int code, struct request* rq, int *flags) {
char	*hdr = "<html><body>\
		<i><h2>Invalid request:</h2></i><p><pre>";
char	*rf= "</pre><b>";
char	*trailer="\
		</b><p>Please, check URL.<p>\
		<hr>\
		Generated by Oops.\
		</body>\
		</html>";
struct	output_object	*obj;
struct	buff		*body;


    obj = malloc(sizeof(*obj));
    if ( !obj )
	return(0);
    bzero(obj, sizeof(*obj));
    put_av_pair(&obj->headers,"HTTP/1.0", "400 Bad Request");
    put_av_pair(&obj->headers,"Expires:", "Thu, 01 Jan 1970 00:00:01 GMT");
    put_av_pair(&obj->headers,"Content-Type:", "text/html");

    check_template_age();

    RDLOCK_ERR_CONFIG ;


    if ( template ) {
	char 	*tptr, *tptrend, *proc;

	body = alloc_buff(template_size);
	if ( !body )
	    goto failed;
	obj->body = body;

	tptr = template;
	tptrend = tptr+template_size;

	/* send template loop */
	while( tptr < tptrend ) {
	    proc = strchr(tptr, '%');
	    if ( !proc ) {
		int rc;
		rc = attach_data(tptr, tptrend-tptr, body);
		if ( rc ) goto failed;
		UNLOCK_ERR_CONFIG ;
		process_output_object(so, obj, rq);
		if ( obj ) free_output_obj(obj);
		SET(*flags, MOD_AFLAG_OUT);
		return(0);
	    }
	    attach_data(tptr, proc-tptr, body);
	    switch ( *(proc+1) ) {
		case '%':
			attach_data("%", 1, body);
			tptr = proc+2;
			break;
		case 'm':
			attach_data(messages[LANG_EN][code-1],
				strlen(messages[LANG_EN][code-1]),
				body);
			if ( code == ERR_DNS_ERR ) {
			    attach_data(": ", 2, body);
			    attach_data(reason, strlen(reason), body);
			}
			if ( code == ERR_TRANSFER ) {
			    attach_data(": ", 2, body);
			    attach_data(reason, strlen(reason), body);
			}
			if ( code == ERR_ACL_DENIED ) {
			    attach_data(": ", 2, body);
			    attach_data(reason, strlen(reason), body);
			}
			tptr = proc+2;
			break;
		case 'M':
			attach_data(messages[curr_lang][code-1],
				strlen(messages[curr_lang][code-1]),
				body);
			if ( code == ERR_DNS_ERR ) {
			    attach_data(": ", 2, body);
			    attach_data(reason, strlen(reason), body);
			}
			if ( code == ERR_TRANSFER ) {
			    attach_data(": ", 2, body);
			    attach_data(reason, strlen(reason), body);
			}
			if ( code == ERR_ACL_DENIED ) {
			    attach_data(": ", 2, body);
			    attach_data(reason, strlen(reason), body);
			}
			tptr = proc+2;
			break;
		default:
			attach_data("%", 1, body);
			tptr = proc+1;
			break;
	    }
	}
    }

    UNLOCK_ERR_CONFIG ;
    body = alloc_buff(128);
    if ( body ) {
	obj->body = body;
	attach_data(hdr, strlen(hdr), body);
	attach_data(msg, strlen(msg), body);
	attach_data(rf, strlen(rf), body);
	attach_data(reason, strlen(reason), body);
	attach_data(trailer, strlen(trailer), body);
	process_output_object(so, obj, rq);
    }
    SET(*flags, MOD_AFLAG_OUT);
    if ( obj ) free_output_obj(obj);
    return;

  failed:
    UNLOCK_ERR_CONFIG ;
    if ( obj ) free_output_obj(obj);
    return;
}

void
check_template_age()
{
    if ( global_sec_timer - template_check_time < 5 )
	return;
    WRLOCK_ERR_CONFIG ;
    reload_template();
    UNLOCK_ERR_CONFIG ;
}

void
reload_template()
{
struct stat sb;
int	rc, size;
char	*in_mem;

    /* must be called under locked err_config_lock */
    rc = stat(err_template, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= template_mtime )
	    return;
	if ( !err_template[0] )
	    return;
	my_log("Loading template from '%s'\n", err_template);

	size   = sb.st_size;
	if ( template ) xfree(template);
	template = NULL;
	
	in_mem = malloc(size+1);
	if ( in_mem ) {
	    int fd = open(err_template, O_RDONLY);
	    if ( fd != -1 ) {
		if ( read(fd, in_mem, size) == size ) {
		    template	= in_mem;
		    template_size	= size;
		    template_mtime	= sb.st_mtime;
		    template_check_time = global_sec_timer;
		    template[size]	= 0; /* so we can use str... functions */
		} else {
		    printf("Read failed: %s\n", strerror(errno));
		    xfree(in_mem);
		}
		close(fd);
	    } /* fd != -1 */ else {
		printf("Open(%s) failed: %s\n", err_template,strerror(errno));
		xfree(in_mem);
	    }
	} /* if in_mem */
    } /* stat() != -1 */
}
