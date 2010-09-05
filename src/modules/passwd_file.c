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

#define	MODULE_NAME	"passwd_file"
#define	MODULE_INFO	"Auth using passwd file"

#if	defined(MODULES)
char		module_type   = MODULE_AUTH ;
char		module_name[] = MODULE_NAME ;
char		module_info[] = MODULE_INFO ;
int		mod_load();
int		mod_unload();
int		mod_config_beg(), mod_config_end(), mod_config(), mod_run();
int		auth(int so, struct group *group, struct request* rq, int *flags);
#else
static	char	module_type   = MODULE_AUTH ;
static	char	module_name[] = MODULE_NAME ;
static	char	module_info[] = MODULE_INFO ;
static  int     mod_load();
static  int     mod_unload();
static  int     mod_config_beg(), mod_config_end(), mod_config(), mod_run();
static	int	auth(int so, struct group *group, struct request* rq, int *flags);
#endif

struct	auth_module	passwd_file = {
	{
	NULL, NULL,
	MODULE_NAME,
	mod_load,
	mod_unload,
	mod_config_beg,
	mod_config_end,
	mod_config,
	NULL,
	MODULE_AUTH,
	MODULE_INFO,
	mod_run
	},
	auth
};


static	pthread_rwlock_t	pwf_lock;
static	char	*pwds = NULL;
static	char	*template = NULL;
static	time_t	pwf_mtime, pwf_check_time;
static	time_t	pwf_template_mtime, pwf_template_check_time;
static	int	pwf_template_len;
static	char	pwf_name[MAXPATHLEN];
static	char	pwf_template[MAXPATHLEN];
static	char	pwf_charset[64];
static	char	realm[64];
static	enum	{Basic,Digest} scheme = Basic;

static	char	*authreq = NULL;
static	int	 authreqlen;
static	char	*authreqfmt = "%s realm=%s";
static	char	*std_template = "\n<body>Authorization to proxy-server failed.<p><hr>\n\
<i><font size=-1>by \'passwd_file\' module to Oops.";
static	int	std_template_len;
static	int	pwf_charset_len;
static	int	badschlen;
static	char	*badsch=NULL;
static	char	*badschfmt = "HTTP/1.0 407 Proxy Authentication required\n\
Proxy-Authenticate: %s realm=%s\n\n\
<body>Authorization to proxy-server failed.<p>\n\
Your browser proposed unsupported scheme\n\
<hr>\n\
<i><font size=-1>by \'passwd_file\' module to Oops.";

#define	RDLOCK_PWF_CONFIG	pthread_rwlock_rdlock(&pwf_lock)
#define	WRLOCK_PWF_CONFIG	pthread_rwlock_wrlock(&pwf_lock)
#define	UNLOCK_PWF_CONFIG	pthread_rwlock_unlock(&pwf_lock)

static	void	reload_pwf(void), reload_pwf_template(void);
static	void	check_pwf_age(void), check_pwf_template_age(void);
static	int	pwf_auth(char*, char*);
static	void	send_auth_req(int, struct request *);

#if	!defined(SOLARIS)
pthread_mutex_t	crypt_lock;
#endif

int
mod_run()
{
    return(MOD_CODE_OK);
}

int
mod_load()
{
    printf("Passwd_file started\n");
    pthread_rwlock_init(&pwf_lock, NULL);
#if	!defined(SOLARIS)
    pthread_mutex_init(&crypt_lock, NULL);
#endif
    std_template_len = strlen(std_template);
    return(MOD_CODE_OK);
}
int
mod_unload()
{
    printf("passwd_file stopped\n");
    return(MOD_CODE_OK);
}

int
mod_config_beg()
{
    WRLOCK_PWF_CONFIG ;
    if ( pwds ) free(pwds); pwds = 0;
    if ( authreq ) free(authreq); authreq = 0;
    if ( badsch ) free(badsch); badsch = 0;
    if ( template ) free(template); template = 0;
    pwf_name[0]		= 0;
    pwf_template[0]	= 0;
    pwf_charset[0]	= 0;
    pwf_mtime = pwf_template_mtime = 0;
    strcpy(realm, "oops") ;
    scheme = Basic;
    pwf_check_time = 0 ;
    pwf_mtime      = 0 ;
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

int
mod_config_end()
{
char	*sch="None";

    WRLOCK_PWF_CONFIG ;
    if ( scheme == Basic ) sch = "Basic";
    if ( scheme == Digest) sch = "Digest";
    authreqlen = 0;
    authreq = malloc(strlen(authreqfmt)+1+strlen(realm)+strlen(sch));
    if ( authreq ) {
	sprintf(authreq, authreqfmt, sch, realm);
	authreqlen = strlen(authreq);
    }

    badschlen = 0;
    badsch = malloc(strlen(badschfmt)+1+strlen(realm)+strlen(sch));
    if ( badsch ) {
	sprintf(badsch, badschfmt, sch, realm);
	badschlen = strlen(badsch);
    }

    if ( pwf_name[0] )
	reload_pwf();
    if ( pwf_template[0] )
	reload_pwf_template();
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

int
mod_config(char *config)
{

char	*p = config;

    WRLOCK_PWF_CONFIG ;

    while( *p && IS_SPACE(*p) ) p++;
    if ( !strncasecmp(p, "file", 4) ) {
	p += 4;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(pwf_name, p, sizeof(pwf_name) -1 );
    } else
    if ( !strncasecmp(p, "realm", 5) ) {
	p += 5;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(realm, p, sizeof(realm) -1 );
    } else
    if ( !strncasecmp(p, "template", 8) ) {
	p += 8;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(pwf_template, p, sizeof(pwf_template) -1 );
    } else
    if ( !strncasecmp(p, "charset", 7) ) {
	p += 7;
	while (*p && IS_SPACE(*p) ) p++;
	sprintf(pwf_charset, "Content-Type: text/html; charset=%.20s\n", p);
	pwf_charset_len = strlen(pwf_charset);
    } else
    if ( !strncasecmp(p, "scheme", 6) ) {
	p += 6;
	while (*p && IS_SPACE(*p) ) p++;
	if ( !strcasecmp(p, "basic") )  scheme = Basic;
	if ( !strcasecmp(p, "digest") ) scheme = Digest;
    }

    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

int
auth(int so, struct group *group, struct request* rq, int *flags) {
char	*authorization = NULL;

    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "auth(): Authenticate request.\n");

    if ( !authreq ) {
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "auth(): Something wrong with passwd_file module.\n");
	return(MOD_CODE_OK);
    }

    WRLOCK_PWF_CONFIG ;
    check_pwf_age();
    check_pwf_template_age();
    UNLOCK_PWF_CONFIG;

    RDLOCK_PWF_CONFIG ;
    if ( !pwds ) {
	my_xlog(LOG_SEVERE, "auth(): Passwd file was not loaded.\n");
	UNLOCK_PWF_CONFIG ;
	return(MOD_CODE_OK);
    }
    if ( rq->av_pairs)
	authorization = attr_value(rq->av_pairs, "Proxy-Authorization");
    if ( !authorization ) {
	/* send 407 Proxy Authentication Required */
	send_auth_req(so, rq);
	SET(*flags, MOD_AFLAG_OUT);
	UNLOCK_PWF_CONFIG ;
	return(MOD_CODE_ERR);
    } else {
	char *data;
	if ( !strncasecmp(authorization, "Basic", 5 ) ) {
	  int	 rc;
	  char	*up=NULL, *u, *p;
	    data = authorization + 5;
	    while ( *data && IS_SPACE(*data) ) data++;
	    if ( *data ) up = base64_decode(data);
	    if ( up ) {
		/* up = username:password */
		u = up;
		p = strchr(up, ':');
		if ( p ) { *p=0; p++; }
		rc = pwf_auth(u, p);
	        if ( rc ) {
		    /*failed*/
		    free(up);
		    goto au_f;
		  } else {
		    IF_STRDUP(rq->proxy_user, u);
		    free(up);
		    goto au_ok;
		  }
	    } /* up != NULL */
	} else {
	    /* we do not support any schemes except Basic */
	    if ( badsch ) {
		writet(so, badsch, badschlen, 30);
		SET(*flags, MOD_AFLAG_OUT);
	    }
	    UNLOCK_PWF_CONFIG ;
	    return(MOD_CODE_ERR);
	}
au_f:   send_auth_req(so, rq);
	SET(*flags, MOD_AFLAG_OUT);
	UNLOCK_PWF_CONFIG ;
	return(MOD_CODE_ERR);
    }
au_ok:
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

void
check_pwf_age(void)
{
    if ( global_sec_timer - pwf_check_time < 60 ) return; /* once per minute */
    reload_pwf();
}

void
check_pwf_template_age(void)
{
    if ( global_sec_timer - pwf_template_check_time < 60 ) return;
    reload_pwf_template();
}

void
reload_pwf(void)
{
struct	stat	sb;
int		rc, size, fd;

    pwf_check_time = global_sec_timer;
    if ( !pwf_name[0] ) return;
    rc = stat(pwf_name, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= pwf_mtime ) return;
	size = sb.st_size;
	if ( size <= 0 ) return;
	if ( pwds ) free(pwds); pwds = NULL;
	pwds = xmalloc(size+2,"reload_pwf(): pwds"); /* for leading \n and closing 0 */
	if ( pwds ) {
	    *pwds = '\n';
	    fd = open(pwf_name, O_RDONLY);
	    if ( fd != -1 ) {
		rc = read(fd, pwds+1, size);
		if ( rc != size ) {
		    free(pwds);pwds = NULL;
		} else {
		    pwf_mtime = sb.st_mtime;
		    *(pwds+1+size)=0;
		}
		close(fd);
	    } else {
		free(pwds); pwds = NULL;
	    }
	}
    }
}

void
reload_pwf_template(void)
{
struct	stat	sb;
int		rc, size, fd;

    if ( !pwf_template[0] ) return;
    rc = stat(pwf_template, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= pwf_template_mtime ) return;
	size = sb.st_size;
	if ( size <= 0 ) return;
	if ( template ) free(template); template = NULL;
	template = xmalloc(size,"reload_pwf_template(): 1");
	if ( template ) {
	    fd = open(pwf_template, O_RDONLY);
	    if ( fd != -1 ) {
		rc = read(fd, template, size);
		if ( rc != size ) {
		    free(template);template = NULL;
		} else {
		    pwf_template_mtime = sb.st_mtime;
		    pwf_template_check_time = global_sec_timer;
		    pwf_template_len = size;
		}
		close(fd);
	    } else {
		free(template); template = NULL;
	    }
	}
    }
}

int
pwf_auth(char* user, char *pass)
{
char	*patt=NULL, *record;
char	passwd[128], *s, *d, *r;
int	off, rc=1;

    if ( !pwds )
	return(1);
    off = strlen(user) + 3;
    patt = xmalloc(off, "pwf_auth(): 1");
    if ( !patt )
	goto bad_auth;
    sprintf(patt,"\n%s:", user);
    record = strstr(pwds, patt);
    if ( !record )
	goto bad_auth;
    s = record+off-1;
    d = passwd;
    while ( *s && !IS_SPACE(*s) && (d - passwd < sizeof(passwd)) ) {
	*d++ = *s++;
    }
    *d = 0;

#if	!defined(SOLARIS)
    pthread_mutex_lock(&crypt_lock);
#endif

    r = crypt(pass, passwd);
    if ( r && !strcmp(r, passwd) )
	rc = 0;

#if	!defined(SOLARIS)
    pthread_mutex_unlock(&crypt_lock);
#endif

bad_auth:;
    if ( patt ) xfree(patt);
    return(rc);
}

void
send_auth_req(int so, struct request *rq)
{
struct	output_object	*obj;
struct	buff		*body;
int			rc;

    obj = xmalloc(sizeof(*obj),"send_auth_req(): obj");
    if ( !obj )
	return;

    bzero(obj, sizeof(*obj));

    put_av_pair(&obj->headers,"HTTP/1.0", "407 Proxy Authentication Required");
    put_av_pair(&obj->headers,"Proxy-Authenticate:", authreq);
    put_av_pair(&obj->headers,"Content-Type:", "text/html");

    if ( !template ) body = alloc_buff(std_template_len);
	else	     body = alloc_buff(pwf_template_len);
    if ( body ) {
	obj->body = body;
	if ( !template )
		rc = attach_data(std_template, std_template_len, body);
	    else
		rc = attach_data(template, pwf_template_len, body);
        if ( !rc )
		process_output_object(so, obj, rq);
    }

    free_output_obj(obj);
    return;
}
