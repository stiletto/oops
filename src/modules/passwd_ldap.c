/*
Copyright (C) 1999 Igor Khasilev, igor@paco.net
Copyright (C) 2003 Dmitry Afanasiev, KOT@MATPOCKuH.Ru

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

#include <lber.h>
#include <ldap.h>

#include	"../oops.h"
#include	"../modules.h"

#define	MODULE_NAME	"passwd_ldap"
#define	MODULE_INFO	"Auth using LDAP"

#if	defined(MODULES)
#define		MODULE_STATIC
#else
#define		MODULE_STATIC	static
#endif

MODULE_STATIC char		module_type   = MODULE_AUTH ;
MODULE_STATIC char		module_name[] = MODULE_NAME ;
MODULE_STATIC char		module_info[] = MODULE_INFO ;
MODULE_STATIC int		mod_load(void);
MODULE_STATIC int		mod_unload(void);
MODULE_STATIC int		mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
MODULE_STATIC int		auth(int so, struct group *group, struct request* rq, int *flags);

struct	auth_module	passwd_ldap = {
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

#define USERPASS_LEN 33
typedef struct {
  char user[USERPASS_LEN];
  char pass[USERPASS_LEN];
  time_t check_time;
} pwds_t;

static	pthread_rwlock_t	pwf_lock;

static pwds_t *pwds = NULL;
static int pwds_count = 0;
static int refresh = 0;
static char *searchbase = NULL;
static char *ldapserver = NULL;
static int ldapport = 0;

static	char	*template = NULL;
static	time_t	pwf_template_mtime, pwf_template_check_time;
static	int	pwf_template_len;
static	char	pwf_template[MAXPATHLEN];
static	char	pwf_charset[64];
static	char	realm[64];
static	enum	{Basic,Digest} scheme = Basic;

static	char	*authreq = NULL;
static	int	 authreqlen;
static	char	*authreqfmt = "%s realm=\"%s\"";
static	char	*std_template = "\n<body>Authorization to proxy-server failed.<p><hr>\n\
<i><font size=-1>by \'passwd_ldap\' module to Oops.";
static	int	std_template_len;
static	int	pwf_charset_len;
static	int	badschlen;
static	char	*badsch=NULL;
static	char	*badschfmt = "HTTP/1.0 407 Proxy Authentication required\n\
Proxy-Authenticate: %s realm=\"%s\"\n\n\
<body>Authorization to proxy-server failed.<p>\n\
Your browser proposed unsupported scheme\n\
<hr>\n\
<i><font size=-1>by \'passwd_ldap\' module to Oops.";

#define	RDLOCK_PWF_CONFIG	pthread_rwlock_rdlock(&pwf_lock)
#define	WRLOCK_PWF_CONFIG	pthread_rwlock_wrlock(&pwf_lock)
#define	UNLOCK_PWF_CONFIG	pthread_rwlock_unlock(&pwf_lock)

static	void	reload_pwf_template(void);
static	void	check_pwf_template_age(void);
static	int	pwf_auth(char*, char*);
static	void	send_auth_req(int, struct request *);

#if	!defined(SOLARIS)
pthread_mutex_t	crypt_lock;
#endif

MODULE_STATIC
int
mod_run(void)
{
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_load(void)
{
    pthread_rwlock_init(&pwf_lock, NULL);
#if	!defined(SOLARIS)
    pthread_mutex_init(&crypt_lock, NULL);
#endif
    std_template_len = strlen(std_template);

    printf(MODULE_NAME" started\n");

    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload(void)
{
    RDLOCK_PWF_CONFIG ;

    if(pwds) {
	free(pwds);
	pwds = NULL;
	pwds_count = 0;
    }

    if(searchbase) {
	free(searchbase);
	searchbase = NULL;
    }

    if(ldapserver) {
	free(ldapserver);
	ldapserver = NULL;
    }

    ldapport = 0;

    UNLOCK_PWF_CONFIG ;

    printf(MODULE_NAME" stopped\n");
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_beg(int i)
{
    WRLOCK_PWF_CONFIG ;

    if(pwds)
	free(pwds);
    if(searchbase)
	free(searchbase);
    if(ldapserver)
	free(ldapserver);

    pwds = NULL;
    searchbase = ldapserver = 0;
    pwds_count = ldapport = 0;

    if ( authreq ) free(authreq); authreq = 0;
    if ( badsch ) free(badsch); badsch = 0;
    if ( template ) free(template); template = 0;
    pwf_template[0]	= 0;
    pwf_charset[0]	= 0;
    pwf_template_mtime = 0;
    strcpy(realm, "oops") ;
    scheme = Basic;
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_end(int i)
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

    if ( pwf_template[0] )
	reload_pwf_template();
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config(char *config, int i)
{
    char *p = config;

    WRLOCK_PWF_CONFIG ;

    while( *p && IS_SPACE(*p) ) p++;

    if ( !strncasecmp(p, "refresh", 7) ) {
	p += 7;
	while (*p && IS_SPACE(*p) ) p++;
	refresh = atoi(p);
    } else
    if ( !strncasecmp(p, "searchbase", 10) ) {
	p += 10;
	while (*p && IS_SPACE(*p) ) p++;
	searchbase = strdup(p);
    } else
    if ( !strncasecmp(p, "ldapserver", 10) ) {
	p += 10;
	while (*p && IS_SPACE(*p) ) p++;
	ldapserver = strdup(p);
    } else
    if ( !strncasecmp(p, "ldapport", 8) ) {
	p += 8;
	while (*p && IS_SPACE(*p) ) p++;
	ldapport = atoi(p);
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

MODULE_STATIC
int
auth(int so, struct group *group, struct request* rq, int *flags) {
char	*authorization = NULL;

    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "auth(): Authenticate request.\n");

    if ( !authreq ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "auth(): Something wrong with passwd_ldap module.\n");
	return(MOD_CODE_OK);
    }

    WRLOCK_PWF_CONFIG ;
    check_pwf_template_age();
    UNLOCK_PWF_CONFIG;

    RDLOCK_PWF_CONFIG ;

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
    SET(*flags, MOD_AFLAG_CKACC);
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

static void
check_pwf_template_age(void)
{
    if ( global_sec_timer - pwf_template_check_time < 60 ) return;
    reload_pwf_template();
}

static void
reload_pwf_template(void)
{
struct	stat	sb;
int		rc, size, fd;

    if ( !pwf_template[0] ) return;
    rc = stat(pwf_template, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= pwf_template_mtime ) return;
	size = (int)sb.st_size;
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

static int
pwf_checkldap(char* user, char *pass) {
    LDAP *ldap;
    char s[256];
    int i, rc;
    pwds_t *p;

    if (!searchbase || !ldapserver || !ldapport) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,
	    "pwf_checkldap(): searchbase, ldapserver or ldapport is not set\n");
	return 0;
    }

    ldap = ldap_open(ldapserver, ldapport);
    snprintf(s, sizeof(s), "uid=%s,%s", user, searchbase);
    rc = ldap_simple_bind_s(ldap, s, pass);
    ldap_unbind(ldap);

    if(rc) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,
	    "Wrong user/password\n");
	return 1;
    }

    if(pwds)
	for(i = 0; i < pwds_count; i++)
	    if(global_sec_timer - pwds[i].check_time > refresh) {
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,
		    "New user %s replaced expired user %s\n",
		     user, pwds[i].user);

		strlcpy(pwds[i].user, user, USERPASS_LEN);
		strlcpy(pwds[i].pass, pass, USERPASS_LEN);
		pwds[i].check_time = global_sec_timer;
		return 0;
	    }

    p = realloc(pwds, sizeof(pwds_t) * (++pwds_count));
    if(!p) {
	pwds_count--;
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,
	    "pwf_checkldap(): realloc failed!!!\n");
	return 0;
    }
    pwds = p;

    strlcpy(pwds[pwds_count - 1].user, user, USERPASS_LEN);
    strlcpy(pwds[pwds_count - 1].pass, pass, USERPASS_LEN);
    pwds[pwds_count - 1].check_time = global_sec_timer;

    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,
	"Added new user %s\n", user);

    return 0;
}

static int
pwf_auth(char* user, char *pass)
{
    int i;

    if (!user || !pass || !user[0] || !pass[0]) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,
	    "pwf_auth(): Bad user or pass\n");
	return 1;
    }   

    if(!pwds)
	return pwf_checkldap(user, pass);

    for(i = 0; i < pwds_count; i++)
	if(!strcmp(pwds[i].user, user) && !strcmp(pwds[i].pass, pass) &&
	    (global_sec_timer - pwds[i].check_time < refresh)) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,
		"Cached user %s\n", user);
	    return 0;
	}
	
    return pwf_checkldap(user, pass);
}

static void
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
