/*
Copyright (C) 1999 Igor Khasilev,   igor@paco.net
Copyright (C) 2000 Vladimir Pivkin, pv_vova@mail.ru

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


#if defined(__PGSQL)
#define		MODULE_NAME	"passwd_pgsql"
#define		MODULE_INFO	"Auth using PostgreSQL %s.%s.%s"
#define		MODULE_BR14	"Auth using PostgreSQL/stopper"
#define		PORT_DEFAULT	"5432"
#define		PORT_TYPE	char *
#define		STRUCT_NAME	passwd_pgsql
#if defined(HAVE_PGSQL)
#include        <pgsql/libpq-fe.h>
#endif
#elif defined(__MYSQL)
#define		MODULE_NAME	"passwd_mysql"
#define		MODULE_INFO	"Auth using mySQL %s"
#define		MODULE_BR14	"Auth using mySQL/stopper"
#define		PORT_DEFAULT	3306
#define		PORT_TYPE	short
#define		STRUCT_NAME	passwd_mysql
#if	defined(HAVE_MYSQL)
#include        <mysql.h> 
#endif
#else
#error You must select & predefine your sql server
#endif

#if	defined(MODULES)
#define MODULE_STATIC
#else
#define MODULE_STATIC static
#endif
MODULE_STATIC	char		module_type   		= MODULE_AUTH;
MODULE_STATIC	char		module_name[] 		= MODULE_NAME;
MODULE_STATIC	char		module_info[MODINFOLEN] = MODULE_BR14;

#if	(defined(__MYSQL) && defined(HAVE_MYSQL)) || (defined(__PGSQL) && defined(HAVE_PGSQL))
MODULE_STATIC	int		mod_load(void),mod_unload(void);
MODULE_STATIC	int		mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
MODULE_STATIC	int		auth(int so, struct group *group, struct request* rq, int *flags);

struct	auth_module STRUCT_NAME = {
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
static	char	pwf_name[MAXPATHLEN]="";
static	time_t	pwf_mtime=0,pwf_check_time=0;
static	char	pwf_charset[64]="";
static	char	realm[64]="";
static	enum	{Basic,Digest} scheme = Basic;

typedef struct {
  char		filename[MAXPATHLEN];
  time_t	mtime;
  time_t	check_time;
  int		len;
  char		*data;
} PWF_FILEINFO;

static PWF_FILEINFO template={"",0,0,0,0};
static PWF_FILEINFO sqlselect={"",0,0,0,0};

typedef struct {
  char		host[32];
  PORT_TYPE		port;
  char		user[32];
  char		password[32];
  char		database[32];
} SQL_INFO;

SQL_INFO sql={"localhost",PORT_DEFAULT,"","",""};
int select_refresh_time=0;

typedef struct {
  char name[20];
  char pass[20];
} USERS_INFO;

USERS_INFO *userlist=NULL;
int userlist_count=0;

static  time_t	sqlres_check_time;
static	pthread_rwlock_t	sql_lock;

static	char	*authreq = NULL;
static	int	 authreqlen;
static	char	*authreqfmt = "%s realm=%s";
static	char	*std_template = 
              "\n<body>Authorization to proxy-server failed.<p><hr>\n"
              "<i><font size=-1>by \'passwd_pgsql\' module to Oops.";
static	int	std_template_len;
static	int	pwf_charset_len;
static	int	badschlen;
static	char	*badsch=NULL;
static	char	*badschfmt =
               "HTTP/1.0 407 Proxy Authentication required\n"
               "Proxy-Authenticate: %s realm=%s\n\n"
               "<body>Authorization to proxy-server failed.<p>\n"
               "Your browser proposed unsupported scheme\n"
               "<hr>\n"
               "<i><font size=-1>by \'passwd_file\' module to Oops.";
static char *logbuf=NULL;

#define	RDLOCK_PWF_CONFIG	pthread_rwlock_rdlock(&pwf_lock)
#define	WRLOCK_PWF_CONFIG	pthread_rwlock_wrlock(&pwf_lock)
#define	UNLOCK_PWF_CONFIG	pthread_rwlock_unlock(&pwf_lock)

#define	RDLOCK_SELECT	pthread_rwlock_rdlock(&sql_lock)
#define	WRLOCK_SELECT	pthread_rwlock_wrlock(&sql_lock)
#define	UNLOCK_SELECT	pthread_rwlock_unlock(&sql_lock)

static void     check_age_and_reload(void);
static void     reload_pwf_file(PWF_FILEINFO *fi);
static void     make_sqlselect(void);

static	int	auth_check_user(char * user, char * pass);
static	void	send_auth_req(int, struct request *);

MODULE_STATIC
int mod_run(void)
{
    return(MOD_CODE_OK);
}

MODULE_STATIC
int mod_load(void)
{
#if	defined(__PGSQL)
    snprintf(module_info, sizeof(module_info)-1, MODULE_INFO,
	     PG_RELEASE, PG_VERSION, PG_SUBVERSION);
#elif	defined(__MYSQL)
    snprintf(module_info, sizeof(module_info)-1, MODULE_INFO,
	     MYSQL_SERVER_VERSION);
#endif

    pthread_rwlock_init(&pwf_lock, NULL);
    pthread_rwlock_init(&sql_lock, NULL);
    std_template_len = strlen(std_template);
    logbuf=malloc(8*1024);

    printf(MODULE_INFO " started\n");

    return(MOD_CODE_OK);
}

MODULE_STATIC
int mod_unload(void)
{
    if (logbuf)         free(logbuf);
    if (template.data)  free(template.data);
    if (sqlselect.data) free(sqlselect.data);
    if (userlist)       free(userlist);
    printf(MODULE_INFO " stopped\n");
    return(MOD_CODE_OK);
}

MODULE_STATIC
int mod_config_beg(int i)
{
    WRLOCK_PWF_CONFIG ;
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "auth(): config_beg");
    if ( authreq )        free(authreq);  authreq = 0;
    if ( badsch )         free(badsch);   badsch = 0;
    if ( template.data )  free(template.data); template.data = 0;
    if ( sqlselect.data ) free(sqlselect.data); sqlselect.data = 0;

    pwf_name[0] = template.filename[0] = sqlselect.filename[0] = 0;
    pwf_charset[0]	= 0;
    pwf_mtime = template.mtime = sqlselect.mtime =0;
    scheme = Basic;
   
    pwf_check_time=sqlres_check_time =0;
    select_refresh_time=0;
    
    strcpy(sql.host,"localhost");
    sql.user[0]=sql.password[0]=sql.database[0]=0;
    
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int mod_config_end(int i)
{
char	*sch="None";
char    *p;

    WRLOCK_PWF_CONFIG ;
    
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "auth(): config_end");

    if      ( scheme == Basic ) sch = "Basic";
    else if ( scheme == Digest) sch = "Digest";
    authreqlen = 0;
    authreq = malloc(strlen(authreqfmt)+1+strlen(realm)+strlen(sch));
    if ( authreq ) {
	sprintf(authreq, authreqfmt, sch,realm);
	authreqlen = strlen(authreq);
    }

    badschlen = 0;
    badsch = malloc(strlen(badschfmt)+1+strlen(realm)+strlen(sch));
    if ( badsch ) {
	sprintf(badsch, badschfmt, sch, realm);
	badschlen = strlen(badsch);
    }
    if ((p=strchr(sql.host,':'))!=0) {
      *p++=0;  
#ifdef __MYSQL
      sql.port=atoi(p);
#else
      sql.port=p;
#endif
    }
    else {
      sql.port=PORT_DEFAULT;
    }

    UNLOCK_PWF_CONFIG ;

    RDLOCK_PWF_CONFIG ;
    reload_pwf_file(&template);
    reload_pwf_file(&sqlselect);
    make_sqlselect();
    UNLOCK_PWF_CONFIG ;

    return(MOD_CODE_OK);
}

static void
getstr_fromcfg(char *dststr,char *srcstr,int dstsize) 
{
    int lastchar;
    while (*srcstr && IS_SPACE(*srcstr) ) srcstr++;
    strncpy(dststr,srcstr,dstsize-1);
    dststr[dstsize-1]=0;
    if ((srcstr=strrchr(dststr,'#'))!=0) *srcstr=0;
    lastchar=strlen(dststr);
    while (lastchar>=0 && IS_SPACE(dststr[lastchar])) lastchar--;
    
}

static int
getint_fromcfg(char *srcstr) 
{
    int lastchar;
    while (*srcstr && IS_SPACE(*srcstr) ) srcstr++;
    return atoi(srcstr);
}

MODULE_STATIC
int mod_config(char *config, int i)
{
    char	*p = config;

    WRLOCK_PWF_CONFIG ;
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "auth(): config_");

    while( *p && IS_SPACE(*p) ) p++;
    if ( !strncasecmp(p, "host", 4) ) {
	getstr_fromcfg(sql.host,p += 4,sizeof(sql.host));
    } 
    else if ( !strncasecmp(p, "user", 4) ) {
	getstr_fromcfg(sql.user,p += 4,sizeof(sql.user));
    } 
    else if ( !strncasecmp(p, "password", 8) ) {
	getstr_fromcfg(sql.password,p += 8,sizeof(sql.password));
    } 
    else if ( !strncasecmp(p, "database", 8) ) {
	getstr_fromcfg(sql.database,p += 8,sizeof(sql.database));
    } 
    else if ( !strncasecmp(p, "refreshdb", 9) ) {
	select_refresh_time=getint_fromcfg(p+=9);
    } 
    else if ( !strncasecmp(p, "select", 6) ) {
	getstr_fromcfg(sqlselect.filename,p += 6,sizeof(sqlselect.filename));
    } 
    else if ( !strncasecmp(p, "template", 8) ) {
	getstr_fromcfg(template.filename,p += 8,sizeof(template.filename));
    } 
    else if ( !strncasecmp(p, "charset", 7) ) {
	p += 7;
	while (*p && IS_SPACE(*p) ) p++;
	sprintf(pwf_charset, "Content-Type: text/html; charset=%.20s\n", p);
	pwf_charset_len = strlen(pwf_charset);
    } else if ( !strncasecmp(p, "scheme", 6) ) {
	p += 6;
	while (*p && IS_SPACE(*p) ) p++;
	if ( !strcasecmp(p, "basic") )  scheme = Basic;
	else if ( !strcasecmp(p, "digest") ) scheme = Digest;
    } 

    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}


static void
check_age_and_reload(void)
{
/*
    if ((global_sec_timer - template.check_time) >= 60 && template.filename[0]) {
      reload_pwf_file(&template);
    }
    if ((global_sec_timer - sqlselect.check_time) >= 60 && sqlselect.filename[0]) {
      reload_pwf_file(&sqlselect);
      make_sqlselect();
    }
*/
    if (select_refresh_time && (global_sec_timer - sqlres_check_time) >= select_refresh_time ) {
      make_sqlselect();
    }
}

static void
reload_pwf_file(PWF_FILEINFO *fi)
{
struct	stat	sb;
int		rc, size, fd;
    rc = stat(fi->filename, &sb);
    if ( rc != -1 ) {
	if ( sb.st_mtime <= fi->mtime ) return;
	size = sb.st_size;
	if ( size <= 0 ) return;
	if ( fi->data) free(fi->data); fi->data = NULL;
	fi->data = xmalloc(size+1,"reload_pwf_template(): 1");
	if ( fi->data ) {
	    fd = open(fi->filename, O_RDONLY);
	    if ( fd != -1 ) {
		rc = read(fd, fi->data, size);
		if ( rc != size ) {
		    free(fi->data);fi->data = NULL;
		} 
		else {
		    fi->mtime = sb.st_mtime;
		    fi->check_time = global_sec_timer;
		    fi->len = size;
		    fi->data[size]=0;    
		}
		close(fd);
	    } else {
		free(fi->data); fi->data = NULL;
	    }
	}
    }
}

static void
righttrim(char *str)
{ 
    int i;
    for (i=strlen(str);i>0 && str[i-1]==' ';i--) ;
    str[i]=0;
}

static void
make_sqlselect(void)
{
    int i,rc=0;
#if defined(__PGSQL)
    PGconn	*conn=0;
    PGresult	*res=0;
#elif defined(__MYSQL)
    MYSQL	*mysql;
    MYSQL_FIELD *fields;
    MYSQL_RES   *rs;
    MYSQL_ROW    row;
#endif
    int loginfield_n,passfield_n;

    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "auth(): reload select");

    WRLOCK_SELECT;

    if (!sqlselect.data) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): Select not loaded\n");
	goto exit; 
    }
    
#if defined(__PGSQL)
    conn=PQsetdbLogin(sql.host,sql.port,NULL,NULL,
			sql.database,sql.user,sql.password);

    if (!conn || PQstatus(conn) == CONNECTION_BAD) {
        sprintf(logbuf,"make_sqlselect(): Connection to database '%s' failed (error=%s)\n",
               sql.database,PQerrorMessage(conn)
	);
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, logbuf);
	goto exit;
    }

    res = PQexec(conn,sqlselect.data);

    if (res==0) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,"make_sqlselect(): Result of select is null\n");
	PQfinish(conn);
	goto exit;
    } 
    if (PQresultStatus(res)!=PGRES_TUPLES_OK) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): select failed\n");
	goto pgsql_exit;
    }
    
    if (PQntuples(res)==0) goto pgsql_exit;
    
    loginfield_n=PQfnumber(res,"login");
    passfield_n=PQfnumber(res,"passwd");
    if (loginfield_n==-1 || passfield_n==-1) {
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): Error find field login,passwd inselect\n");
        goto pgsql_exit;
    }

    if (userlist_count<PQntuples(res)) {
	free(userlist);
	userlist=(USERS_INFO *)malloc(PQntuples(res)*sizeof(USERS_INFO));    
    }  
	
    if (!userlist) {
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): Error allocate memory for userinfo\n");
        goto pgsql_exit;
    }

    userlist_count=PQntuples(res);
	
    for (i=0;i<userlist_count;i++) {
	strcpy(userlist[i].name,PQgetvalue(res,i,loginfield_n));
	righttrim(userlist[i].name);
	strcpy(userlist[i].pass,PQgetvalue(res,i,passfield_n));  
	righttrim(userlist[i].pass);
    } 
    rc=1;
        
pgsql_exit:    
    PQclear(res); 
    PQfinish(conn);

#elif defined(__MYSQL)
    
    mysql=mysql_init(NULL);
    if (!mysql) {
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): Error init mysql\n");
	goto exit;
    }

    if (!mysql_real_connect(mysql,sql.host,sql.user,sql.password,sql.database,
	        	        sql.port, 0, 0)) 
    {
	sprintf(logbuf,"make_sqlselect(): Connection to database '%s' failed (error=%s)\n",
    	               sql.database,mysql_error(mysql)
	       );
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, logbuf);
        goto exit; 	
    }

    if (mysql_real_query(mysql, sqlselect.data, sqlselect.len)!=0) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): select failed\n");
	goto mysql_exit;
    }
    
    rs = mysql_store_result(mysql);
    
    if (mysql_num_rows(rs)==0) goto mysql_free_rs_exit;
    
    fields=mysql_fetch_fields(rs);
    if (!fields) {
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): Error get fields info\n");
        goto mysql_free_rs_exit;
    }
    loginfield_n=passfield_n=-1;
    for (i=0;i<mysql->field_count;i++) {
	  if      (strcmp(fields[i].name,"login")==0) loginfield_n=i;
	  else if (strcmp(fields[i].name,"passwd")==0) passfield_n=i;
    }
    if (loginfield_n==-1 || passfield_n==-1) {
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): Error find field login,passwd inselect\n");
        goto mysql_free_rs_exit;
    }

    if (userlist_count<	mysql_num_rows(rs)) {
	if (userlist) free(userlist);
	userlist=(USERS_INFO *)malloc(mysql_num_rows(rs)*sizeof(USERS_INFO));    
    }
    if (!userlist) {
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "make_sqlselect(): Error allocate memory for userinfo\n");
        goto mysql_free_rs_exit;
    }
    
    userlist_count=mysql_num_rows(rs);
    
    for (i=0;(i<userlist_count) && (row=mysql_fetch_row(rs));i++) {
	strcpy(userlist[i].name,row[loginfield_n]);
	righttrim(userlist[i].name);
	strcpy(userlist[i].pass,row[passfield_n]);  
	righttrim(userlist[i].pass);
    } 
    if (i<userlist_count)  userlist_count=i;

    rc=1;
    
mysql_free_rs_exit:
    mysql_free_result(rs);
    
mysql_exit:    
    
    mysql_close(mysql);
 
#endif
exit:
    if (!rc) {
      if (userlist) free(userlist);
      userlist=0;
      userlist_count=0;
    }
    sqlres_check_time=global_sec_timer;
    UNLOCK_SELECT;
}

MODULE_STATIC
int auth(int so, struct group *group, struct request* rq, int *flags) 
{
    char	*authorization = NULL;

    if ( !authreq ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "auth(): Something wrong with passwd_pgsql module.\n");
	return(MOD_CODE_OK);
    }

    if (!logbuf) return(MOD_CODE_ERR);

    sprintf(logbuf,"auth(): request: "
                 "ip=%d.%d.%d.%d host=%s method=%s\n",
		 (rq->client_sa.sin_addr.s_addr      ) & 0xff,
		 (rq->client_sa.sin_addr.s_addr >>  8) & 0xff,
		 (rq->client_sa.sin_addr.s_addr >> 16) & 0xff,
		 (rq->client_sa.sin_addr.s_addr >> 24) & 0xff,
		 rq->url.host,
		 rq->method
	    );
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM,logbuf);

    if ( rq->av_pairs)
	authorization = attr_value(rq->av_pairs, "Proxy-Authorization");
	
    WRLOCK_PWF_CONFIG ;
    check_age_and_reload();
    UNLOCK_PWF_CONFIG;

    RDLOCK_PWF_CONFIG ;

    if ( !authorization ) {
	/* send 407 Proxy Authentication Required */
	goto au_f;
    } 

    if ( !strncasecmp(authorization, "Basic", 5 ) ) {
	  int	 rc;
	  char	*u=NULL, *p;
	  char  *data = authorization + 5;
	    while ( *data && IS_SPACE(*data) ) data++;
	    if ( *data ) u = base64_decode(data);
	    if ( u ) {
		/* up = username:password */
		p = strchr(u, ':');
		if ( p ) { *p=0; p++; }
	        if ( auth_check_user(u, p) ) {
		    IF_STRDUP(rq->proxy_user, u);
		    free(u);
		    goto au_ok;
		}
		free(u);
  	    } 
	    goto au_f;
    } 
    else {
        /* we do not support any schemes except Basic */
	if ( badsch ) {
	    writet(so, badsch, badschlen, 30);
	    SET(*flags, MOD_AFLAG_OUT);
	}
	UNLOCK_PWF_CONFIG ;
	return(MOD_CODE_ERR);
    }    
au_f: 
    send_auth_req(so, rq);
    SET(*flags, MOD_AFLAG_OUT);
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_ERR);
    
au_ok:
    SET(*flags, MOD_AFLAG_CKACC);
    UNLOCK_PWF_CONFIG ;
    return(MOD_CODE_OK);
}

static int
auth_check_user(char *user, char *pass)
{
    int i=0;
    if (!user || !pass) {
        my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "auth_check_user(): Bad user or pass\n");
        return 0;
    }

    RDLOCK_SELECT;
    if (userlist) {

	while(i<userlist_count) {
	    if (strcmp(userlist[i].name,user)==0 &&
		strcmp(userlist[i].pass,pass)==0
	       ) { 
	        UNLOCK_SELECT;
		return 1;  
	    }
	    i++;
	}
	    
    }
    UNLOCK_SELECT;
    return 0;
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

    if ( !template.data ) body = alloc_buff(std_template_len);
    else	          body = alloc_buff(template.len);
    if ( body ) {
	obj->body = body;
	if ( !template.data )
		rc = attach_data(std_template, std_template_len, body);
	    else
		rc = attach_data(template.data, template.len, body);
        if ( !rc )
		process_output_object(so, obj, rq);
    }

    free_output_obj(obj);
    return;
}
#else
struct	auth_module STRUCT_NAME = {
	{
	NULL, NULL,
	MODULE_NAME,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	MODULE_AUTH,
	MODULE_INFO,
	NULL
	},
	NULL
};
#endif
