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

#include "../oops.h"
#include "../modules.h"

#define	MODULE_NAME	"berkeley_db"
#define	MODULE_INFO	"BerkeleyDB %d.%d.%d API"
#define	MODULE_BR14	"BerkeleyDB API/stopper"

#if	defined(MODULES)
char		module_type 		= MODULE_DB_API;
char		module_info[MODINFOLEN] = MODULE_BR14;
char		module_name[]		= MODULE_NAME;
#define		MODULE_STATIC
#else
static	char	module_type 		= MODULE_DB_API;
static	char	module_info[MODINFOLEN] = MODULE_BR14;
static	char	module_name[]		= MODULE_NAME;
#define		MODULE_STATIC	static
#endif

#if	defined(HAVE_BERKELEYDB)
#include	<db.h>

#if	defined(MODULES)
int		mod_run(void);
int		mod_load(void);
int		mod_unload(void);
int		mod_config_beg(int), mod_config_end(int), mod_config(char*, int), mod_run(void);
int		db_api_open(int*), db_api_close(void);
int		db_api_get(db_api_arg_t*, db_api_arg_t*, int*);
int		db_api_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*, int*);
int		db_api_del(db_api_arg_t*, int*);
int		db_api_sync(int *);
void*		db_api_cursor_open(int, int*);
int		db_api_cursor_get(void*, db_api_arg_t*, db_api_arg_t*, int*);
int		db_api_cursor_del(void*, int*);
int		db_api_cursor_close(void*, int*);
#else
static	int	mod_run(void);
static	int	mod_load(void);
static	int	mod_unload(void);
static	int	mod_config_beg(int), mod_config_end(int), mod_config(char*,int), mod_run(void);
static	int	db_api_open(int*), db_api_close(void);
static	int	db_api_get(db_api_arg_t*, db_api_arg_t*, int*);
static	int	db_api_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*, int*);
static	int	db_api_del(db_api_arg_t*, int*);
static	int	db_api_sync(int *);
static	void*	db_api_cursor_open(int, int*);
static	int	db_api_cursor_get(void*, db_api_arg_t*, db_api_arg_t*, int*);
static	int	db_api_cursor_del(void*, int*);
static	int	db_api_cursor_close(void*, int*);
#endif

struct	db_api_module	berkeley_db_api = {
	{
	    NULL, NULL,
	    MODULE_NAME,
	    mod_load,
	    mod_unload,
	    mod_config_beg,
	    mod_config_end,
	    mod_config,
	    NULL,
	    MODULE_DB_API,
	    MODULE_INFO,
	    mod_run
	},
	db_api_open,
	db_api_close,
	db_api_get,
	db_api_put,
	db_api_del,
	db_api_cursor_open,
	db_api_cursor_get,
	db_api_cursor_del,
	db_api_cursor_close,
	db_api_sync
};

static	DB_ENV                  *dbenv;
#if     DB_VERSION_MAJOR < 3
static	DB_INFO                 dbinfo;
#endif
static	DB                      *dbp;
static	char			dbhome[MAXPATHLEN];
static	char			dbname[MAXPATHLEN];
static	size_t			db_cache_mem_val;

#define	DB_VERSION_IN_USE	(DB_VERSION_MAJOR*100+DB_VERSION_MINOR)

#if	DB_VERSION_IN_USE >= 302
static  int     my_bt_compare(DB*, const DBT*, const DBT*);
#else
static  int     my_bt_compare(const DBT*, const DBT*);
#endif

static	pthread_rwlock_t	bdb_config_lock;

#define	RDLOCK_BDB_CONFIG	pthread_rwlock_rdlock(&bdb_config_lock)
#define WRLOCK_BDB_CONFIG	pthread_rwlock_wrlock(&bdb_config_lock)
#define UNLOCK_BDB_CONFIG	pthread_rwlock_unlock(&bdb_config_lock)


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
    int major, minor, patch;

    major = DB_VERSION_MAJOR;
    minor = DB_VERSION_MINOR;
    patch = DB_VERSION_PATCH;
    snprintf(module_info, sizeof(module_info)-1, MODULE_INFO,
	     major, minor, patch);

    dbp		= NULL;
    dbenv	= NULL;
    dbhome[0]	= 0;
    dbname[0]	= 0;
    db_cache_mem_val = 4 * 1024 * 1024;
    pthread_rwlock_init(&bdb_config_lock, NULL);

    printf("%s started\n", module_name);

    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_unload(void)
{
    printf("%s stopped\n", module_name);
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_beg(int i)
{
    WRLOCK_BDB_CONFIG ;
    if ( dbp ) {
	dbp->close(dbp, 0);
	dbp = NULL;
    }
#if     DB_VERSION_MAJOR < 3
    if ( dbhome[0] && dbenv && db_appexit(dbenv) ) {
	my_xlog(OOPS_LOG_SEVERE, "main(): db_appexit failed.\n");
    }
    if ( dbenv ) free(dbenv);
#else
    if ( dbenv ) dbenv->close(dbenv,0);
#endif
    dbenv = NULL;
    db_cache_mem_val = 4 * 1024 * 1024;
    UNLOCK_BDB_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config_end(int i)
{
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
mod_config(char *config, int i)
{
char	*p = config;

    WRLOCK_BDB_CONFIG ;
    while( *p && IS_SPACE(*p) ) p++;
    if ( !strncasecmp(p, "dbhome", 6) ) {
	p += 6;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(dbhome, p, sizeof(dbhome)-1);
    } else
    if ( !strncasecmp(p, "dbname", 6) ) {
	p += 6;
	while (*p && IS_SPACE(*p) ) p++;
	strncpy(dbname, p, sizeof(dbname)-1);
    }
    if ( !strncasecmp(p, "db_cache_mem", 12) ) {
	int	scale = 1;

	p += 12;
	while (*p && IS_SPACE(*p) ) p++;
	db_cache_mem_val = atoi(p);
	if ( strchr(p, 'k') || strchr(p,'K') ) scale = 1024;
	if ( strchr(p, 'm') || strchr(p,'M') ) scale = 1024*1024;
	if ( strchr(p, 'g') || strchr(p,'G') ) scale = 1024*1024;
	db_cache_mem_val *= scale;
    }
    UNLOCK_BDB_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
db_api_open(int *aflag)
{
int	rc;

    WRLOCK_BDB_CONFIG ;
    if ( !dbhome[0] || !dbname[0] ) {
	UNLOCK_BDB_CONFIG ;
	return(MOD_CODE_OK);
    }
    printf("BerkeleyDB interface\n");
    my_xlog(OOPS_LOG_STOR, "db_api_open()\n");

    dbp = NULL;
#if	DB_VERSION_MAJOR < 3
    dbenv = calloc(sizeof(*dbenv),1);
    bzero(&dbinfo, sizeof(dbinfo));
    dbinfo.db_cachesize = db_cache_mem_val;
    dbinfo.db_pagesize = OOPS_DB_PAGE_SIZE;
    dbinfo.bt_compare = my_bt_compare;
    if (db_appinit(dbhome, NULL, dbenv,
		DB_CREATE|DB_THREAD) ) {
		my_xlog(OOPS_LOG_SEVERE, "open_db(): db_appinit(%s) failed: %m\n", dbhome);
    }
    if ( (rc = db_open(dbname, DB_BTREE,
    		DB_CREATE|DB_THREAD,
    		0644,
    		dbenv,
    		&dbinfo,
    		&dbp)) != 0 ) {
	my_xlog(OOPS_LOG_SEVERE, "open_db(): db_open(%s): %d %m\n", dbname, rc);
	dbp = NULL;
    }
#else	/* Berkeley DB >= 3.x.x */
    if ( db_env_create(&dbenv, 0) )
	return(MOD_CODE_ERR);
    dbenv->set_errfile(dbenv, stderr);
    dbenv->set_errpfx(dbenv, "oops");
    dbenv->set_cachesize(dbenv, 0, db_cache_mem_val, 0);
    rc = dbenv->open(dbenv, dbhome,
#if	DB_VERSION_MAJOR == 3 && DB_VERSION_MINOR == 0
	NULL,
#endif
	DB_CREATE|DB_THREAD|DB_PRIVATE|DB_INIT_MPOOL,
	0);
    if ( rc ) {
	my_xlog(OOPS_LOG_SEVERE, "open_db(): Can't open dbenv.\n");
	dbenv->close(dbenv, 0); dbenv = NULL;
	UNLOCK_BDB_CONFIG ;
	return(MOD_CODE_ERR);
    }
    rc = db_create(&dbp, dbenv, 0);
    if ( rc ) {
	dbenv->close(dbenv, 0); dbenv = NULL;
	dbp = NULL;
	UNLOCK_BDB_CONFIG ;
	return(MOD_CODE_ERR);
    }
    dbp->set_bt_compare(dbp, my_bt_compare);
    dbp->set_pagesize(dbp, OOPS_DB_PAGE_SIZE);
    rc = dbp->open(dbp,
        #if DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR > 0
        NULL,
        #endif
        dbname,
        NULL, 
        DB_BTREE, DB_CREATE, 0);
    if ( rc ) {
	my_xlog(OOPS_LOG_SEVERE, "open_db(): dbp->open(%s): (%d)\n", dbname, rc);
	dbenv->close(dbenv, 0); dbenv = NULL;
	dbp = NULL;
	UNLOCK_BDB_CONFIG ;
	return(MOD_CODE_ERR);
    }
#endif
    printf("BerkeleyDB opened successfully\n");
    *aflag = MOD_AFLAG_BRK;
    UNLOCK_BDB_CONFIG ;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
db_api_close(void)
{
    WRLOCK_BDB_CONFIG ;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG ;
	return(MOD_CODE_OK);
    }
    my_xlog(OOPS_LOG_STOR, "db_api_close()\n");
    if ( dbp ) {
	dbp->sync(dbp, 0);
	dbp->close(dbp, 0);
	dbp = NULL;
    }
#if     DB_VERSION_MAJOR < 3
    if ( dbhome[0] && dbenv && db_appexit(dbenv) ) {
	my_xlog(OOPS_LOG_SEVERE, "db_api_close(): db_appexit failed.\n");
    }
    if ( dbenv ) free(dbenv);
#else
    if ( dbenv )
        dbenv->close(dbenv,0);
#endif
    dbenv = NULL;
    UNLOCK_BDB_CONFIG ;
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "BerkeleyDB closed\n");
    printf("BerkeleyDB closed\n");
    return(MOD_CODE_OK);
}

/* take key from arg, return result in res
   return code is in res->flag
*/

MODULE_STATIC
int
db_api_get(db_api_arg_t *arg, db_api_arg_t *res, int *aflag)
{
DBT	key, data;
int	rc;

    if ( !arg || !res ) return(MOD_CODE_ERR);
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    bzero(res, sizeof(*res));
    bzero(&key, sizeof(key));
    bzero(&data, sizeof(data));
    key.data = arg->data;
    key.size = arg->size;
    data.flags = DB_DBT_MALLOC;
    rc = dbp->get(dbp, NULL, &key, &data, 0);
    switch ( rc ) {
	case 0:
	    res->data = data.data;
	    res->size = data.size;
	    res->flags= DB_API_RES_CODE_OK;
	    break;
	case DB_NOTFOUND:
	    res->flags= DB_API_RES_CODE_NOTFOUND;
	    break;
	default:
	    res->flags= DB_API_RES_CODE_ERR;
	    break;
    }
    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
db_api_put(db_api_arg_t *key, db_api_arg_t *data, struct mem_obj *obj,int *aflag)
{
DBT	dbkey, dbdata;
int	rc;

    if ( !key || !data ) return(MOD_CODE_ERR);
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    bzero(&dbkey, sizeof(dbkey));
    bzero(&dbdata, sizeof(dbdata));
    dbkey.data = key->data;
    dbkey.size = key->size;
    dbdata.data = data->data;
    dbdata.size = data->size;
    rc = dbp->put(dbp, NULL, &dbkey, &dbdata, DB_NOOVERWRITE);
    switch ( rc ) {
	case 0:
	    data->flags = 0;
	    break;
	case DB_KEYEXIST:
	    data->flags = DB_API_RES_CODE_EXIST;
	    break;
	default:
	    data->flags = DB_API_RES_CODE_ERR;
	    break;
    }
    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
db_api_del(db_api_arg_t *key, int *aflag)
{
DBT	dbkey;
int	rc;

    if ( !key ) return(MOD_CODE_ERR);
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    bzero(&dbkey, sizeof(dbkey));
    dbkey.data = key->data;
    dbkey.size = key->size;
    rc = dbp->del(dbp, NULL, &dbkey, 0);
    switch ( rc ) {
	case 0:
	    key->flags= DB_API_RES_CODE_OK;
	    break;
	case DB_NOTFOUND:
	    key->flags= DB_API_RES_CODE_NOTFOUND;
	    break;
	default:
	    key->flags= DB_API_RES_CODE_ERR;
	    break;
    }
    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    return(MOD_CODE_OK);
}

MODULE_STATIC
void*	db_api_cursor_open(int type, int* aflag)
{
int	rc;
DBC	*dbcp;
void	*res = NULL;

    my_xlog(OOPS_LOG_STOR, "db_api_cursor_open()\n");
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    rc = dbp->cursor(dbp, NULL, &dbcp
#if     DB_VERSION_IN_USE >= 206
					, 0
#endif
					);

    if ( !rc )
	res = dbcp;

    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    my_xlog(OOPS_LOG_STOR, "db_api_cursor_open'ed()=%p\n", res);
    return(res);
}

MODULE_STATIC
int
db_api_cursor_close(void *cursor, int *aflag)
{
DBC	*dbcp = (DBC*)cursor;

    my_xlog(OOPS_LOG_STOR, "db_api_cursor_close(%p)\n", cursor);
    if ( !dbcp ) return(MOD_CODE_ERR);
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    dbcp->c_close(dbcp);
    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
db_api_cursor_get(void *cursor, db_api_arg_t *key, db_api_arg_t *data, int *aflag)
{
DBT	dbkey,dbdata;
DBC	*dbcp = (DBC*)cursor;
int	rc;

    if ( !dbcp ) return(MOD_CODE_ERR);
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    bzero(&dbkey, sizeof(dbkey));
    bzero(&dbdata, sizeof(dbdata));
    dbkey.flags = dbdata.flags = DB_DBT_MALLOC;
    rc = dbcp->c_get(dbcp, &dbkey, &dbdata, DB_NEXT);
    if ( !rc ) {
	key->data  = dbkey.data;
	key->size  = dbkey.size;
	data->data = dbdata.data;
	data->size = dbdata.size;
    } else {
	my_xlog(OOPS_LOG_STOR, "dbcp->get: %d\n", rc);
	key->data = data->data = NULL;
	key->size = data->size = 0;
	if ( rc == DB_NOTFOUND )
		data->flags = DB_API_RES_CODE_NOTFOUND ;
	   else
		data->flags = DB_API_RES_CODE_ERR ;
    }
    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
db_api_cursor_del(void *cursor, int *aflag)
{
DBC	*dbcp = (DBC*)cursor;

    if ( !dbcp ) return(MOD_CODE_ERR);
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    dbcp->c_del(dbcp, 0);
    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    return(MOD_CODE_OK);
}

MODULE_STATIC
int
db_api_sync(int *aflag)
{
    my_xlog(OOPS_LOG_STOR, "db_api_sync()\n");
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    dbp->sync(dbp, 0);
    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    return(MOD_CODE_OK);
}

int
#if	DB_VERSION_IN_USE >= 302
my_bt_compare(DB* db, const DBT* a, const DBT* b)
#else
my_bt_compare(const DBT* a, const DBT* b)
#endif
{
    if ( a->size != b->size ) return(a->size-b->size);
    if ( a->size == 0 ) return(0);
    return(memcmp(a->data, b->data, a->size));
}
#else
#if	!defined(MODULES)
struct	db_api_module	berkeley_db_api = {
	{
	    NULL, NULL,
	    MODULE_NAME,
	    NULL,
	    NULL,
	    NULL,
	    NULL,
	    NULL,
	    NULL,
	    NULL,
	    MODULE_INFO,
	    NULL
	},
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif /*MODULES*/
#endif
