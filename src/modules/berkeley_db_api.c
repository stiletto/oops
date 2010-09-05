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
#define	MODULE_INFO	"BerkeleyDB API"

#if	defined(MODULES)
char		module_type 	= MODULE_DB_API;
char		module_info[]	= MODULE_INFO  ;
char		module_name[]	= MODULE_NAME  ;
#else
static	char	module_type 	= MODULE_DB_API ;
static	char	module_info[]	= MODULE_INFO	;
static	char	module_name[]	= MODULE_NAME	;
#endif

#if	defined(HAVE_BERKELEYDB)
#include	<db.h>

#if	defined(MODULES)
int		mod_run();
int		mod_load();
int		mod_unload();
int		mod_config_beg(), mod_config_end(), mod_config(), mod_run();
int		db_api_open(int*), db_api_close();
int		db_api_get(db_api_arg_t*, db_api_arg_t*, int*);
int		db_api_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*, int*);
int		db_api_del(db_api_arg_t*, int*);
int		db_api_sync();
void*		db_api_cursor_open(int, int*);
int		db_api_cursor_get(void*, db_api_arg_t*, db_api_arg_t*, int*);
int		db_api_cursor_del(void*, int*);
int		db_api_cursor_close(void*, int*);
#else
static	int	mod_run();
static	int	mod_load();
static	int	mod_unload();
static	int	mod_config_beg(), mod_config_end(), mod_config(), mod_run();
static	int	db_api_open(int*), db_api_close();
static	int	db_api_get(db_api_arg_t*, db_api_arg_t*, int*);
static	int	db_api_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*, int*);
static	int	db_api_del(db_api_arg_t*, int*);
static	int	db_api_sync();
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
#if     DB_VERSION_MAJOR<3
static	DB_INFO                 dbinfo;
#endif
static	DB                      *dbp;
static	char			dbhome[MAXPATHLEN];
static	char			dbname[MAXPATHLEN];
static	size_t			db_cache_mem_val;

static  int     my_bt_compare(const DBT*, const DBT*);

static	pthread_rwlock_t	bdb_config_lock;

#define	RDLOCK_BDB_CONFIG	pthread_rwlock_rdlock(&bdb_config_lock)
#define WRLOCK_BDB_CONFIG	pthread_rwlock_wrlock(&bdb_config_lock)
#define UNLOCK_BDB_CONFIG	pthread_rwlock_unlock(&bdb_config_lock)


int
mod_run()
{
    return(MOD_CODE_OK);
}

int
mod_load()
{
    printf("%s started\n", module_name);
    dbp		= NULL;
    dbenv	= NULL;
    dbhome[0]	= 0;
    dbname[0]	= 0;
    db_cache_mem_val = 4 * 1024 * 1024;
    pthread_rwlock_init(&bdb_config_lock, NULL);
    return(MOD_CODE_OK);
}

int
mod_unload()
{
    printf("%s stopped\n", module_name);
    return(MOD_CODE_OK);
}

int
mod_config_beg()
{
    WRLOCK_BDB_CONFIG ;
    if ( dbp ) {
	dbp->close(dbp, 0);
	dbp = NULL;
    }
#if     DB_VERSION_MAJOR<3
    if ( dbhome[0] && dbenv && db_appexit(dbenv) ) {
	my_xlog(LOG_SEVERE, "main(): db_appexit failed.\n");
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

int
mod_config_end()
{
    return(MOD_CODE_OK);
}
int
mod_config(char *config)
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
    my_xlog(LOG_STOR, "db_api_open()\n");

    dbp = NULL;
#if	DB_VERSION_MAJOR<3
    dbenv = calloc(sizeof(*dbenv),1);
    bzero(&dbinfo, sizeof(dbinfo));
    dbinfo.db_cachesize = db_cache_mem_val;
    dbinfo.db_pagesize = OOPS_DB_PAGE_SIZE;
    dbinfo.bt_compare = my_bt_compare;
    if (db_appinit(dbhome, NULL, dbenv,
		DB_CREATE|DB_THREAD) ) {
		my_xlog(LOG_SEVERE, "open_db(): db_appinit(%s) failed: %m\n", dbhome);
    }
    if ( (rc = db_open(dbname, DB_BTREE,
    		DB_CREATE|DB_THREAD,
    		0644,
    		dbenv,
    		&dbinfo,
    		&dbp)) != 0 ) {
	my_xlog(LOG_SEVERE, "open_db(): db_open(%s): %d %m\n", dbname, rc);
	dbp = NULL;
    }
#else
    if ( db_env_create(&dbenv, 0) )
	return(MOD_CODE_ERR);
    dbenv->set_errfile(dbenv, stderr);
    dbenv->set_errpfx(dbenv, "oops");
    dbenv->set_cachesize(dbenv, 0, db_cache_mem_val, 0);
    rc = dbenv->open(dbenv, dbhome,
#if	DB_VERSION_MAJOR==3 && DB_VERSION_MINOR==0
	NULL,
#endif
	DB_CREATE|DB_THREAD|DB_INIT_MPOOL|DB_PRIVATE,
	0);
    if ( rc ) {
	my_xlog(LOG_SEVERE, "open_db(): Can't open dbenv.\n");
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
    rc = dbp->open(dbp, dbname, NULL, DB_BTREE, DB_CREATE, 0);
    if ( rc ) {
	my_xlog(LOG_SEVERE, "open_db(): dbp->open(%s): (%d)\n", dbname, rc);
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
int
db_api_close()
{
    WRLOCK_BDB_CONFIG ;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG ;
	return(MOD_CODE_OK);
    }
    printf("db_api_close()\n");
    my_xlog(LOG_STOR, "db_api_close()\n");
    if ( dbp ) {
	dbp->sync(dbp, 0);
	dbp->close(dbp, 0);
	dbp = NULL;
    }
#if     DB_VERSION_MAJOR<3
    if ( dbhome[0] && dbenv && db_appexit(dbenv) ) {
	my_xlog(LOG_SEVERE, "main(): db_appexit failed.\n");
    }
    if ( dbenv ) free(dbenv);
#else
    if ( dbenv )
        dbenv->close(dbenv,0);
#endif
    dbenv = NULL;
    UNLOCK_BDB_CONFIG ;
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "BerkeleyDB closed\n");
    return(MOD_CODE_OK);
}

/* take key from arg, return result in res
   return code is in res->flag
*/

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

void*	db_api_cursor_open(int type, int* aflag)
{
int	rc;
DBC	*dbcp;
void	*res = NULL;

    my_xlog(LOG_STOR, "db_api_cursor_open()\n");
    RDLOCK_BDB_CONFIG;
    if ( !dbp ) {
	UNLOCK_BDB_CONFIG;
	return(MOD_CODE_OK);
    }
    rc = dbp->cursor(dbp, NULL, &dbcp
#if     (DB_VERSION_MAJOR>2) || (DB_VERSION_MINOR>=6)
					, 0
#endif
					);

    if ( !rc )
	res = dbcp;

    UNLOCK_BDB_CONFIG;
    *aflag = MOD_AFLAG_BRK;
    my_xlog(LOG_STOR, "db_api_cursor_open'ed()=%p\n", res);
    return(res);
}

int
db_api_cursor_close(void *cursor, int *aflag)
{
DBC	*dbcp = (DBC*)cursor;

    my_xlog(LOG_STOR, "db_api_cursor_close(%p)\n", cursor);
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
	my_xlog(LOG_STOR, "dbcp->get: %d\n", rc);
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

int
db_api_sync(int *aflag)
{
    my_xlog(LOG_STOR, "db_api_sync()\n");
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
my_bt_compare(const DBT* a, const DBT* b)
{
    if ( a->size != b->size ) return(a->size-b->size);
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
