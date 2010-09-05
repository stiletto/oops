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

#define	NO_NEED_XMALLOC		1
#define	_LIB_H_INCLUDED_	1

#if	defined(SOLARIS)
#undef  _LARGEFILE_SOURCE
#undef  WITH_LARGE_FILES
#undef  _FILE_OFFSET_BITS
#endif

#if	defined(_AIX)
#undef  _LARGE_FILES
#undef  _LARGE_FILE_API
#undef  WITH_LARGE_FILES
#endif

#include "../oops.h"
#include "../modules.h"

#if !defined(HAVE_SNPRINTF)
extern "C" int snprintf(char *str, size_t size, const char *format, ...);
#endif


#define	MODULE_NAME	"gigabase_db"
#define	MODULE_INFO	"GigaBASE %d.%d API"
#define	MODULE_BR14	"GigaBASE API/stopper"

#if	defined(MODULES)
char		module_type 		= MODULE_DB_API;
char		module_info[MODINFOLEN] = MODULE_BR14;
char		module_name[]		= MODULE_NAME;
#else
static	char	module_type 		= MODULE_DB_API;
static	char	module_info[MODINFOLEN] = MODULE_BR14;
static	char	module_name[]		= MODULE_NAME;
#endif

#if	defined(HAVE_GIGABASE)
#include <gigabase.h>

#define	COMMIT_DELAY	180

#if	defined(MODULES)
extern	"C" {
int		mod_run(void);
int		mod_load(void);
int		mod_unload(void);
int		mod_config_beg(int), mod_config_end(int), mod_config(char*,int);
int		db_api_open(int*), db_api_close(void);
int		db_api_get(db_api_arg_t*, db_api_arg_t*, int*);
int		db_api_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*,int*);
int		db_api_del(db_api_arg_t*, int*);
int		db_api_sync(void);
void*		db_api_cursor_open(int, int*);
int		db_api_cursor_get(void*, db_api_arg_t*, db_api_arg_t*, int*);
int		db_api_cursor_del(void*, int*);
int		db_api_cursor_close(void*, int*);
int		db_api_cursor_freeze(void*, int*);
int		db_api_cursor_unfreeze(void*, int*);
int		db_api_attach(int*);
int		db_api_detach(int*);
int		db_api_precommit(int*);
}
#else
extern	"C" {
static	int	mod_run(void);
static	int	mod_load(void);
static	int	mod_unload(void);
static	int	mod_config_beg(int), mod_config_end(int), mod_config(char*,int);
static	int	db_api_open(int*), db_api_close(void);
static	int	db_api_get(db_api_arg_t*, db_api_arg_t*, int*);
static	int	db_api_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*, int*);
static	int	db_api_del(db_api_arg_t*, int*);
static	int	db_api_sync(void);
static	void*	db_api_cursor_open(int, int*);
static	int	db_api_cursor_get(void*, db_api_arg_t*, db_api_arg_t*, int*);
static	int	db_api_cursor_del(void*, int*);
static	int	db_api_cursor_close(void*, int*);
static	int	db_api_cursor_freeze(void*, int*);
static	int	db_api_cursor_unfreeze(void*, int*);
static	int	db_api_attach(int*);
static	int	db_api_detach(int*);
static	int	db_api_precommit(int*);
}
#endif

struct	db_api_module	gigabase_db_api = {
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
	db_api_sync,
	db_api_attach,
	db_api_detach,
	db_api_precommit,
	db_api_cursor_freeze,
	db_api_cursor_unfreeze
};


class	URL_Info {
    public:
	char*			url;
	int			accessed;
	struct	disk_ref	disk_ref;
	dbArray<int8>		blocks;

    TYPE_DESCRIPTOR((
		    KEY(url, INDEXED|HASHED),
		    FIELD(accessed),
		    RAWFIELD(disk_ref),
		    FIELD(blocks)
			));
};

REGISTER(URL_Info);

static	dbDatabase	*db = NULL;

struct dbcp_ {
	dbCursor<URL_Info>	*cursor;
	int			next_status;
	int			type;
};
typedef	struct	dbcp_	dbcp_t;

static	int			gdb_in_use = FALSE;
static	char			dbhome[MAXPATHLEN];
static	char			dbname[MAXPATHLEN];
static	int			db_cache_mem;
static  pthread_rwlock_t	giga_db_config_lock;

#define RDLOCK_GDB_CONFIG       pthread_rwlock_rdlock(&giga_db_config_lock)
#define WRLOCK_GDB_CONFIG       pthread_rwlock_wrlock(&giga_db_config_lock)
#define UNLOCK_GDB_CONFIG       pthread_rwlock_unlock(&giga_db_config_lock)

int
mod_run(void)
{
    return(MOD_CODE_OK);
}

int
mod_load(void)
{
#if	defined(GIGABASE_MAJOR_VERSION)
    snprintf(module_info, sizeof(module_info)-1, MODULE_INFO,
             GIGABASE_MAJOR_VERSION, GIGABASE_MINOR_VERSION);
#else
#define	GIGABASE_MAJOR_VERSION	(int)(GIGABASE_VERSION/100)
#define	GIGABASE_MINOR_VERSION	(int)(GIGABASE_VERSION%100)
    snprintf(module_info, sizeof(module_info)-1, MODULE_INFO,
             GIGABASE_MAJOR_VERSION, GIGABASE_MINOR_VERSION);
#endif

    dbname[0] = dbhome[0] = 0;
    gdb_in_use = FALSE;
    pthread_rwlock_init(&giga_db_config_lock, NULL);

    printf("%s started\n", module_name);

    return(MOD_CODE_OK);
}

int
mod_unload(void)
{
    printf("%s stopped\n", module_name);
    return(MOD_CODE_OK);
}

int
mod_config_beg(int instance)
{
    WRLOCK_GDB_CONFIG ;
    dbname[0] = dbhome[0] = 0;
    db_cache_mem = 1024;
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
mod_config_end(int instance)
{
    if ( db_cache_mem < 1024 ) 
	db_cache_mem = 1024;
    return(MOD_CODE_OK);
}

int
mod_config(char *config, int instance)
{
char	*p = config;

    while( *p && IS_SPACE(*p) ) p++;
    WRLOCK_GDB_CONFIG ;
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
	p += 12;
	while (*p && IS_SPACE(*p) ) p++;
	if ( strlen(p) > 0 ) {
	    db_cache_mem = atoi(p);
	    if (tolower(p[strlen(p)-1]) == 'k') db_cache_mem *= 1024;
	    if (tolower(p[strlen(p)-1]) == 'm') db_cache_mem *= 1024*1024;
	    db_cache_mem /= dbPageSize; /* gigabase accept this in pages */
	}
    }
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
db_api_open(int *aflag)
{

    WRLOCK_GDB_CONFIG ;
    if ( !dbhome[0] || !dbname[0] ) {
        UNLOCK_GDB_CONFIG ;
	return(MOD_CODE_OK);
    }
    printf("GigaBASE interface\n");
    my_xlog(OOPS_LOG_STOR, "db_api_open()\n");

    if ( gdb_in_use == TRUE ) {
	db->close();
	delete db;
	db = NULL;
	gdb_in_use = FALSE;
    }
    if ( dbname[0] && dbhome[0] ) {
	char	path[2*MAXPATHLEN];
	snprintf(path, sizeof(path)-1, "%s/%s", dbhome, dbname);
	db = new dbDatabase(dbDatabase::dbAllAccess, db_cache_mem);
	if ( db->open(path) ) {
	    gdb_in_use = TRUE;
	} else {
	    printf("failed to open database\n");
	}
    }
    if ( gdb_in_use ) {
	*aflag = MOD_AFLAG_BRK;
	printf("GigaBASE opened successfully\n");
    }
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
db_api_close(void)
{
    WRLOCK_GDB_CONFIG ;
    if ( gdb_in_use == TRUE ) {
	db->close();
	delete db;
	db = NULL;
	gdb_in_use = FALSE;
	my_xlog(OOPS_LOG_STOR, "gigabase_db_api_close(): GigaBASE closed\n");
	printf("GigaBASE closed\n");
    }
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
db_api_get(db_api_arg_t *arg, db_api_arg_t *res, int *aflag)
{
dbQuery			query;
dbCursor<URL_Info>	cursor;
URL_Info		*rec;
char			*url = NULL;

    if ( !arg || !res || !aflag ) return(MOD_CODE_ERR);

    RDLOCK_GDB_CONFIG ;
    if ( (gdb_in_use == FALSE) || !db ) goto done;

    *aflag = MOD_AFLAG_BRK;

    url = new char[arg->size + 1];
    if ( !url ) goto error;
    memcpy(url, arg->data, arg->size);
    url[arg->size] = 0;

    query = "url=", url;

    if ( cursor.select(query) > 0 ) {
	if ( (rec = cursor.get()) != 0 ) {
	    int blks = rec->disk_ref.blk;
	    void* result = malloc(sizeof(struct disk_ref) + blks * sizeof(uint32_t));
	    if ( !result ) {
		db->precommit();
		delete url;
		goto error;
	    }

	    memcpy(result, &rec->disk_ref, sizeof(struct disk_ref));
	    uint32_t* cblk = (uint32_t*)((struct disk_ref*)result + 1);
	    for ( int i = 0; i < blks; i++, cblk++ )
		*cblk = (rec->blocks)[i];

	    db->precommit();

	    res->data = result;
	    res->size = sizeof(struct disk_ref) + blks * sizeof(uint32_t);
	    res->flags= DB_API_RES_CODE_OK;
	    delete url;
	    goto done;
	}
    }

    db->precommit();
    res->flags = DB_API_RES_CODE_NOTFOUND;

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);

error:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_ERR);
}

int
db_api_put(db_api_arg_t *key, db_api_arg_t *data, struct mem_obj *obj, int *aflag)
{
dbQuery			query;
dbCursor<URL_Info>	cursor(dbCursorForUpdate);
URL_Info		UI;

    if ( !key || !data || !obj ) return(MOD_CODE_ERR);

    RDLOCK_GDB_CONFIG ;
    if ( (gdb_in_use == FALSE) || !db ) goto done;

    *aflag = MOD_AFLAG_BRK;

    UI.url = NULL;
    UI.url = new char[key->size + 1];
    if ( !UI.url ) goto error1;
    memcpy(UI.url, key->data, key->size);
    *(UI.url + key->size) = 0;

    memcpy(&UI.disk_ref, data->data, sizeof(disk_ref));
    UI.accessed = obj ? obj->accessed : 0;

    query = "url=", UI.url;

    if ( cursor.select(query) == 0 ) {
	if ( UI.disk_ref.blk <= 0 ) goto error;

	int blks = UI.disk_ref.blk;
	uint32_t* cblk = (uint32_t*)((struct disk_ref*)data->data + 1);

	dbArray<int8>	*blocks = NULL;
	blocks = new dbArray<int8>;
	if ( !blocks ) goto error;

	for( int i = 0; i < blks; i++, cblk++ )
	    blocks->append((int8)(*cblk));
	UI.blocks = *blocks;

	insert(UI);
	db->precommit();

	data->flags = 0;
	delete blocks;
    } else {
	db->precommit();
	data->flags = DB_API_RES_CODE_EXIST;
    }

    delete UI.url;

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);

error:
    db->precommit();
    delete UI.url;
error1:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_ERR);
}

int
db_api_del(db_api_arg_t *key, int *aflag)
{
dbQuery			query;
dbCursor<URL_Info>	cursor(dbCursorForUpdate);
char			*url = NULL;

    if ( !key || !aflag ) return(MOD_CODE_ERR);

    RDLOCK_GDB_CONFIG ;
    if ( (gdb_in_use == FALSE) || !db ) goto done;

    *aflag = MOD_AFLAG_BRK;

    url = new char[key->size + 1];
    if ( !url ) goto error;
    memcpy(url, key->data, key->size);
    url[key->size] = 0;

    query = "url=", url;

    if ( cursor.select(query) > 0 ) {
	cursor.remove();
	db->precommit();
	key->flags= DB_API_RES_CODE_OK;
    } else {
	db->precommit();
	key->flags= DB_API_RES_CODE_NOTFOUND;
    }

    delete url;

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);

error:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_ERR);
}

void*
db_api_cursor_open(int type, int* aflag)
{
void			*res = NULL;
dbcp_t			*newc;
int			r;

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE ) {
	UNLOCK_GDB_CONFIG ;
	return(MOD_CODE_OK);
    }
    my_xlog(OOPS_LOG_STOR, "gigabase_db_api_cursor_open()\n");

    db->attach();

    dbCursor<URL_Info>	*dbcp = new dbCursor<URL_Info>(dbCursorForUpdate);
    if ( !dbcp ) {
	UNLOCK_GDB_CONFIG ;
	return(NULL);
    }

    UNLOCK_GDB_CONFIG ;
    newc = (dbcp_t*)malloc(sizeof(*newc));
    newc->cursor = dbcp;
    newc->type = type;
    r = dbcp->select();
    newc->next_status = ( r > 0) ? TRUE : FALSE;
    res = newc;
    my_xlog(OOPS_LOG_STOR, "gigabase_db_api_cursor_open(): %d entries.\n", r);
    *aflag = MOD_AFLAG_BRK;
    return(res);
}

int
db_api_cursor_close(void *cursor, int *aflag)
{
struct	dbcp_		*cursor_data = (dbcp_t*)cursor;
dbCursor<URL_Info>      *dbcp;

    if ( !cursor_data ) return(MOD_CODE_ERR);
    dbcp = cursor_data->cursor;
    RDLOCK_GDB_CONFIG ;
    if ( (gdb_in_use == TRUE) && dbcp ) {
	delete dbcp;
	*aflag = MOD_AFLAG_BRK;
    }
    free(cursor_data);
    db->detach();
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

/* get disk reference for the object */
int
db_api_cursor_get(void *cursor, db_api_arg_t *key, db_api_arg_t *data, int *aflag)
{
dbcp_t			*curs = (dbcp_t*)cursor;
dbCursor<URL_Info>	*dbcp;
URL_Info		rec;

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE ) 	goto done;

    *aflag = MOD_AFLAG_BRK;

    if ( !curs ) goto error;

    dbcp = curs->cursor;

    if ( (curs->next_status != FALSE) ) {
	struct disk_ref disk_ref = (*dbcp)->disk_ref;
	int blks = disk_ref.blk;

	char* allocated = (char*)malloc(sizeof(disk_ref) + blks*sizeof(uint32_t));
	if ( !allocated ) goto error;

	memcpy(allocated, &disk_ref, sizeof(disk_ref));
	uint32_t* d = (uint32_t*)((struct disk_ref*)allocated + 1);
	for( int i = 0; i < blks; i++, d++ )
	    *d = (uint32_t)((*dbcp)->blocks[i]);

	key->size = strlen((*dbcp)->url);
	key->data = strdup((*dbcp)->url);

	data->size = sizeof(disk_ref) + blks*sizeof(uint32_t);
	data->data = allocated;
	data->flags = DB_API_RES_CODE_OK;
	curs->next_status = dbcp->next() ? TRUE : FALSE;
    } else {
	my_xlog(OOPS_LOG_STOR, "db_api_cursor_get(): Cursor empty.\n");
	key->data = data->data = NULL;
	key->size = data->size = 0;
	data->flags = DB_API_RES_CODE_NOTFOUND ;
    }

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);

error:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_ERR);
}

int
db_api_cursor_del(void *cursor, int *aflag)
{
dbcp_t			*curs = (dbcp_t*)cursor;
dbCursor<URL_Info>      *dbcp;

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db ) goto done;

    *aflag = MOD_AFLAG_BRK;

    if ( !curs ) goto error;

    dbcp = curs->cursor;

    // cursor_get called ->next(), so we have return. But we have to check
    // if next() was successfull
    if ( curs->next_status == TRUE ) dbcp->prev();
    my_xlog(OOPS_LOG_STOR, "gigabase_db_api_cursor_del(%s)\n", (*dbcp)->url);
    dbcp->remove();

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);

error:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_ERR);
}

int
db_api_sync(void)
{
    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db ) goto done;

    my_xlog(OOPS_LOG_STOR, "gigabase_db_api_sync()\n");
    db->commit();

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);    
}

int
db_api_attach(int *aflag)
{
    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db ) goto done;

    *aflag = MOD_AFLAG_BRK;

    my_xlog(OOPS_LOG_DBG, "gigabase_db_api_attach()\n");
    db->attach();

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);    
}

int
db_api_detach(int *aflag)
{

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db ) goto done;

    *aflag = MOD_AFLAG_BRK;

    my_xlog(OOPS_LOG_DBG, "gigabase_db_api_detach()\n");
    db->detach();

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
db_api_precommit(int *aflag)
{

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db ) goto done;

    *aflag = MOD_AFLAG_BRK;

    my_xlog(OOPS_LOG_STOR, "gigabase_db_api_precommit()\n");
    db->precommit();

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
db_api_cursor_freeze(void *cursor, int *aflag)
{
dbcp_t			*curs = (dbcp_t*)cursor;

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db ) goto done;

    if ( !curs || !curs->cursor ) goto error;

    curs->cursor->freeze();

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);

error:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_ERR);
}

int
db_api_cursor_unfreeze(void *cursor, int *aflag)
{
dbcp_t			*curs = (dbcp_t*)cursor;

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db ) goto done;

    if ( !curs || !curs->cursor ) goto error;

    curs->cursor->unfreeze();

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);

error:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_ERR);
}

#else	/* HAVE_GIGABASE */
#if	!defined(MODULES)
struct	db_api_module	gigabase_db_api = {
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
