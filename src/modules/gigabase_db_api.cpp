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

#if	defined(SOLARIS)
#undef  _LARGEFILE_SOURCE
#undef  WITH_LARGE_FILES
#undef  _FILE_OFFSET_BITS
#endif

#include "../oops.h"
#include "../modules.h"

#define	MODULE_NAME	"gigabase_db"
#define	MODULE_INFO	"GigaBASE API"

#if	defined(MODULES)
char		module_type 	= MODULE_DB_API;
char		module_info[]	= MODULE_INFO  ;
char		module_name[]	= MODULE_NAME  ;
#else
static	char	module_type 	= MODULE_DB_API ;
static	char	module_info[]	= MODULE_INFO	;
static	char	module_name[]	= MODULE_NAME	;
#endif

#if	defined(HAVE_GIGABASE)
#include "/usr/local/include/gigabase/gigabase.h"


#if	defined(MODULES)
extern	"C" {
int		mod_run();
int		mod_load();
int		mod_unload();
int		mod_config_beg(), mod_config_end(), mod_config(char*), mod_run();
int		db_api_open(int*), db_api_close();
int		db_api_get(db_api_arg_t*, db_api_arg_t*, int*);
int		db_api_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*,int*);
int		db_api_del(db_api_arg_t*, int*);
int		db_api_sync();
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
static	int	mod_run();
static	int	mod_load();
static	int	mod_unload();
static	int	mod_config_beg(), mod_config_end(), mod_config(char*), mod_run();
static	int	db_api_open(int*), db_api_close();
static	int	db_api_get(db_api_arg_t*, db_api_arg_t*, int*);
static	int	db_api_put(db_api_arg_t*, db_api_arg_t*, struct mem_obj*, int*);
static	int	db_api_del(db_api_arg_t*, int*);
static	int	db_api_sync();
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

dbDatabase	*db = NULL;

struct dbcp_ {
	dbCursor<URL_Info>	*cursor;
	int			next_status;
	int			type;
};
typedef	struct	dbcp_	dbcp_t;
static	int		gdb_in_use = FALSE;
static	char		dbhome[MAXPATHLEN];
static	char		dbname[MAXPATHLEN];
static	int		db_cache_mem;
static  pthread_rwlock_t	giga_db_config_lock;

#define RDLOCK_GDB_CONFIG       pthread_rwlock_rdlock(&giga_db_config_lock)
#define WRLOCK_GDB_CONFIG       pthread_rwlock_wrlock(&giga_db_config_lock)
#define UNLOCK_GDB_CONFIG       pthread_rwlock_unlock(&giga_db_config_lock)

int
mod_run()
{
    return(MOD_CODE_OK);
}

int
mod_load()
{
    printf("%s started\n", module_name);
    dbname[0] = dbhome[0] = 0;
    gdb_in_use = FALSE;
    pthread_rwlock_init(&giga_db_config_lock, NULL);
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
    WRLOCK_GDB_CONFIG ;
    dbname[0] = dbhome[0] = 0;
    db_cache_mem = 1024;
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
mod_config_end()
{
    if ( db_cache_mem < 1024 ) 
	db_cache_mem = 1024;
    return(MOD_CODE_OK);
}

int
mod_config(char *config)
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
	    db_cache_mem /= 4096; /* gigabase accept this in pages */
	}
    }
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}
int
db_api_open(int *aflag)
{

    WRLOCK_GDB_CONFIG ;
    if ( gdb_in_use == TRUE ) {
	db->close();
	delete(db);
	db = NULL;
	gdb_in_use = FALSE;
    }
    if ( dbname[0] && dbhome[0] ) {
	char	path[2*MAXPATHLEN];
	sprintf(path, "%s/%s", dbhome, dbname);
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
db_api_close()
{
    WRLOCK_GDB_CONFIG ;
    if ( gdb_in_use == TRUE ) {
	my_xlog(LOG_STOR, "gigabase_db_api_close(): GigaBASE closed\n");
	db->close();
	delete(db);
	db = NULL;
	gdb_in_use = FALSE;
    }
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
db_api_get(db_api_arg_t *arg, db_api_arg_t *res, int *aflag)
{
dbQuery			q;
dbCursor<URL_Info>	cursor;
URL_Info		*rec;
int			r, blks;
char			*url = NULL;
void			*result;
uint32_t		*cblk;

    if ( !arg || !res || !aflag ) return(MOD_CODE_ERR);

    RDLOCK_GDB_CONFIG ;
    if ( (gdb_in_use == FALSE) || !db ) goto done;
    *aflag = MOD_AFLAG_BRK;

    url = (char*)malloc(arg->size + 1);
    if ( !url ) goto done;
    memcpy(url, arg->data, arg->size);
    url[arg->size] = 0;

    q = "url=", url;
    r = cursor.select(q);
    if ( r <= 0 ) {
	res->flags= DB_API_RES_CODE_NOTFOUND;
	goto done;
    }
    rec = cursor.get();
    if ( !rec ) {
	res->flags= DB_API_RES_CODE_NOTFOUND;
	goto done;
    }
    blks = rec->disk_ref.blk;
    result = malloc(sizeof(struct disk_ref) + blks * sizeof(uint32_t));
    if ( !result ) goto done;
    memcpy(result, &rec->disk_ref, sizeof(struct disk_ref));
    cblk = (uint32_t*)((struct disk_ref*)result + 1);
    for ( r=0;r<blks; r++,cblk++)
	*cblk = (rec->blocks)[r];
    res->data = result;
    res->size = sizeof(struct disk_ref) + blks * sizeof(uint32_t);
    res->flags= DB_API_RES_CODE_OK;
done:
    UNLOCK_GDB_CONFIG ;
    if ( url ) free(url);
    return(MOD_CODE_OK);
}


int
db_api_put(db_api_arg_t *key, db_api_arg_t *data, struct mem_obj *obj, int *aflag)
{
int			blks, i;
uint32_t		*cblk;
dbArray<int8>		*blocks = NULL;
int			r;
dbQuery			q;
dbCursor<URL_Info>	cursor;
URL_Info		UI;

    if ( !key || !data || !obj ) return(MOD_CODE_ERR);

    RDLOCK_GDB_CONFIG ;
    UI.url = NULL;
    
    if ( (gdb_in_use == FALSE) || !db ) goto done;

    memcpy(&UI.disk_ref, data->data, sizeof(disk_ref));
    UI.accessed = obj?obj->accessed:0;
    UI.url = new (char[key->size + 1]);
    if ( UI.url ) {
	memcpy(UI.url, key->data, key->size);
	*(UI.url + key->size) = 0;
    }
    q = "url=", UI.url;
    r = cursor.select(q);
    if ( r > 0 ) {
	data->flags = DB_API_RES_CODE_EXIST;
	goto done;
    }
    if ( UI.disk_ref.blk <= 0 )
	goto error;
    blks = UI.disk_ref.blk;
    cblk = (uint32_t*)((struct disk_ref*)data->data + 1);

    blocks = new (dbArray<int8>);
    for(i=0;i<blks;i++,cblk++)
	blocks->append((int8)(*cblk));
    UI.blocks = *blocks;

    insert(UI);
    data->flags = 0;

done:
    UNLOCK_GDB_CONFIG ;
    *aflag = MOD_AFLAG_BRK;
    if ( blocks ) delete(blocks);
    if ( UI.url ) delete(UI.url);
    return(MOD_CODE_OK);
error:
    UNLOCK_GDB_CONFIG ;
    *aflag = MOD_AFLAG_BRK;
    if ( blocks ) delete(blocks);
    if ( UI.url ) delete(UI.url);
    return(MOD_CODE_ERR);
}

int
db_api_del(db_api_arg_t *key, int *aflag)
{
dbQuery			q;
dbCursor<URL_Info>	cursor(dbCursorForUpdate);
char			*url = NULL;
int			r;

    if ( !key || !aflag ) return(MOD_CODE_ERR);

    RDLOCK_GDB_CONFIG ;
    if ( (gdb_in_use == FALSE) || !db ) goto done;
    *aflag = MOD_AFLAG_BRK;

    url = (char*)malloc(key->size + 1);
    if ( !url ) goto done;
    memcpy(url, key->data, key->size);
    url[key->size] = 0;

    q = "url=", url;
    r = cursor.select(q);
    if ( r <= 0 ) {
	key->flags= DB_API_RES_CODE_NOTFOUND;
	goto done;
    }

    cursor.remove();
    key->flags= DB_API_RES_CODE_OK;

done:
    if ( url ) free(url);
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

void*	db_api_cursor_open(int type, int* aflag)
{
void			*res = NULL;
dbcp_t			*newc;
int			r;

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE ) {
	UNLOCK_GDB_CONFIG ;
	return(MOD_CODE_OK);
    }
    my_xlog(LOG_STOR, "gigabase_db_api_cursor_open()\n");

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
    newc->next_status = (r>0)?TRUE:FALSE;
    res = newc;
    my_xlog(LOG_STOR, "gigabase_db_api_cursor_open'ed(): %d entries\n", r);
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
	delete(dbcp);
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
dbCursor<URL_Info>      *dbcp;
URL_Info		rec;
struct	disk_ref	disk_ref;
int			blks, i;
uint32_t		*d;
char			*allocated;

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE )
	goto done;
    *aflag = MOD_AFLAG_BRK;

    if ( !curs ) goto done;

    dbcp = curs->cursor;
    if ( (curs->next_status != FALSE) ) {
	key->size = strlen((*dbcp)->url);
	key->data = strdup((*dbcp)->url);
	disk_ref = (*dbcp)->disk_ref;
	blks = disk_ref.blk;
	allocated = (char*)xmalloc(sizeof(disk_ref) + blks*sizeof(uint32_t), "");
	memcpy(allocated, &disk_ref, sizeof(disk_ref));
	d = (uint32_t*)((struct disk_ref*)allocated + 1);
	for(i=0;i<blks;i++,d++)
	    *d = (uint32_t)((*dbcp)->blocks[i]);
	data->size = sizeof(disk_ref) + blks*sizeof(uint32_t);
	data->data = allocated;
	data->flags = DB_API_RES_CODE_OK ;
	curs->next_status = dbcp->next()?TRUE:FALSE;
    } else {
	my_xlog(LOG_STOR, "Cursor empty\n");
	key->data = data->data = NULL;
	key->size = data->size = 0;
	data->flags = DB_API_RES_CODE_NOTFOUND ;
    }

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
db_api_cursor_del(void *cursor, int *aflag)
{
dbcp_t			*curs = (dbcp_t*)cursor;
dbCursor<URL_Info>      *dbcp;

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db )
	goto done;
    *aflag = MOD_AFLAG_BRK;
    if ( !curs ) goto error;

    dbcp = curs->cursor;

    // cursor_get called ->next(), so we have return. But we have to check
    // if next() was successfull
    if ( curs->next_status == TRUE ) dbcp->prev();
    my_xlog(LOG_STOR, "gigabase_db_api_cursor_del(%s)\n", (*dbcp)->url);
    dbcp->remove();

done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);

error:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_ERR);
}

int
db_api_sync()
{
    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db )
	goto done;
    my_xlog(LOG_STOR, "gigabase_db_api_sync()\n");
    db->commit();
done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);    
}

int
db_api_attach(int *aflag)
{
    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db )
        goto done;
    my_xlog(LOG_STOR, "gigabase_db_api_attach()\n");
    *aflag = MOD_AFLAG_BRK;
    db->attach();
done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);    
}

int
db_api_detach(int *aflag)
{

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db )
	goto done;
    my_xlog(LOG_STOR, "gigabase_db_api_detach()\n");
    *aflag = MOD_AFLAG_BRK;
    db->detach();
done:
    UNLOCK_GDB_CONFIG ;
    return(MOD_CODE_OK);
}

int
db_api_precommit(int *aflag)
{

    RDLOCK_GDB_CONFIG ;
    if ( gdb_in_use == FALSE || !db )
	goto done;
    my_xlog(LOG_STOR, "gigabase_db_api_precommit()\n");
    *aflag = MOD_AFLAG_BRK;
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
    if ( gdb_in_use == FALSE || !db )
	goto done;
    if ( !curs || !curs->cursor )
	goto error;

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
    if ( gdb_in_use == FALSE || !db )
	goto done;
    if ( !curs || !curs->cursor )
	goto error;

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
