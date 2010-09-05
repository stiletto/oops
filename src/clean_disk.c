#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<strings.h>
#include	<stdarg.h>
#include	<netdb.h>
#include	<ctype.h>

#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/socketvar.h>
#include	<sys/resource.h>
#include	<fcntl.h>

#include	<netinet/in.h>

#include	<arpa/inet.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"

#define		KEEP_NO_LONGER_THAN	1	/* keep storage locked for cleanup *
						 * no longer than		   */
#define		LOW_SPACE(s)		(!s->super.blks_free || \
		(((s->super.blks_free*100)/s->super.blks_total) < disk_low_free))

#define		SPACE_NOT_GOOD(s)		(!s->super.blks_free || \
		(((s->super.blks_free*100)/s->super.blks_total) < disk_hi_free))

time_t		last_expire = 0;

void		check_expire();
void		sync_storages();

long
count_total_free()
{
struct storage_st *storage;
long		  res = 0;

    storage = storages;
    while ( storage ) {
	res += storage->super.blks_free;
	storage = storage->next;
    }
    return(res);
}
long
count_total_blks()
{
struct storage_st *storage;
long		  res = 0;

    storage = storages;
    while ( storage ) {
	res += storage->super.blks_total;
	storage = storage->next;
    }
    return(res);
}

void*
clean_disk(void *arg)
{
struct	storage_st	*storage;
DBC			*dbcp;
DBT			key, data;
int			rc, forced_cleanup = 0;
long			total_free, total_blks;
struct	disk_ref	*disk_ref;
time_t			now;

    arg = arg ;
    while(1) {

	check_expire();

	now = time(NULL);

	RDLOCK_CONFIG ;
	if ( !dbp ) {
	    UNLOCK_CONFIG;
	    my_sleep(10);
	    continue;
	}
	total_free = count_total_free();
	total_blks = count_total_blks();
	LOCK_STATISTICS(oops_stat);
	if ( total_blks <= 0 )	oops_stat.storages_free = -1;
	        else		oops_stat.storages_free = (total_free*100)/total_blks;
	UNLOCK_STATISTICS(oops_stat);
	if ( total_blks <= 0 ) {
	    UNLOCK_CONFIG;
	    my_sleep(10);
	    continue;
	}
	if ( (total_free*100)/total_blks < disk_low_free || forced_cleanup ) {
	    my_log("Need disk clean up: free: %d/total: %d\n", total_free, total_blks);
	    /* 1. create db cursor */
	    rc = dbp->cursor(dbp, NULL, &dbcp
#if     (DB_VERSION_MAJOR>2) || (DB_VERSION_MINOR>=6)   
					     , 0
#endif
	    					);
	    if ( rc ) {
		my_log("cursor: %s\n", strerror(rc));
		goto err;
	    }
	    while ((total_free*100)/total_blks < disk_hi_free ) {
		bzero(&key, sizeof(key));
		bzero(&data, sizeof(data));
		key.flags = data.flags = DB_DBT_MALLOC;
		rc = dbcp->c_get(dbcp, &key, &data, DB_NEXT);
		if ( rc > 0 ) {
		    my_log("c_get: %s\n", strerror(rc));
		    goto done;
	        }
	        if ( rc < 0 ) {
		    forced_cleanup = FALSE ;
		    dbcp->c_close(dbcp);
		    dbp->sync(dbp, 0);
		    UNLOCK_DB ;
		    goto done;
		}
	        disk_ref = data.data;
		storage = locate_storage_by_id(disk_ref->id);
		WRLOCK_DB ;
		dbcp->c_del(dbcp, 0);
		if ( storage ) {
		    WRLOCK_STORAGE(storage);
		    release_blks(disk_ref->blk, storage, disk_ref);
		    UNLOCK_STORAGE(storage) ;
		    total_free+=disk_ref->blk;
		} else {
		    my_log("WARNING: Failed to find storage in clean_disk\n");
		}
		free(key.data);
		free(data.data);
		if ( time(NULL) - now >= KEEP_NO_LONGER_THAN || MUST_BREAK ) {
		    forced_cleanup = TRUE ;
		    dbcp->c_close(dbcp);
		    dbp->sync(dbp, 0);
		    UNLOCK_DB ;
		    goto done;
		}
		UNLOCK_DB ;
	    }
	    forced_cleanup = FALSE;
	} else {
	    my_log("Skip cleanup: %d out of %d (%d%%) free\n", total_free, total_blks,(total_free*100)/total_blks);
	}
done:
err:
	UNLOCK_CONFIG ;
	my_sleep(10);
	sync_storages();
	continue;
    }
}


void
check_expire()
{
time_t			started, now = time(NULL);
DBC			*dbcp = NULL ;
DBT			key, data ;
int			rc, get_counter, expired_cnt = 0, total_cnt = 0;
struct	disk_ref	*disk_ref;
struct	storage_st	*storage;

    if ( now - last_expire < default_expire_interval )
	return ;

    if ( !dbp || !storages )
	return ;
    last_expire = started = now ;

    /* otherwise start expire */
    RDLOCK_CONFIG ;
    if ( !dbp ) goto nodb;
run:
    WRLOCK_DB ;
    /* I'd like lo lock all storages now, but can this lead to deadlocks?	*/
    /* so, storages will be locked and unlocked when need			*/
    if ( !dbcp ) {
	rc = dbp->cursor(dbp, NULL, &dbcp
#if     (DB_VERSION_MAJOR>2) || (DB_VERSION_MINOR>=6)   
					 , 0
#endif
					);
	if ( rc ) {
	    UNLOCK_DB ;
	    UNLOCK_CONFIG ;
	    my_log("EXPIRE Finished: %d expires, %d seconds, %d total\n",
	    	expired_cnt, time(NULL)-started, total_cnt);
	    return ;
	}
    }
    my_log("EXPIRE started, %d total, %d expired\n", total_cnt, expired_cnt);
    now = time(NULL);
    get_counter = 0 ;
    while ( 1 ) {
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	key.flags = data.flags = DB_DBT_MALLOC;
	if ( MUST_BREAK )
	    goto done;
	rc = dbcp->c_get(dbcp, &key, &data, DB_NEXT);
	if ( rc )
	    goto done;
	get_counter++;
	total_cnt++;
	disk_ref = data.data;
	if ( disk_ref->expires < now ) {
	    storage = locate_storage_by_id(disk_ref->id);
	    if ( storage ) {
		if ( ( storage->flags & ST_READY ) && SPACE_NOT_GOOD(storage) ) {
		    dbcp->c_del(dbcp, 0);
		    expired_cnt++ ;
		    WRLOCK_STORAGE(storage);
		    release_blks(disk_ref->blk, storage, disk_ref);
		    UNLOCK_STORAGE(storage);
		} /* low space */
	    } else {
		/* lost storage - recodr must be erased */
		    dbcp->c_del(dbcp, 0);
	    }
	}
	free(key.data);
	free(data.data);
	if ( (get_counter > 20) &&
	     (time(NULL)-now >= KEEP_NO_LONGER_THAN) ) {
		/* must break */
	    dbp->sync(dbp, 0);
	    UNLOCK_DB ;
	    /* cursor used acros runs, so we can't release CONFIG */
	    my_sleep(5);
	    goto run ;
	}
    }
done:
    dbp->sync(dbp, 0);
    UNLOCK_DB ;
nodb:
    UNLOCK_CONFIG ;
    if ( dbcp )
	dbcp->c_close(dbcp);
    my_log("EXPIRE Finished: %d expires, %d seconds, %d total\n",
	expired_cnt, time(NULL)-started, total_cnt);
}

void
sync_storages()
{
struct	storage_st *storage = storages;

    while(storage) {
	WRLOCK_STORAGE(storage);
	flush_super(storage);
	flush_map(storage);
	UNLOCK_STORAGE(storage);
	storage = storage->next;
    }
}
