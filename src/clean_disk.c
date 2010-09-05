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

#include	"oops.h"

#define		KEEP_NO_LONGER_THAN	1	/* keep storage locked for cleanup *
						 * no longer than		   */
#define		LOW_SPACE(s)		(!s->super.blks_free || \
		(((s->super.blks_free*100)/s->super.blks_total) < disk_low_free))

#define		SPACE_NOT_GOOD(s)		(!s->super.blks_free || \
		(((s->super.blks_free*100)/s->super.blks_total) < disk_hi_free))

time_t		last_expire = 0;

void		check_expire(void);
void		sync_storages(void);
int		forced_cleanup = 0;

long
count_total_free(void)
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
count_total_blks(void)
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

int
start_cleanup(int total_blks, int total_free, int low_free)
{
    if ( forced_cleanup )
	return(1);
    if ( ( low_free > 0 ) && ((total_free*100)/total_blks < low_free) )
	return(1);
    if ( !low_free && ( total_free < 128 ) )
	return(1);
    return(0);
}

int
continue_cleanup(int total_blks, int total_free, int hi_free)
{
    if ( (hi_free > 0) && ((total_free*100)/total_blks < hi_free) )
	return(1);
    if ( !hi_free && ( total_free < 512 ) )
	return(1);
    return(0);
}

void *
clean_disk(void *arg)
{
struct	storage_st	*storage;
DBC			*dbcp;
DBT			key, data;
int			rc;
long			total_free, total_blks;
struct	disk_ref	*disk_ref;
time_t			now;

    if ( arg ) return (void *)0;

    forever() {
	pthread_mutex_lock(&st_check_in_progr_lock);
	if ( !st_check_in_progr ) check_expire();
	pthread_mutex_unlock(&st_check_in_progr_lock);

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
	if ( start_cleanup(total_blks, total_free, disk_low_free) ) {
	    my_xlog(LOG_STOR|LOG_DBG, "clean_disk(): Need disk clean up: free: %d/total: %d\n",
		    total_free, total_blks);
	    /* 1. create db cursor */
	    WRLOCK_DB ;
	    rc = dbp->cursor(dbp, NULL, &dbcp
#if     (DB_VERSION_MAJOR>2) || (DB_VERSION_MINOR>=6)   
					     , 0
#endif
	    					);
	    if ( rc ) {
		UNLOCK_DB;
		my_xlog(LOG_SEVERE, "clean_disk(): cursor: %d %m\n", rc);
		goto err;
	    }
	    while ( continue_cleanup(total_blks, total_free, disk_hi_free) ) {
		bzero(&key, sizeof(key));
		bzero(&data, sizeof(data));
		key.flags = data.flags = DB_DBT_MALLOC;
		rc = dbcp->c_get(dbcp, &key, &data, DB_NEXT);
		if ( rc > 0 ) {
		    my_xlog(LOG_SEVERE, "clean_disk(): c_get: %d %m\n", rc);
		    UNLOCK_DB;
		    goto done;
	        }
	        if ( rc < 0 ) {
		    forced_cleanup = FALSE ;
		    dbcp->c_close(dbcp);
		    UNLOCK_DB ;
		    goto done;
		}
	        disk_ref = data.data;
		storage = locate_storage_by_id(disk_ref->id);
		dbcp->c_del(dbcp, 0);
		if ( storage ) {
		    WRLOCK_STORAGE(storage);
		    release_blks(disk_ref->blk, storage, disk_ref);
		    UNLOCK_STORAGE(storage) ;
		    total_free+=disk_ref->blk;
		} else {
		    my_xlog(LOG_SEVERE, "clean_disk(): WARNING: Failed to find storage in clean_disk.\n");
		}
		free(key.data);
		free(data.data);
		if ( global_sec_timer - now >= KEEP_NO_LONGER_THAN || MUST_BREAK ) {
		    forced_cleanup = TRUE ;
		    dbcp->c_close(dbcp);
		    UNLOCK_DB ;
		    goto done;
		}
	    }
	    UNLOCK_DB ;
	    forced_cleanup = FALSE;
	} else {
	    my_xlog(LOG_STOR|LOG_DBG, "clean_disk(): Skip cleanup: %d out of %d (%d%%) free.\n",
		    total_free, total_blks, (total_free*100)/total_blks);
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
check_expire(void)
{
time_t			started, now = time(NULL);
DBC			*dbcp = NULL ;
DBT			key, data ;
int			rc, get_counter, expired_cnt = 0, total_cnt = 0;
struct	disk_ref	*disk_ref;
struct	storage_st	*storage;

    if ( now - last_expire < default_expire_interval )
	return ;

    RDLOCK_CONFIG ;
    if ( !dbp || !storages ) {
	UNLOCK_CONFIG ;
	return ;
    }
    last_expire = started = now ;

    /* otherwise start expire */

run:
    WRLOCK_DB ;
    /* I'd like to lock all storages now, but can this lead to deadlocks?	*/
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
	    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_expire(): EXPIRE Finished: %d expires, %d seconds, %d total\n",
	    	    expired_cnt, (utime_t)(global_sec_timer-started), total_cnt);
	    return ;
	}
    }
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_expire(): EXPIRE started, %d total, %d expired\n",
	    total_cnt, expired_cnt);
    now = global_sec_timer;
    get_counter = 0 ;
    forever() {
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
		if ( ( storage->flags & ST_READY ) /*&& SPACE_NOT_GOOD(storage)*/ ) {
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
	     (global_sec_timer-now >= KEEP_NO_LONGER_THAN) ) {
		/* must break */
	    UNLOCK_DB ;
	    /* cursor used acros runs, so we can't release CONFIG */
	    my_sleep(5);
	    goto run ;
	}
    }

done:
    UNLOCK_DB ;
    if ( dbcp )
	dbcp->c_close(dbcp);
    UNLOCK_CONFIG ;
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_expire(): EXPIRE Finished: %d expires, %d seconds, %d total\n",
	    expired_cnt, (utime_t)(global_sec_timer-started), total_cnt);
}

void
sync_storages(void)
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
