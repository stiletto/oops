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

static	hg_entry	hg[] = {
	{0,		30*_MINUTE_,	0},
	{30*_MINUTE_,	   _HOUR_,	0},
	{   _HOUR_,	3* _HOUR_,	0},
	{3* _HOUR_,	6* _HOUR_,	0},
	{6* _HOUR_,	   _DAY_,	0},
	{   _DAY_,	3* _DAY_,	0},
	{3* _DAY_,	   _WEEK_,	0},
	{   _WEEK_,	2* _WEEK_,	0},
	{2* _WEEK_,	   _MONTH_,	0},
	{-1,		-1,		0}	/* stop */
};

static	time_t	last_expire = 0;
static	int	forced_cleanup = 0;

static	void	check_expire(void);
static	void	clear_hg(hg_entry *table);
static	int	continue_cleanup(int total_blks, int total_free, int hi_free);
static	long	count_total_blks(void);
static	long	count_total_free(void);
static	void	decrement_hg(int created, int value);
static	void	hg_print(void);
static	int	ok_to_delete(int created);
static	int	start_cleanup(int total_blks, int total_free, int low_free);
static	void	sync_storages(void);

inline	static	void	increment_hg(hg_entry *table, int arg, int value);


/* histogram handling routines */
static void
decrement_hg(int created, int value)
{
hg_entry *res = &hg[0];

    created = global_sec_timer - created;
    while ( res->from != res->to ) {
	if ( (res->from < created) && (created <= res->to) ) {
	    res->sum -= value;
	    return;
	};
	res++;
    }
}

static void
hg_print(void)
{
hg_entry *res = &hg[0];
char	*n[] = {
	"<30min",
	"<1hour",
	"<3hour",
	"<6hour",
	"<1day",
	"<3day",
	"<1week",
	"<2week",
	"<month"
};
char	**np = &n[0];

    while ( res->from != res->to ) {
	my_xlog(OOPS_LOG_STOR, "%8.8s - %d\n", *np, res->sum);
	res++;
	np++;
    }
}

static int
ok_to_delete(int created)
{
    created = global_sec_timer - created;
    if ( created > hg[8].from ) return(1);
    if ( ( created < hg[8].from ) && (hg[8].sum>0) ) return(0);
    if ( created > hg[7].from ) return(1);
    if ( ( created < hg[7].from ) && (hg[7].sum>0) ) return(0);
    if ( created > hg[6].from ) return(1);
    if ( ( created < hg[6].from ) && (hg[6].sum>0) ) return(0);
    if ( created > hg[5].from ) return(1);
    if ( ( created < hg[5].from ) && (hg[5].sum>0) ) return(0);
    if ( created > hg[4].from ) return(1);
    if ( ( created < hg[4].from ) && (hg[4].sum>0) ) return(0);
    if ( created > hg[3].from ) return(1);
    if ( ( created < hg[3].from ) && (hg[3].sum>0) ) return(0);
    if ( created > hg[2].from ) return(1);
    if ( ( created < hg[2].from ) && (hg[2].sum>0) ) return(0);
    if ( created > hg[1].from ) return(1);
    if ( ( created < hg[1].from ) && (hg[1].sum>0) ) return(0);
    return(1);
}

inline
static void
increment_hg(hg_entry *table, int arg, int value)
{
hg_entry *res = table;

    arg = global_sec_timer - arg;
    if ( !table ) return;
    while ( res->from != res->to ) {
	if ( (res->from < arg) && (arg <= res->to) ) {
	    res->sum += value;
	    return;
	}
	res++;
    }
}

static void
clear_hg(hg_entry *table)
{
hg_entry *res = table;

    if ( !table ) return;
    while ( res->from != res->to ) {
	res->sum = 0;
	res++;
    }
}

static long
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

static long
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

static int
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

static int
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
void			*dbcp = NULL;
db_api_arg_t		key, data;
int			rc;
long			total_free, total_blks;
struct	disk_ref	*disk_ref;
time_t			now;
int			sync_counter = 0;

    if ( arg ) return (void *)0;

    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "Clean disk started.\n");

    forever() {
	pthread_mutex_lock(&st_check_in_progr_lock);
	if ( !st_check_in_progr ) check_expire();
	pthread_mutex_unlock(&st_check_in_progr_lock);

	now = time(NULL);

	RDLOCK_CONFIG ;
	if ( !db_in_use || !storages_ready || broken_db ) {
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
	if (TEST(verbosity_level, OOPS_LOG_STOR)) hg_print();
	if ( start_cleanup(total_blks, total_free, disk_low_free) ) {
            snprintf(disk_state_string, sizeof(disk_state_string)-1, "Cleanup: %d free", total_free);
	    my_xlog(OOPS_LOG_STOR|OOPS_LOG_DBG, "clean_disk(): Need disk clean up: free: %d/total: %d\n",
		    total_free, total_blks);
	    /* 1. create db cursor */
	    WRLOCK_DB ;
	    dbcp =  db_mod_cursor_open(DB_API_CURSOR_NORMAL);
	    if ( !dbcp ) {
		UNLOCK_DB;
		my_xlog(OOPS_LOG_SEVERE, "clean_disk(): cursor: %m\n");
		goto err;
	    }
	    while ( continue_cleanup(total_blks, total_free, disk_hi_free) ) {
		if ( MUST_BREAK ) {
		    forced_cleanup = TRUE ;
		    db_mod_cursor_close(dbcp);
		    UNLOCK_DB ;
		    goto done;
		}
		bzero(&key, sizeof(key));
		bzero(&data, sizeof(data));
		rc = db_mod_cursor_get(dbcp, &key, &data);
	        if ( rc == DB_API_RES_CODE_NOTFOUND ) {
		    forced_cleanup = FALSE ;
		    db_mod_cursor_close(dbcp);
		    dbcp = NULL;
		    UNLOCK_DB ;
		    goto done;
		}
		if ( rc != 0 ) {
		    my_xlog(OOPS_LOG_SEVERE, "clean_disk(): c_get: %d\n", rc);
		    db_mod_cursor_close(dbcp);
		    dbcp = NULL;
		    UNLOCK_DB;
		    goto done;
	        }
	        disk_ref = data.data;
		if ( ok_to_delete(disk_ref->created) ) {
		    storage = locate_storage_by_id(disk_ref->id);
		    db_mod_cursor_del(dbcp);
		    if ( storage ) {
			WRLOCK_STORAGE(storage);
			release_blks(disk_ref->blk, storage, disk_ref);
			UNLOCK_STORAGE(storage) ;
			total_free+=disk_ref->blk;
		    } else {
			my_xlog(OOPS_LOG_SEVERE, "clean_disk(): WARNING: Failed to find storage in clean_disk.\n");
		    }
		    decrement_hg(disk_ref->created, disk_ref->blk);
		}
		xfree(key.data);
		xfree(data.data);
		if ( global_sec_timer - now >= KEEP_NO_LONGER_THAN ) {
		    db_mod_cursor_freeze(dbcp);
		    db_mod_sync();
		    UNLOCK_DB ;
		    my_sleep(5);
		    WRLOCK_DB ;
		    now = global_sec_timer;
		    db_mod_cursor_unfreeze(dbcp);
		    continue;
		}
	    }
	    if ( dbcp ) db_mod_cursor_close(dbcp);
	    UNLOCK_DB ;
	    forced_cleanup = FALSE;
	} else {
	    my_xlog(OOPS_LOG_STOR|OOPS_LOG_DBG, "clean_disk(): Skip cleanup: %d out of %d (%d%%) free.\n",
		    total_free, total_blks, (total_free*100)/total_blks);
	}

done:
err:
	UNLOCK_CONFIG ;
        snprintf(disk_state_string, sizeof(disk_state_string)-1, "Cleanup finished");
	my_sleep(10);
        sync_counter++;
	if ( !(sync_counter%6) ) {
	    sync_storages();
	    sync_counter=0;
        }
	continue;
    }
}


static void
check_expire(void)
{
time_t			started, now = time(NULL);
void			*dbcp = NULL ;
db_api_arg_t		key, data ;
int			rc, get_counter, expired_cnt = 0, total_cnt = 0;
struct	disk_ref	*disk_ref;
struct	storage_st	*storage;

    if ( now - last_expire < default_expire_interval )
	return ;

    RDLOCK_CONFIG ;
    if ( !db_in_use || !storages_ready || !storages || broken_db ) {
	UNLOCK_CONFIG ;
	return ;
    }
    if ( expiretime && !denytime_check(expiretime) ) {
	UNLOCK_CONFIG ;
	return ;
    }
    last_expire = started = now ;

    /* otherwise start expire */

    clear_hg(&hg[0]);

run:
    WRLOCK_DB ;
run_locked:
    /* I'd like to lock all storages now, but can this lead to deadlocks?	*/
    /* so, storages will be locked and unlocked when need			*/
    if ( !dbcp ) {
	dbcp =  db_mod_cursor_open(DB_API_CURSOR_NORMAL);
	if ( !dbcp ) {
	    UNLOCK_DB ;
	    UNLOCK_CONFIG ;
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "check_expire(): EXPIRE Finished: %d expires, %d seconds, %d total\n",
	    	    expired_cnt, (utime_t)(global_sec_timer-started), total_cnt);
            snprintf(disk_state_string, sizeof(disk_state_string)-1, "Expire finished: %d expired", expired_cnt);
	    return ;
	}
    }
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "check_expire(): EXPIRE started, %d total, %d expired\n",
	    total_cnt, expired_cnt);
    now = global_sec_timer;
    get_counter = 0 ;
    forever() {
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	if ( MUST_BREAK )
	    goto done;
	rc = db_mod_cursor_get(dbcp, &key, &data);
	if ( rc )
	    goto done;
	get_counter++;
	total_cnt++;
	disk_ref = data.data;
	if ( disk_ref->expires < now ) {
	    storage = locate_storage_by_id(disk_ref->id);
	    if ( storage ) {
		if ( ( storage->flags & ST_READY ) /*&& SPACE_NOT_GOOD(storage)*/ ) {
		    db_mod_cursor_del(dbcp);
		    expired_cnt++ ;
		    WRLOCK_STORAGE(storage);
		    release_blks(disk_ref->blk, storage, disk_ref);
		    UNLOCK_STORAGE(storage);
		} /* low space */
	    } else {
		/* lost storage - recodr must be erased */
		    db_mod_cursor_del(dbcp);
	    }
	} else {
	    /* not expired, update histogram */
	    increment_hg(&hg[0], disk_ref->created, disk_ref->blk);
	}
	xfree(key.data);
	xfree(data.data);
	if ( (get_counter > 20) &&
	     (global_sec_timer-now >= KEEP_NO_LONGER_THAN) ) {
		/* must break */
	    /* cursor used acros runs, so we can't release CONFIG */
	    db_mod_cursor_freeze(dbcp);
	    db_mod_sync();
	    UNLOCK_DB ;
	    my_sleep(5);
	    WRLOCK_DB ;
	    db_mod_cursor_unfreeze(dbcp);
    	    if ( expiretime && !denytime_check(expiretime) ) {
		goto done;
    	    }
	    goto run_locked ;
	}
    }

done:
    if ( dbcp )
	db_mod_cursor_close(dbcp);
    UNLOCK_DB ;
    UNLOCK_CONFIG ;
    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "check_expire(): EXPIRE Finished: %d expires, %d seconds, %d total\n",
	    expired_cnt, (utime_t)(global_sec_timer-started), total_cnt);
    snprintf(disk_state_string, sizeof(disk_state_string)-1, "Expire finished: %d expired", expired_cnt);
}

static void
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
