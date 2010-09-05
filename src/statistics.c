#include        <stdio.h>
#include        <stdlib.h>
#include        <fcntl.h>
#include        <errno.h>
#include        <stdarg.h>
#include        <strings.h>
#include        <netdb.h>
#include        <unistd.h>
#include        <ctype.h>
#include        <signal.h>
#include	<time.h>

#include        <sys/param.h>
#include        <sys/socket.h>
#include        <sys/types.h>
#include        <sys/stat.h>
#include        <sys/file.h>
#include	<sys/time.h>

#include        <netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"

#define		MID3(a,b,c)	((40*a+30*b+30*c)/100)

#define		PURGE_INTERVAL	5
#define		DSTD_CACHE_TTL	(30*60)

void		purge_old_dstd(void*, void*,void*);
static	void	destroy_entries(hash_t*, struct string_list*);
static	struct	string_list *purged_entries = NULL;

void
check_transfer_rate(struct request *rq, int size)
{
struct group	*group ;
int		cbytes, bw;

    /* LOCK_CONFIG must be done, but this slow things down */
    group = inet_to_group(&rq->client_sa.sin_addr);
    if ( group ) {
	bw = group->bandwidth;
	cbytes = MID(bytes);
	if ( cbytes < bw )
	    return;
	/* must sleep a little. */
	my_sleep(1);
    }
}

void
update_transfer_rate(struct request *rq, int size)
{
struct group	*group ;

    /* LOCK_CONFIG must be done, but this slow things down */
    group = inet_to_group(&rq->client_sa.sin_addr);
    if ( group ) {
	pthread_mutex_lock(&group->group_mutex);
	group->cs0.bytes += size;
	pthread_mutex_unlock(&group->group_mutex);
    }
}

int
group_traffic_load(struct group *group)
{
int	cbytes, bw;

     if ( !group ) /* this can happens during reconfigure */
	return(0);
     if ( !(bw = group->bandwidth) ) return(0);
     cbytes = MID(bytes);
     return((cbytes*100)/bw);
}

void*
statistics(void *arg)
{
struct group 	 *group;
struct peer	 *peer;
struct oops_stat temp_stat;
int		 counter = 0;
int		 hits, reqs;
int		 purge = PURGE_INTERVAL;

    arg = arg;
    start_time = time(NULL);

    while(1) {
	global_sec_timer = time(NULL);

	if ( ++counter == 60 ) {	/* once per minute */

	    LOCK_STATISTICS(oops_stat);
	    memcpy(&temp_stat, &oops_stat, sizeof(oops_stat));
	    oops_stat.requests_http1 = oops_stat.requests_http0;
	    oops_stat.hits1 = oops_stat.hits0;
	    oops_stat.requests_http0 = 0;
	    oops_stat.hits0 = 0;
	    UNLOCK_STATISTICS(oops_stat);
	    reqs = temp_stat.requests_http0;
	    hits = temp_stat.hits0;
	    my_log("Statistics: clients      : %d\n", temp_stat.clients);
	    my_log("Statistics: http_requests: %d\n", temp_stat.requests_http);
	    my_log("Statistics: icp_requests : %d\n", temp_stat.requests_icp);
	    my_log("Statistics: req_rate     : %d/s\n", temp_stat.requests_http0/60);
	    if ( reqs ) my_log("Statistics: hits_rate    : %d%%\n", (hits*100)/reqs);
		  else  my_log("Statistics: hits_rate    : 0%%\n");
	    counter = 0;
	}

	RDLOCK_CONFIG;
	peer = peers;
	while ( peer ) {
	    if ( ABS(peer->last_recv - peer->last_sent) > peer_down_interval ) {
		peer->state |=  PEER_DOWN ;
	    } else {
		peer->state &= ~PEER_DOWN ;
	    }
	    peer = peer->next;
	}
	/* run over all groups and move statistics */
	group = groups ;
	if ( group ) {
	    while ( group ) {
		/*my_log("transfer : %d bytes/sec\n", MID(bytes));*/
		pthread_mutex_lock(&group->group_mutex);
		group->cs_total.bytes += group->cs0.bytes;
		group->cs_total.requests += group->cs0.requests;
		group->cs2 = group->cs1;
		group->cs1 = group->cs0;
		memset((void*)&group->cs0, 0, sizeof(group->cs0));
		pthread_mutex_unlock(&group->group_mutex);

		/* remove stale dstdomain cache entries */
		if ( group->dstdomain_cache ) {
		    if ( purge <= 0 ) {
			hash_operate(group->dstdomain_cache, purge_old_dstd, NULL);
			if ( purged_entries ) {
			    /* */
			    destroy_entries(group->dstdomain_cache, purged_entries);
			    free_string_list(purged_entries);
			    purged_entries = NULL;
			}
			purge = PURGE_INTERVAL;
		    } else
			purge--;
		}
		group = group->next;
	    }
	}
	if ( !counter && statisticslog[0] ) {
	  FILE *statl = fopen(statisticslog, "w");

	    if ( statl ) {
		fprintf(statl,"clients      : %d\n", temp_stat.clients);
		fprintf(statl,"uptime       : %d sec. (%d day(s))\n",
			(unsigned int)global_sec_timer-start_time,
			(unsigned int)(global_sec_timer-start_time)/86400);
		fprintf(statl,"http_requests: %d\n", temp_stat.requests_http);
		fprintf(statl,"http_hits    : %d\n", temp_stat.hits);
		fprintf(statl,"icp_requests : %d\n", temp_stat.requests_icp);
		fprintf(statl,"req_rate     : %d/s\n", temp_stat.requests_http0/60);
		if ( reqs ) fprintf(statl,"hits_rate    : %d%%\n", (hits*100)/reqs);
		      else  fprintf(statl,"hits_rate    : 0%%\n");
		fprintf(statl,"free_space   : %d%%\n", temp_stat.storages_free);
		fclose(statl);
	    }
	}
	UNLOCK_CONFIG;

	my_sleep(1);
    }
}

/* realy delete */
void
destroy_entries(hash_t *tbl, struct string_list *list)
{
struct dstdomain_cache_entry **dstd_ce, *dstd_ce_data;

    if ( !tbl ) return;

    while( list ) {
	dstd_ce = (struct dstdomain_cache_entry **)hash_get(tbl, list->string);
	if ( dstd_ce ) {
	    dstd_ce_data = (struct dstdomain_cache_entry *)*dstd_ce;
	    if ( dstd_ce_data ) xfree(dstd_ce_data);
	    *dstd_ce = NULL;
	    hash_delete(tbl, (void**)dstd_ce);
	}
	list = list->next;
    }
}

/* create list for further deletion */

void
purge_old_dstd(void *a1, void *a2, void *a3)
{
struct dstdomain_cache_entry *dstd_entry = (struct dstdomain_cache_entry *)a1;
char			     *key = (char*)a3;

    if ( global_sec_timer - dstd_entry->when_created > DSTD_CACHE_TTL ) {
	add_to_string_list(&purged_entries, key);
    }
}
