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
    group = rq_to_group(rq);
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
struct group	*group = NULL;
ip_hash_entry_t	*he = NULL;

    /* LOCK_CONFIG must be done, but this slow things down */
    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH) ) group = rq_to_group(rq);
    if ( group ) {
	pthread_mutex_lock(&group->group_mutex);
	group->cs0.bytes += size;
	pthread_mutex_unlock(&group->group_mutex);
    }
    if ( TEST(rq->flags, RQ_HAVE_PER_IP_BW) ) he = rq->ip_hash_ptr;
    if ( he ) {
	pthread_mutex_lock(&he->lock);
	he->traffic0 += size;
	he->access = global_sec_timer;
	pthread_mutex_unlock(&he->lock);
    }
}

int
traffic_load(struct request *rq)
{
int		bytes, bw;
int		gload = 0, iload = 0 ;
struct group 	*group = NULL;
ip_hash_entry_t	*he = NULL;

    if ( !rq ) return(0);
    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH) ) group = rq_to_group(rq);
    if ( group && (bw = group->bandwidth) ) {
	bytes = MID(bytes);
	gload = (bytes*100)/bw;
    }
    if ( TEST(rq->flags, RQ_HAVE_PER_IP_BW) ) he = rq->ip_hash_ptr;
    if ( he && (bw = rq->per_ip_bw) ) {
	bytes = MID_IP(he);
	iload = (bytes*100)/bw;
    }
    return(MAX(gload,iload));
}

int
sess_traffic_load(struct request *rq)
{
int	cbytes, bw;

    if ( !rq || !(bw = rq->sess_bw) ) return(0);
    cbytes = rq->s0_sent;
    my_xlog(LOG_SEVERE, "Session bw: %d\n", (cbytes*100)/bw);
    return((cbytes*100)/bw);
}

void
update_sess_transfer_rate(struct request *rq, int size)
{
    if ( !rq || ! size ) return;
    if ( rq->last_writing == global_sec_timer )
		rq->s0_sent += size;
        else {
		rq->last_writing = global_sec_timer;
		rq->s0_sent = size;
    }
}

void *
statistics(void *arg)
{
struct group 	 *group;
struct peer	 *peer;
struct oops_stat temp_stat;
int		 counter = 0, i;
int		 hits = 0, reqs = 0;
int		 purge = PURGE_INTERVAL;
ip_hash_entry_t	*he, *next_he;

    if ( arg ) return (void *)0;
    bzero(&oops_stat, sizeof(oops_stat));
    start_time = oops_stat.timestamp0 = oops_stat.timestamp = time(NULL);

    forever() {
	global_sec_timer = time(NULL);

	if ( ++counter == 60 ) {	/* once per minute */

	    LOCK_STATISTICS(oops_stat);
	    memcpy(&temp_stat, &oops_stat, sizeof(oops_stat));
	    oops_stat.requests_http1 = oops_stat.requests_http0;
	    oops_stat.hits1 = oops_stat.hits0;
	    oops_stat.requests_http0 = 0;
	    oops_stat.hits0 = 0;
	    oops_stat.timestamp0 = oops_stat.timestamp;
	    oops_stat.timestamp = global_sec_timer;
	    oops_stat.drops0 = 0;

	    oops_stat.requests_icp1 = oops_stat.requests_icp0;
	    oops_stat.requests_icp0 = 0;
	    if ( oops_stat.requests_http1 > oops_stat.requests_http0_max )
		oops_stat.requests_http0_max = oops_stat.requests_http1;
	    if ( oops_stat.requests_icp1 > oops_stat.requests_icp0_max )
		oops_stat.requests_icp0_max = oops_stat.requests_icp1;
	    if ( oops_stat.hits0_max > oops_stat.hits1 )
		oops_stat.hits0_max = oops_stat.hits1;
	    if ( oops_stat.clients > oops_stat.clients_max )
		oops_stat.clients_max = oops_stat.clients;
#if	HAVE_GETRUSAGE
	    memcpy(&oops_stat.rusage0, &oops_stat.rusage, sizeof(oops_stat.rusage));
	    getrusage(RUSAGE_SELF, &oops_stat.rusage);
#endif
	    UNLOCK_STATISTICS(oops_stat);
	    reqs = temp_stat.requests_http0;
	    hits = temp_stat.hits0;
	    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "statistics(): clients      : %d\n", temp_stat.clients);
	    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "statistics(): http_requests: %d\n", temp_stat.requests_http);
	    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "statistics(): icp_requests : %d\n", temp_stat.requests_icp);
	    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "statistics(): req_rate     : %d/s\n", temp_stat.requests_http0/60);
	    if ( reqs ) my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "statistics(): hits_rate    : %d%%\n", (hits*100)/reqs);
		  else  my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "statistics(): hits_rate    : 0%%\n");
	    counter = 0;
	}

	RDLOCK_CONFIG;
	peer = peers;
	while ( peer ) {
	    if ( !peer->icp_port ) {
		/* this is not icp peer - different up/down ideology */
		peer = peer->next;
		continue;
	    }
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
		/* my_xlog(LOG_DBG, "statistics(): transfer : %d bytes/sec\n", MID(bytes)); */
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
	for (i=0;i<IP_HASH_SIZE;i++) {
	    pthread_mutex_lock(&ip_hash[i].lock);
	    he = ip_hash[i].link;
	    while ( he ) {
		pthread_mutex_lock(&he->lock);
		next_he = he->next;
		he->traffic2 = he->traffic1;
		he->traffic1 = he->traffic0;
		he->traffic0 = 0;
		pthread_mutex_unlock(&he->lock);
		if ( !he->refcount )  {
		    if ( global_sec_timer - he->access >= 10 ) {
			/* unlink and free */
			if ( !he->prev ) {
			    ip_hash[i].link = he->next;
			} else {
			    he->prev->next = he->next;
			}
			if ( he->next ) he->next->prev = he->prev;
			pthread_mutex_destroy(&he->lock);
			free(he);
		    }
		}
		he = next_he;
	    }
	    pthread_mutex_unlock(&ip_hash[i].lock);
	}
	if ( !counter && statisticslog[0] ) {
	  FILE *statl = fopen(statisticslog, "w");

	    if ( statl ) {
		fprintf(statl,"clients      : %d\n", (unsigned)temp_stat.clients);
		fprintf(statl,"uptime       : %ld sec.\n", (utime_t)(global_sec_timer-start_time));
		fprintf(statl,"http_requests: %d\n", (unsigned)temp_stat.requests_http);
		fprintf(statl,"http_hits    : %d\n", (unsigned)temp_stat.hits);
		fprintf(statl,"icp_requests : %d\n", (unsigned)temp_stat.requests_icp);
		fprintf(statl,"req_rate     : %d/s\n", (unsigned)(temp_stat.requests_http0/60));
		if ( reqs ) fprintf(statl,"hits_rate    : %d%%\n", (hits*100)/reqs);
		      else  fprintf(statl,"hits_rate    : 0%%\n");
		fprintf(statl,"free_space   : %u%%\n", (unsigned)temp_stat.storages_free);
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

    if ( !dstd_entry ) return;
    if ( global_sec_timer - dstd_entry->when_created > DSTD_CACHE_TTL ) {
	add_to_string_list(&purged_entries, key);
    }
}
