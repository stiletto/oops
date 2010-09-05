#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <time.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <pthread.h>

#include <netinet/in.h>

#include <db.h>

#include "oops.h"

#define	GC_EASY		0
#define	GC_DROP		1

struct	hash_entry	*hash_ptr[HASH_SIZE];
int			hash_cmp(const void*, const void*);

int			total_alloc = 0;

int			clears = 0;

void*
garbage_collector(void* arg)
{
int			i, k;
struct	hash_entry	*h = hash_table, *hash_back;
int			total_size, last_non_zero, sbrk_size, obj_size, destroyed;
int			gc_mode;
struct	mem_obj		*obj;
struct	storage_st	*storage;
uint32_t		blk;
struct	disk_ref	*chain;
time_t			now;

    for(i=0;i<HASH_SIZE;i++) hash_ptr[i] = h++;

    while(1) {
	RDLOCK_CONFIG ;
	if ( dbp ) {
	    WRLOCK_DB ;
	    dbp->sync(dbp, 0);
	    UNLOCK_DB ;
	}
	UNLOCK_CONFIG ;
	my_sleep(9);

	/* clean dns hash */
	k = 0;
	pthread_mutex_lock(&dns_cache_lock);
	for(i=0; i< DNS_HASH_SIZE; i++) {
	    struct dns_cache	*dns_cp;

	    if ( !dns_hash[i].first )
		goto next_dns;
	    k++;
	    if ( global_sec_timer - dns_hash[i].first->time <  dns_ttl )
		goto next_dns;
	    /* have to clean something from here */
	    while( dns_hash[i].first && 
		  (global_sec_timer - dns_hash[i].first->time >=  dns_ttl ) ) {
		dns_cp = dns_hash[i].first->next;
		free_dns_hash_entry(dns_hash[i].first);
		dns_hash[i].first = dns_cp;
		if ( !dns_cp )
		    dns_hash[i].last = NULL;
	    }
	next_dns:;
	}
	pthread_mutex_unlock(&dns_cache_lock);

	my_xlog(LOG_DNS, "%d dns hash entries\n", k);
	last_non_zero = 0;

    resort:
	h = hash_table;
	obj_size = 0;
	for(i=0;i<HASH_SIZE;i++) {
	    if ( hash_ptr[i]->size > 0 ) {
		obj_size += hash_ptr[i]->size;
	    } else
	    if ( hash_ptr[i]->size < 0 ) {
		my_log("Negative hash size\n");
		abort();
	    }
	    continue;
	}

	sbrk_size = (unsigned)sbrk(0) - (unsigned)startup_sbrk;
	total_size = obj_size;

/*	my_log("Clients in service:  %d\n", clients_number);
	my_log("Total obj size:      %dk\n", obj_size/1024);
        my_log("Total objects:       %d\n", total_objects);
	my_log("Total sbrk size:     %dk\n", sbrk_size/1024);
*/
	/* select hash entry to free */
	if ( total_size <  lo_mark_val ) {
		my_xlog(LOG_STOR, "Total size %dk - too small\n", total_size/1024);
#if	defined(MALLOCDEBUG)
		list_all_mallocs();
#endif
		continue;
	}

	if ( total_size > mem_max_val ) {
	    gc_mode = GC_DROP ; 
	} else
	    gc_mode = GC_EASY ;

	now = time(NULL);	/* I will not call time for each obj	*/
	destroyed = 0;
	pthread_mutex_lock(&obj_chain);
    set_on_oldest:
	obj=oldest_obj;
	if ( obj ) {
    do_destr:
	    hash_back = obj->hash_back ;
	    pthread_mutex_lock(&hash_back->lock);
	    if ( !obj->refs ) {
		if ( gc_mode == GC_DROP ) {
		    /* we have no time to save object, just drop it */
		    total_size -= obj->resident_size;
		    destroy_obj(obj);
		    destroyed++;
		    pthread_mutex_unlock(&hash_back->lock);
		    if ( destroyed >= 100 ||
				total_size <= lo_mark_val ||
				total_size <= 0 ) {
			pthread_mutex_unlock(&obj_chain);
			goto resort;
		    }
		    goto set_on_oldest;
		}
		my_xlog(LOG_STOR, "Destroy oldest object <%s/%s>\n",
			obj->url.host, obj->url.path);
		chain = NULL;
		/* XXX */
		RDLOCK_CONFIG ;
		WRLOCK_DB ;
		if ( !(obj->flags&FLAG_FROM_DISK) &&
		     dbp ) {
		    DBT			key, data;
		    struct disk_ref	*disk_ref;
		    int			rc, urll;
		    struct	url	*url = &obj->url;
		    char		*url_str, time_buf[16];

		    /* add my own headers */
		    /* add obj->X-oops-times...*/
		    if ( obj->request_time ) {
			sprintf(time_buf, "%d", obj->request_time);
			insert_header("X-oops-internal-request-time:",
					time_buf, obj);
		    }
		    if ( obj->response_time ) {
			sprintf(time_buf, "%d", obj->response_time);
			insert_header("X-oops-internal-response-time:",
					time_buf, obj);
		    }
		    blk = move_obj_to_storage(obj, &storage, &chain);
		    if ( !blk ) goto o_written;
		    my_xlog(LOG_STOR, "Stored in %u of storage %u\n", blk, storage->super.id);
		    urll = strlen(url->proto)+strlen(url->host)+strlen(url->path)+10;
		    urll+= 3 + 1; /* :// + \0 */
		    url_str = xmalloc(urll, "url_str");
		    if ( !url_str ) {
			WRLOCK_STORAGE(storage);
			release_blks(blk, storage, chain);
			UNLOCK_STORAGE(storage);
			if (chain) xfree(chain);
			goto stored;
		    }
		    if ( obj->doc_type == HTTP_DOC )
			sprintf(url_str,"%s%s:%d", url->host, url->path, url->port);
		    else
			sprintf(url_str,"%s://%s%s:%d", url->proto, url->host, url->path, url->port);
		    /* insert this url in DB */
		    bzero(&key, sizeof(key));
		    bzero(&data,sizeof(data));
		    key.data  = url_str;
		    key.size  = strlen(url_str);
		    disk_ref = (struct disk_ref*)chain;
		    disk_ref->size = obj->size;
		    disk_ref->blk  = blk ;
		    if ( obj->flags & ANSW_HAS_EXPIRES )
			disk_ref->expires = obj->times.expires ;
		    else
			disk_ref->expires = now + default_expire_value ;
		    disk_ref->id   = storage->super.id;
		    data.data = disk_ref;
		    data.size = sizeof(struct disk_ref) + blk*sizeof(uint32_t);
		    switch( rc = dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE) ) {
			case 0:
				break;
			default:
				my_log("dbp->put failed, rc: %d\n", rc);
				/* release allocated blocks */
				WRLOCK_STORAGE(storage);
				release_blks(blk, storage, disk_ref);
				UNLOCK_STORAGE(storage);
				break;			
		    }
		    xfree(url_str);
		    if (chain) xfree(chain);
		stored:;
		}
    o_written:
		UNLOCK_DB ;
		UNLOCK_CONFIG ;
		destroy_obj(obj);
		destroyed++;
	    }
	    pthread_mutex_unlock(&hash_back->lock);
	    if ( destroyed ) {
		pthread_mutex_unlock(&obj_chain);
	    	goto resort;
	    }
	    obj = obj->younger;
	    if ( obj )
		goto do_destr;
	    pthread_mutex_unlock(&obj_chain);
	    my_sleep(3);
	    goto resort;
	} /* if (obj) */
	pthread_mutex_unlock(&obj_chain);
    } /* while(1) */
}

int
hash_cmp(const void *a1, const void *a2)
{
struct	hash_entry	*h1 = *(struct hash_entry**)a1,
			*h2 = *(struct hash_entry**)a2;

	if (h1->size > h2->size) return(-1);
	if (h1->size < h2->size) return(1);
	return(0);
}
