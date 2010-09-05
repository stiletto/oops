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

#define		SWAP_RATE	0

#define		GC_EASY		0
#define		GC_DROP		1

struct	obj_hash_entry	*hash_ptr[HASH_SIZE];
int			hash_cmp(const void*, const void*);

int			clears = 0;

void			swap_out_object(struct mem_obj *);

dataq_t			eraser_queue;

void
flush_mem_cache(int cleanup)
{
int		total_size, kill_size, i, destroyed, gc_mode;
list_t		kill_list;
struct mem_obj	*obj;

  list_init(&kill_list);
    total_size = 0;
    RDLOCK_CONFIG ;
    for (i=0;i<HASH_SIZE;i++) {
	if ( !hash_ptr[i] ) continue;
	if ( hash_ptr[i]->size > 0 ) {
	    total_size += hash_ptr[i]->size;
	} else
	if ( hash_ptr[i]->size < 0 ) {
	    my_xlog(OOPS_LOG_SEVERE, "flush_mem_cache(): Negative hash size.\n");
	    abort();
	}
	/*if ( total_size > lo_mark_val ) break;*/
	continue;
    }
    UNLOCK_CONFIG ;
    my_xlog(OOPS_LOG_STOR, "flush_mem_chache: total_size: %d.\n", total_size);
    if ( total_size < lo_mark_val ) return;
    if ( total_size > mem_max_val ) {
	gc_mode = GC_DROP ;
	my_xlog(OOPS_LOG_STOR, "flush_mem_chache: DROPout documents.\n");
    } else {
	gc_mode = GC_EASY ;
	my_xlog(OOPS_LOG_STOR, "flush_mem_chache: SWAPout documents.\n");
    }
    /* create kill-list */
    kill_size = total_size - lo_mark_val;
    destroyed = 0;
    MY_TNF_PROBE_0(obj_chain_lock_start, "contention", "obj_chain_lock start");
    pthread_mutex_lock(&obj_chain);
    MY_TNF_PROBE_0(obj_chain_lock_stop, "contention", "obj_chain_lock stop");
    obj = oldest_obj;
    while( obj && (kill_size > 0) ) {
	if ( !obj->refs && ( obj->rate <= SWAP_RATE ) ) {
	    destroyed++;
	    kill_size -= obj->resident_size;
	    unlink_obj(obj);
	    list_add(&kill_list, obj);
	    obj = oldest_obj;
	} else
	    obj = obj->younger;
    }
    pthread_mutex_unlock(&obj_chain);
    my_xlog(OOPS_LOG_STOR, "flush_mem_chache: %d documents in kill list.", kill_list.count);
    if ( kill_list.count > 0 ) {
	my_xlog(OOPS_LOG_DBG, "flush_mem_cache(): Will swap/destroy %d objects.\n", kill_list.count);
	RDLOCK_CONFIG ;
	if ( gc_mode == GC_EASY )
#if	defined(USE_INTERNAL_DB_LOCKS)
		RDLOCK_DB;
#else
		WRLOCK_DB;
#endif
	db_mod_attach();
	while ( (obj = list_dequeue(&kill_list)) != 0 ) {
	    my_xlog(OOPS_LOG_STOR|OOPS_LOG_DBG, "flush_mem_cache(): Destroying object <%s/%s>\n",
			obj->url.host, obj->url.path);
	    if ( gc_mode == GC_EASY )
		swap_out_object(obj);
	    destroy_obj(obj);
	}
	db_mod_detach();
	if ( gc_mode == GC_EASY ) UNLOCK_DB;
	UNLOCK_CONFIG ;
    }

    list_destroy(&kill_list);
}

void *
garbage_collector(void* arg)
{
struct	obj_hash_entry	*h = hash_table;
int			i, k;

    if ( arg ) return (void *)0;

    for(i=0;i<HASH_SIZE;i++) hash_ptr[i] = h++;

    forever() {
	RDLOCK_CONFIG ;
	if ( db_in_use == TRUE) {
	    WRLOCK_DB ;
	    db_mod_attach();
	    db_mod_sync();
	    db_mod_detach();
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

	my_xlog(OOPS_LOG_DNS|OOPS_LOG_DBG, "garbage_collector(): %d dns hash entries.\n", k);

	flush_mem_cache(0);

    } /* forever() */
}

int
hash_cmp(const void *a1, const void *a2)
{
struct	obj_hash_entry	*h1 = *(struct obj_hash_entry**)a1,
			*h2 = *(struct obj_hash_entry**)a2;

	if (h1->size > h2->size) return(-1);
	if (h1->size < h2->size) return(1);
	return(0);
}
void
swap_out_object(struct mem_obj *obj)
{
uint32_t		blk;
struct	disk_ref	*chain = NULL;
time_t			now = global_sec_timer;
struct	storage_st	*storage;


    if ( !(obj->flags&FLAG_FROM_DISK) &&
	     db_in_use ) {
	db_api_arg_t	key, data;
	struct disk_ref	*disk_ref;
	int		rc, urll;
	struct	url	*url = &obj->url;
	char		*url_str, time_buf[16];

	if ( TEST(obj->flags, ANSW_HDR_CHANGED) && obj->headers) {
	    /* headers can be changed because of redirect
	       rewrite for example */
	    struct	av	*header;
	    struct	buff	*new_hdrs;

	    header = obj->headers;
	    new_hdrs = alloc_buff(512);
	    if ( new_hdrs ) {
	        while(header) {
	    	attach_av_pair_to_buff(header->attr, header->val, new_hdrs);
	    	header = header->next;
	        }
	        obj->insertion_point = new_hdrs->used-2;
	        obj->tail_length = 4;
	        attach_av_pair_to_buff("", "", new_hdrs);
	        new_hdrs->next = obj->container->next;
	        obj->size += new_hdrs->used - obj->container->used;
	        obj->container->next = NULL;
	        free_container(obj->container);
	        obj->container = new_hdrs;
	    }
	}
	/* add my own headers */
	/* add obj->X-oops-times...*/
	if ( obj->request_time ) {
	    sprintf(time_buf, "%d", (unsigned)obj->request_time);
	    insert_header("X-oops-internal-request-time:",
	    		time_buf, obj);
	}
	if ( obj->response_time ) {
	    sprintf(time_buf, "%d", (unsigned)obj->response_time);
	    insert_header("X-oops-internal-response-time:",
	    		time_buf, obj);
	}
	if ( obj->x_content_length ) {
	    sprintf(time_buf, "%d", obj->x_content_length);
	    insert_header("X-oops-internal-content-length:",
	    		time_buf, obj);
	}
	if ( TEST(obj->flags, ANSW_EXPIRES_ALTERED) ) {
	    sprintf(time_buf, "%d", (unsigned)obj->times.expires);
	    insert_header("X-oops-internal-alt-expires:",
	    		time_buf, obj);
	}
	blk = move_obj_to_storage(obj, &storage, &chain);
	if ( !blk ) goto stored;
	my_xlog(OOPS_LOG_STOR|OOPS_LOG_DBG, "swap_out_object(): Stored in %u of storage %u\n",
		blk, storage->super.id);
	urll = strlen(url->proto)+strlen(url->host)+strlen(url->path)+10;
	urll+= 3 + 1; /* :// + \0 */
	url_str = xmalloc(urll, "swap_out_object(): url_str");
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
	disk_ref->created = global_sec_timer;
	if ( obj->flags & ANSW_HAS_EXPIRES )
	    disk_ref->expires = obj->times.expires ;
	else {
	    if (  obj->times.last_modified &&
	         (last_modified_factor > 0) &&
	         (obj->times.last_modified < now) ) {
	        time_t	delta;
	        delta = (now-obj->times.last_modified)
	    		/last_modified_factor;
	        if ( delta > max_expire_value ) delta = max_expire_value;
	        disk_ref->expires = now + delta;
	        my_xlog(OOPS_LOG_STOR|OOPS_LOG_DBG, "swap_out_object(): Modified %d sec ago (%dd).\n",
	    		now-obj->times.last_modified,
	    		(now-obj->times.last_modified)/(24*3600));
	        my_xlog(OOPS_LOG_STOR|OOPS_LOG_DBG, "swap_out_object(): Will expired %d sec in future (%dd).\n",
	    		delta, delta/(24*3600));
	    }
	    disk_ref->expires = now + default_expire_value ;
	}
	disk_ref->id   = storage->super.id;
	data.data = disk_ref;
	data.size = sizeof(struct disk_ref) + blk*sizeof(uint32_t);
	switch( rc = db_mod_put(&key, &data, obj) ) {
	    case 0:
		break;
	    default:
		if ( rc != DB_API_RES_CODE_EXIST )
			my_xlog(OOPS_LOG_SEVERE, "swap_out_object(): dbp->put failed, rc = %d\n", rc);
		    else
			my_xlog(OOPS_LOG_SEVERE, "swap_out_object('%s'): key exists\n", url_str);
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
}

/* this thread will erase docs from disk immideately if
   we found that document expired or changed
 */
 
void*
eraser(void *arg)
{
eraser_data_t	*ed;

    if ( arg ) return (void*)0;
    dataq_init(&eraser_queue, 128);
    forever() {
	dataq_dequeue(&eraser_queue, (void**)&ed);
	if ( ed ) {
	    if ( ed->url ) my_xlog(OOPS_LOG_STOR, "eraser(): Eraser got %s\n", ed->url);
	    RDLOCK_CONFIG;
	    WRLOCK_DB;
	    if ( ed->url && ed->disk_ref )
		erase_from_disk(ed->url, ed->disk_ref);
	    UNLOCK_DB;
	    UNLOCK_CONFIG;
	    IF_FREE(ed->url);
	    IF_FREE(ed->disk_ref);
	    xfree(ed);
	} else {
	    my_xlog(OOPS_LOG_SEVERE, "eraser(): Null pointer\n");
	}
    }
}
