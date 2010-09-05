/*
Copyright (C) 1999, 2000 Igor Khasilev, igor@paco.net
Copyright (C) 2000 Andrey Igoshin, ai@vsu.ru

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

#include	"modules.h"
extern struct	err_module	*err_first;

#define		READ_REQ_TIMEOUT	(10*60)		/* 10 minutes */
#define		READ_BUFF_SZ		(1500)

#define		REQUEST_EMPTY	0
#define		REQUEST_READY	1

void		free_url(struct url *url);
void		free_request(struct request *rq);
void		leave_obj(struct mem_obj *);
u_short		hash(struct url *url);
void		send_not_cached(int so, struct request *rq, char *hdrs);
int		parse_http_request(char *start, struct request *rq, int so);
int		check_headers(struct request *rq, char *beg, char *end, int *checked, int so);
int		parse_url(char*, char*, struct url *, int);
void		release_obj(struct mem_obj*);
void		send_from_mem(int, struct request *, char* , struct mem_obj*, int);
void		increment_clients(void);
void		decrement_clients(void);
void		make_purge(int, struct request *);
int		parse_connect_url(char* src, char *httpv, struct url *url, int so);
void		insert_request_in_hash(struct request *);
void		remove_request_from_hash(struct request *);
void		insert_request_in_ip_hash(struct request *);
void		remove_request_from_ip_hash(struct request *);

#if	defined(DEMO)
static	int	served = 0;
#endif

void*
run_client(void *arg)
{
u_char			*buf = NULL;
int			got, rc;
u_char			*cp, *ip;
char			*headers;
struct	request		request;
time_t			started;
struct	mem_obj		*stored_url;
size_t			current_size;
int			status, checked_len = 0, mod_flags;
int			mem_send_flags = 0;
socklen_t		clsalen = sizeof(request.client_sa);
socklen_t		mysalen = sizeof(request.my_sa);
struct	group		*group;
int			miss_denied = TRUE;
int			so, new_object, redir_mods_visited, auth_mods_visited;
int			accepted_so;
struct	work		*work;

    work = (struct work*)arg;
    if ( !work ) return(NULL);
    so = work->so;
    accepted_so = work->accepted_so;
    xfree(work);	/* we don't need it anymore	*/

    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(LOG_SEVERE, "run_client(): fcntl(): %m\n");

    increment_clients();
    set_socket_options(so);

    /* here we go if client want persistent connection */
    bzero(&request, sizeof(request));
    request.accepted_so = accepted_so;
    request.so = so;
    getpeername(so, (struct sockaddr*)&request.client_sa, &clsalen);
    getsockname(so, (struct sockaddr*)&request.my_sa, &mysalen);
    request.request_time = started = time(NULL);
    insert_request_in_hash(&request);
    insert_request_in_ip_hash(&request);
    redir_mods_visited = FALSE;
    auth_mods_visited  = FALSE;
    buf = xmalloc(READ_BUFF_SZ, "run_client(): For client request.");
    if ( !buf ) {
	my_xlog(LOG_SEVERE, "run_client(): No mem for header!\n");
	goto done;
    }
    current_size = READ_BUFF_SZ;
    cp = buf; ip = buf;

    forever() {
	got = readt(so, (char*)cp, current_size-(cp-ip), 100);
	if ( got == 0 ) {
	    my_xlog(LOG_FTP|LOG_HTTP|LOG_DBG, "run_client(): Client closed connection.\n");
	    goto done;
	}
	if ( got == -2 ) {
	    my_xlog(LOG_HTTP|LOG_FTP|LOG_DBG, "Read client input timeout.\n");
	    if ( time(NULL) - started > READ_REQ_TIMEOUT ) {
		my_xlog(LOG_HTTP|LOG_FTP|LOG_DBG, "run_client(): Client send too slow.\n");
		goto done;
	    }
	    continue;
	}
	if ( got <  0 ) {
	    my_xlog(LOG_HTTP|LOG_FTP|LOG_DBG, "run_client(): Failed to read from client.\n");
	    goto done;
	}
	cp += got;
	if ( (unsigned)(cp - ip) >= current_size ) {
	    char *nb = xmalloc(current_size+CHUNK_SIZE, "run_client(): new block");
	    /* resize buf */
	    if ( !nb ) {
		my_xlog(LOG_SEVERE, "run_client(): No mem to read request.\n");
		goto done;
	    }	    
	    memcpy(nb, buf, current_size);
	    xfree(buf);
	    buf=ip=(u_char*)nb;
	    cp=ip+current_size;
	    *cp=0;
	    current_size=current_size+CHUNK_SIZE;
	} else
	    *cp=0;
	status = check_headers(&request, (char*)ip, (char*)cp, &checked_len, so);
	if ( status ) {
	    my_xlog(LOG_HTTP|LOG_FTP|LOG_DBG, "run_client(): Failed to check headers.\n");
	    say_bad_request(so, "Bad request format.\n", "",
		    ERR_BAD_URL, &request);
	    goto done;
	}
	if ( request.state == REQUEST_READY )
	    break;
    }
    if ( request.headers_off <= 0 ) {
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "run_client(): Something wrong with headers_off: %d\n", request.headers_off);
	goto done;
    }
    headers = (char*)buf + request.headers_off;
    RDLOCK_CONFIG ;
ck_group:
    group = rq_to_group(&request);
    if ( ! group ) {
	UNLOCK_CONFIG;
	say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
	    ERR_ACC_DENIED, &request);
	goto done;
    }
    miss_denied = group->miss_deny;
    if ( (rc = deny_http_access(so, &request, group)) != 0 ) {
	UNLOCK_CONFIG ;
	my_xlog(LOG_HTTP|LOG_FTP|LOG_DBG, "run_client(): Access banned.\n");
	switch ( rc ) {
	case ACCESS_PORT:
		say_bad_request(so, "<font color=red>Access denied for requestsd port.\n</font>", "",
			ERR_BAD_PORT, &request);
		break;
	case ACCESS_DOMAIN:
		say_bad_request(so, "<font color=red>Access denied for requested domain.\n</font>", "",
			ERR_ACC_DOMAIN, &request);
		break;
	case ACCESS_METHOD:
		say_bad_request(so, "<font color=red>Access denied for requestsd method.\n</font>", "",
			ERR_BAD_PORT, &request);
		break;
	default:
		say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
			ERR_ACC_DENIED, &request);
		break;
	}
	IF_STRDUP(request.tag, "TCP_DENIED");
	request.code = 555;
	log_access(0, &request, NULL);
	goto done;
    }
    if ( !group ) {
	UNLOCK_CONFIG ;
	goto done;
    }
    if ( group->denytimes && (rc = denytime_check(group->denytimes)) ) {
	UNLOCK_CONFIG ;
	say_bad_request(so, "<font color=red>Your access to proxy service denied at this time.\n</font>", "",
		ERR_ACC_DENIED, &request);
	IF_STRDUP(request.tag,"TCP_DENIED");
	IF_STRDUP(request.source, "DENY_TIME");
	request.code = 555;
	log_access(0, &request, NULL);
	goto done;
    }
    /* copy redir modules reference to struct request, so we will
       not lookup for group again
    */
    if ( !redir_mods_visited ) {
	mod_flags = 0;
	request.redir_mods = lock_l_string_list(group->redir_mods);
	/* check for redirects */
	if ( check_redirect(so, &request, group, &mod_flags) ) {
	    UNLOCK_CONFIG;
	    goto done;
	}
	redir_mods_visited = TRUE;
	if ( TEST(mod_flags, MOD_AFLAG_CKACC) )
	    goto ck_group;	/* we must get group again, as it my-be 
				   changed because of redir		*/
    }
    if ( !auth_mods_visited ) {
	/* time to visit auth modules */
	mod_flags = 0;
	if ( check_auth(so, &request, group, &mod_flags) == MOD_CODE_ERR) {
	    UNLOCK_CONFIG;
	    if ( !TEST(mod_flags, MOD_AFLAG_OUT) ) {
		/* there was no output */
		say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
			ERR_ACC_DENIED, &request);
	    }
	    IF_STRDUP(request.tag, "TCP_DENIED");
	    IF_STRDUP(request.source, "AUTH_MOD");
	    request.code = 555;
	    log_access(0, &request, NULL);
	    goto done;
	}
	auth_mods_visited = TRUE;
	if ( TEST(mod_flags, MOD_AFLAG_CKACC) )
	    goto ck_group;	/* we must get group again, as it my-be 
				   changed because of redir		*/
    }

    if ( acl_deny && (check_acl_access(acl_deny, &request) == TRUE) ) {
	UNLOCK_CONFIG;
	say_bad_request(so, "Please contact cachemaster\n",
			     request.matched_acl, ERR_ACL_DENIED, &request);
	goto done;
    }
    if (   !request.refresh_pattern.valid	/* if not set by redir mods 	*/
	   && global_refresh_pattern )		/* and we have global refr_patt	*/

	set_refresh_pattern(&request, global_refresh_pattern);

    if ( group && group->bandwidth )
	request.flags |= RQ_HAS_BANDWIDTH;
    if ( group && group->per_sess_bw )
	request.sess_bw = group->per_sess_bw;
    if ( group && group->per_ip_bw ) {
	request.flags |= RQ_HAVE_PER_IP_BW;
	request.per_ip_bw = group->per_ip_bw;
    }
    if ( request.ip_hash_ptr &&
	 group->per_ip_conn &&
	 (request.ip_hash_ptr->refcount > group->per_ip_conn) ) {
	UNLOCK_CONFIG;
	say_bad_request(so, "Please contact cachemaster\n",
			     "Connections limit.", ERR_ACC_DENIED, &request);
	goto done;
    }
    pthread_mutex_lock(&group->group_mutex);
    group->cs0.requests++;
    pthread_mutex_unlock(&group->group_mutex);
    if ( group->maxreqrate && (group->cs0.requests > group->maxreqrate) ) {
	/* request rate limit reached, drop connection 	*/
	/* this is crude and must be used as last resort	*/
	UNLOCK_CONFIG ;
	goto done;
    }

    UNLOCK_CONFIG ;

    /* now:
	buf  - contain complete client request
    */

    if ( request.url.proto && !strcasecmp(request.url.proto, "http") )
	request.proto = PROTO_HTTP;
      else
    if ( request.url.proto && !strcasecmp(request.url.proto, "ftp") )
	request.proto = PROTO_FTP;
      else
	request.proto = PROTO_OTHER;
    /* if request state to send not cached info - send directly from origin */
    if ( request.meth == METH_CONNECT ) {
	if ( miss_denied ) {
	    say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
		ERR_ACC_DENIED, &request);
	    goto done;
	}
	/* make ssl connect	*/
	send_ssl(so, &request);
	goto done;
    }

    if ( request.meth == METH_PURGE ) {
	make_purge(so, &request);
	goto done;
    }

    if ( !request.url.host || !request.url.host[0] ) {
	    say_bad_request(so, "No host part in URL\n", "",
		    ERR_BAD_URL, &request);
	    goto done;
    }

    if ( (request.proto != PROTO_FTP)   && /* ftp processed below */
	((!request.meth==METH_GET) 		||
	 ( request.flags & RQ_HAS_NO_STORE) 	||
	 ( request.flags & RQ_HAS_AUTHORIZATION)||
	 ( request.url.login )) ) {
	if ( miss_denied ) {
	    say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
		ERR_ACC_DENIED, &request);
	    goto done;
	}
	send_not_cached(so, &request, headers);
	CLOSE(so); so = -1;
	goto done;
    }
    if ( (request.proto != PROTO_FTP) && !request.refresh_pattern.valid && in_stop_cache(&request) ) {
	if ( miss_denied ) {
	    say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
		ERR_ACC_DENIED, &request);
	    goto done;
	}
	send_not_cached(so, &request, headers);
	CLOSE(so); so = -1;
	goto done;
    }
    if ( request.flags & RQ_HAS_ONLY_IF_CACHED ) {
	stored_url = locate_in_mem(&request.url, AND_USE, &new_object, &request);
	if ( !stored_url ) {
	    send_error(so, 504, "Gateway Timeout. Or not in cache");
	    goto done;
	}
	send_from_mem(so, &request, headers, stored_url, mem_send_flags);
	CLOSE(so); so = -1;
	leave_obj(stored_url);
	goto done;
    }

    if ( always_check_freshness && (request.proto == PROTO_HTTP) )
	mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
    if ( request.flags & RQ_HAS_NO_CACHE )
	mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
    if ( request.flags &
	(RQ_HAS_MAX_AGE|RQ_HAS_MAX_STALE|RQ_HAS_MIN_FRESH) ) {
	stored_url = locate_in_mem(&request.url, AND_USE|AND_PUT, &new_object, &request);
	if ( !stored_url ) {
	    my_xlog(LOG_SEVERE, "run_client(): Can't create or find memory object.\n");
	    say_bad_request(so, "Can't create memory object.\n", "No memory?",
	    	ERR_INTERNAL, &request);
	    goto done;
	}
	if ( new_object ) {
	    /* it is new object, it probably can be stored	*/
	    /* it can be forwarded to client			*/
	    goto read_net;
	}

	if ( !(request.flags & MEM_OBJ_MUST_REVALIDATE) &&
	      (request.flags & RQ_HAS_MAX_AGE) ) {
	    time_t age = current_obj_age(stored_url);
	    if ( age > request.max_age ) {
		mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
	    }
	}

	if ( !(request.flags & MEM_OBJ_MUST_REVALIDATE) &&
	      (request.flags & RQ_HAS_MAX_STALE) ) {
	    time_t freshness_lifetime;
	    time_t freshness_val = obj_freshness_lifetime(stored_url);
	
	    if ( freshness_val < 0 ) {
		/* this is heuristic */
		freshness_lifetime = -freshness_val;
		mem_send_flags |= MEM_OBJ_WARNING_113;
	    } else
		freshness_lifetime = freshness_val;
	    if ( freshness_lifetime < request.max_stale ) {
		my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "run_client(): Must revalidate: freshness_lifetime = %d, request.max_stale: %d\n",
				freshness_lifetime, request.max_stale);
		mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
	    } else {
		/* we probably will send stale document - need warning */
		if ( freshness_lifetime < current_obj_age(stored_url) )
		    mem_send_flags |= MEM_OBJ_WARNING_110;
	    }
	}

	if ( !(request.flags & MEM_OBJ_MUST_REVALIDATE) &&
	      (request.flags & RQ_HAS_MAX_STALE) ) {
	    time_t freshness_lifetime;
	    time_t freshness_val = obj_freshness_lifetime(stored_url);
	    if ( freshness_val < 0 ) {
		/* this is heuristic */
		freshness_lifetime = -freshness_val;
		mem_send_flags |= MEM_OBJ_WARNING_113;
	    } else
		freshness_lifetime = freshness_val;
	    if ( freshness_lifetime < current_obj_age(stored_url) + request.min_fresh)
		mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
	}
	if ( !TEST(mem_send_flags, MEM_OBJ_MUST_REVALIDATE) 
		&& always_check_freshness_acl
		&& obj_check_acl_access(always_check_freshness_acl, stored_url, &request) )
		mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
	send_from_mem(so, &request, headers, stored_url, mem_send_flags);
	CLOSE(so); so = -1;
	leave_obj(stored_url);
	goto done;
    }
    stored_url = locate_in_mem(&request.url, AND_PUT|AND_USE, &new_object, &request);
    if ( !stored_url ) {
	my_xlog(LOG_SEVERE, "run_client(): Can't create or find memory object.\n");
	say_bad_request(so, "Can't create memory object.\n", "No memory?",
		ERR_INTERNAL, &request);
	goto done;
    }

    if ( new_object ) {
read_net:
	my_xlog(LOG_HTTP|LOG_FTP|LOG_DBG, "run_client(): read <%s><%s><%d><%s> from the net.\n",
		request.url.proto, request.url.host, request.url.port, request.url.path);
	if ( miss_denied ) {
	    say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
		ERR_ACC_DENIED, &request);
	    stored_url->flags |= FLAG_DEAD;
	} else {
	    if ( !strcasecmp(request.url.proto, "ftp") )
		ftp_fill_mem_obj(so, &request, headers, stored_url);
	    else if ( !strcasecmp(request.url.proto, "http") )
		fill_mem_obj(so, &request, headers, stored_url, 0, 0, NULL);
	    else {
		say_bad_request(so, "Unsupported protocol\n", request.url.proto,
		    ERR_BAD_URL, &request);
		stored_url->flags |= FLAG_DEAD;
	    }
	}
	CLOSE(so); so = -1;
	leave_obj(stored_url);
    } else {
	if ( stored_url->flags & ANSW_HAS_MAX_AGE ) {
	    time_t age = current_obj_age(stored_url);
	    if ( stored_url->times.max_age &&
	         (age > stored_url->times.max_age) ) {
		mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
	    }
	}
	if ( TEST(stored_url->flags, ANSW_HAS_EXPIRES) ) {
	     if ( stored_url->times.expires < global_sec_timer )
		mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
	}
	if ( !TEST(mem_send_flags, MEM_OBJ_MUST_REVALIDATE) 
		&& always_check_freshness_acl
		&& obj_check_acl_access(always_check_freshness_acl, stored_url, &request) )
		mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
	my_xlog(LOG_HTTP|LOG_FTP|LOG_DBG, "run_client(): read <%s:%s:%s> from mem.\n",
		request.url.proto, request.url.host, request.url.path);
	send_from_mem(so, &request, headers, stored_url, mem_send_flags);
	CLOSE(so); so = -1;
        leave_obj(stored_url);
    }
/*persistent:*/

done:
    IF_FREE(buf);
    remove_request_from_hash(&request);
    free_request(&request);
    if ( so != -1 ) CLOSE(so);
    decrement_clients();
    LOCK_STATISTICS(oops_stat);
	oops_stat.requests_http++;
	oops_stat.requests_http0++;
    UNLOCK_STATISTICS(oops_stat);
    return(NULL);
}

/* create absolutely empty object	*/
/* which is not included in any lists	*/

struct mem_obj*
create_temp_obj()
{
struct mem_obj	*obj = NULL;

    obj = xmalloc(sizeof(*obj), "create_temp_obj(): 1");
    if ( !obj )
	return(NULL);
    bzero(obj, sizeof(*obj));
    pthread_mutex_init(&obj->lock, NULL);
    pthread_mutex_init(&obj->state_lock, NULL);
    pthread_cond_init(&obj->state_cond, NULL);
    return(obj);
}

void
destroy_temp_obj(struct mem_obj *obj)
{
    free_url(&obj->url);
    free_container(obj->container);
    free_avlist(obj->headers);
    pthread_mutex_destroy(&obj->lock);
    pthread_mutex_destroy(&obj->state_lock);
    pthread_cond_destroy(&obj->state_cond);
    xfree(obj);
}

void
unlink_obj(struct mem_obj *obj)
{
    if ( obj->prev ) obj->prev->next=obj->next;
    if ( obj->next ) obj->next->prev=obj->prev;
    if ( obj->older )
	obj->older->younger = obj->younger;
    if ( obj->younger )
	obj->younger->older = obj->older;
    if ( youngest_obj == obj ) {
	youngest_obj = obj->older;
    }
    if ( oldest_obj == obj ) {
	oldest_obj = obj->younger;
    }
    decrease_hash_size(obj->hash_back, obj->resident_size);
    obj->hash_back = NULL;
    obj->prev = obj->next = obj->older = obj->younger = NULL;
}

void
destroy_obj(struct mem_obj *obj)
{
    if ( obj->prev ) obj->prev->next=obj->next;
    if ( obj->next ) obj->next->prev=obj->prev;
    if ( obj->older )
	obj->older->younger = obj->younger;
    if ( obj->younger )
	obj->younger->older = obj->older;
    if ( youngest_obj == obj ) {
	youngest_obj = obj->older;
    }
    if ( oldest_obj == obj ) {
	oldest_obj = obj->younger;
    }
    free_url(&obj->url);
    free_container(obj->container);
    free_avlist(obj->headers);
    IF_FREE(obj->disk_ref);
    pthread_mutex_destroy(&obj->lock);
    pthread_mutex_destroy(&obj->state_lock);
    pthread_cond_destroy(&obj->state_cond);
    pthread_mutex_destroy(&obj->decision_lock);
    pthread_cond_destroy(&obj->decision_cond);
    decrease_hash_size(obj->hash_back, obj->resident_size);
    --total_objects;
    xfree(obj);
}

struct mem_obj*
locate_in_mem(struct url *url, int flags, int *new_object, struct request *rq)
{
struct	mem_obj	*obj=NULL;
u_short 	url_hash = hash(url);
int		found=0, mod_flags = 0;

    if ( new_object ) *new_object = FALSE;
    if ( pthread_mutex_lock(&obj_chain) ) {
	fprintf(stderr, "locate_in_mem(): Failed mutex lock.\n");
	return(NULL);
    }
    /* lock hash entry */
    if ( pthread_mutex_lock(&hash_table[url_hash].lock) ) {
	fprintf(stderr, "locate_in_mem(): Failed mutex lock\n");
	pthread_mutex_unlock(&obj_chain);
	return(NULL);
    }
	obj=hash_table[url_hash].next;
	if ( !(flags & PUT_NEW_ANYWAY) ) while(obj) {
	    if ( (url->port==obj->url.port) &&
	         !strcmp(url->path, obj->url.path) &&
	         !strcasecmp(url->host, obj->url.host) &&
	         !strcasecmp(url->proto, obj->url.proto) &&
	         !(obj->flags & (FLAG_DEAD|ANSW_NO_CACHE)) &&
		 (!TEST(flags, READY_ONLY) || (obj->state==OBJ_READY) )
		    && ( rq && (check_headers_match(obj, rq, &mod_flags) == MOD_CODE_OK) )
	         ) {

		    found=1;
		    if (  flags & AND_USE ) {
			if ( pthread_mutex_lock(&obj->lock) ) {
			    pthread_mutex_unlock(&hash_table[url_hash].lock);
			    pthread_mutex_unlock(&obj_chain);
			    return(NULL);
			}
			obj->refs++;
			pthread_mutex_unlock(&obj->lock);
		    }
		    obj->last_access = global_sec_timer;
		    obj->accessed += 1;
		    obj->rate = obj_rate(obj);
		    pthread_mutex_unlock(&hash_table[url_hash].lock);
		    pthread_mutex_unlock(&obj_chain);
		    return(obj);
		}
	    obj=obj->next;
	}
	if ( !found && ( flags & AND_PUT ) ) {
		/* need to insert */
		obj=xmalloc(sizeof(struct mem_obj), "locate_in_mem(): for object");
		if ( obj ) {
		    memset(obj, 0, sizeof(struct mem_obj));
		    obj->created = global_sec_timer;
		    obj->last_access = global_sec_timer;
		    obj->accessed = 1;
		    obj->rate = 0;
		    /* copy url */
		    obj->url.port = url->port;
		    obj->url.proto = xmalloc(strlen(url->proto)+1, "locate_in_mem(): for obj->url.proto");
		    if ( obj->url.proto ) {
			strcpy(obj->url.proto, url->proto);
		    } else {
			xfree(obj); obj = NULL;
			goto done;
		    }
		    obj->url.host = xmalloc(strlen(url->host)+1, "locate_in_mem(): for obj->url.host");
		    if ( obj->url.host ) {
			strcpy(obj->url.host, url->host);
		    } else {
			xfree(obj->url.proto);
			xfree(obj); obj = NULL;
			goto done;
		    }
		    obj->url.path = xmalloc(strlen(url->path)+1, "locate_in_mem(): for obj->url.path");
		    if ( obj->url.path ) {
			strcpy(obj->url.path, url->path);
		    } else {
			xfree(obj->url.proto);
			xfree(obj->url.host);
			xfree(obj); obj = NULL;
			goto done;
		    }
		    obj->url.httpv = xmalloc(strlen(url->httpv)+1, "locate_in_mem(): locate_in_mem4");
		    if ( obj->url.httpv ) {
			strcpy(obj->url.httpv, url->httpv);
		    } else {
			xfree(obj->url.proto);
			xfree(obj->url.host);
			xfree(obj->url.path);
			xfree(obj); obj = NULL;
			goto done;
		    }
		    found = 1;
		    pthread_mutex_init(&obj->lock, NULL);
		    pthread_mutex_init(&obj->state_lock, NULL);
		    pthread_cond_init(&obj->state_cond, NULL);
		    pthread_mutex_init(&obj->decision_lock, NULL);
		    pthread_cond_init(&obj->decision_cond, NULL);
		    if ( new_object ) *new_object = TRUE;
		    obj->next    = hash_table[url_hash].next;
		    obj->prev    = (struct mem_obj*)&hash_table[url_hash];
		    obj->flags  |= ANSW_NO_CACHE; /* we dont know yet if obj is cachable */
		    obj->decision_done = TRUE;
		    obj->writers = 1;
		    if (obj->next) obj->next->prev = obj;
		    hash_table[url_hash].next=obj;
		    obj->hash_back = &hash_table[url_hash];
		    if ( youngest_obj) {
			obj->older = youngest_obj;
			youngest_obj->younger = obj;
		    }
		    youngest_obj = obj;
		    if ( !oldest_obj ) {
		       oldest_obj = obj;
		    }
		    if ( found && ( flags & AND_USE ) ) {
			pthread_mutex_lock(&obj->lock);
			obj->refs++;
			pthread_mutex_unlock(&obj->lock);
		    }
		    ++total_objects;
		    pthread_mutex_unlock(&hash_table[url_hash].lock);
		    pthread_mutex_unlock(&obj_chain);
		    /* now try to load obj from disk */
		    if ( !(flags & NO_DISK_LOOKUP) ) {
			int			rc, resident_size;
			struct	disk_ref	*disk_ref;
			struct	storage_st	*storage;
			RDLOCK_CONFIG;
			RDLOCK_DB;
			rc = locate_url_on_disk(url, &disk_ref);
			if ( rc >= 0 && disk_ref ) {
			    /* it is on disk */
			    storage = locate_storage_by_id(disk_ref->id);
			    if ( storage && (storage->flags&ST_READY) ) {
				my_xlog(LOG_HTTP|LOG_FTP|LOG_STOR|LOG_DBG, "locate_in_mem(): Found on disk: %s\n", storage->path);
				/* order important. flags must be changed
				   when all done
				*/
				obj->disk_ref = disk_ref ;
				if ( new_object ) *new_object = FALSE;
				obj->writers = 0; /* like old object */
				if ( load_obj_from_disk(obj, disk_ref) ) {
				    obj->disk_ref = NULL ;
				    if ( new_object ) *new_object = TRUE ;
				    obj->writers = 1; /* like old object */
				    xfree(disk_ref);
				    goto nf;
				}
				/* ok, obj was loaded */
				resident_size = calculate_resident_size(obj);
        			obj->resident_size = resident_size;
                		increase_hash_size(obj->hash_back, obj->resident_size);
				if ( !strcasecmp(url->proto,"ftp") ) obj->doc_type = FTP_DOC;
				SET(obj->flags, FLAG_FROM_DISK);
				if ( rq && (check_headers_match(obj, rq, &mod_flags) != MOD_CODE_OK) ) {
				    /* obj don't match request	*/
				    struct	mem_obj	*n_obj;

				    if ( new_object ) *new_object = TRUE ;
				    SET(obj->flags, FLAG_DEAD);
				    UNLOCK_DB;
				    UNLOCK_CONFIG ;
				    leave_obj(obj);
				    n_obj = locate_in_mem(&rq->url,
					AND_PUT|AND_USE|PUT_NEW_ANYWAY|NO_DISK_LOOKUP, NULL, NULL);
				    /* old content will be dead */
				    return(n_obj);
				} else
				    CLR(obj->flags, ANSW_NO_CACHE);
				pthread_cond_broadcast(&obj->decision_cond);
			    }
			} else {
			    my_xlog(LOG_HTTP|LOG_FTP|LOG_DBG, "locate_in_mem(): Not found.\n");
			}
		nf:	UNLOCK_DB;
			UNLOCK_CONFIG;
		    }
		    return(obj);
		}
	}
done:
    pthread_mutex_unlock(&hash_table[url_hash].lock);
    pthread_mutex_unlock(&obj_chain);
    return(obj);
}


int
add_request_av(char* avtext, struct request *request)
{
struct	av	*new=NULL, *next;
char		*attr=avtext, *sp=avtext, *val,holder;
char		*new_attr=NULL, *new_val=NULL;

    while( *sp && !IS_SPACE(*sp) && (*sp != ':') ) sp++;
    if ( !*sp ) {
	my_xlog(LOG_SEVERE, "add_request_av(): Invalid request string: %s\n", avtext);
	return(-1);
    }
    if ( *sp ==':' ) sp++;
    holder = *sp;
    *sp = 0;
    new = xmalloc(sizeof(*new), "add_request_av(): for av pair");
    if ( !new ) goto failed;
    new_attr=xmalloc( strlen(attr)+1, "add_request_av(): for new_attr" );
    if ( !new_attr ) goto failed;
    strcpy(new_attr, attr);
    *sp = holder;
    val = sp; while( *val && IS_SPACE(*val) ) val++;
    if ( !*val ) goto failed;
    new_val = xmalloc( strlen(val) + 1, "add_request_av(): for val");
    if ( !new_val ) goto failed;
    strcpy(new_val, val);
    new->attr = new_attr;
    new->val  = new_val;
    new->next = NULL;
    if ( !request->av_pairs ) {
	request->av_pairs = new;
    } else {
	next = request->av_pairs;
	while (next->next) next=next->next;
	next->next=new;
    }
    return(0);
failed:
    *sp = holder;
    IF_FREE(new);
    IF_FREE(new_attr);
    IF_FREE(new_val);
    return(-1);
}

/* check any new headers we received and update struct request
   and checked accordingly.
   checked poins to the character next to the last recognized header
 */
int
check_headers(struct request *request, char *beg, char *end, int *checked, int so)
{
char	*start;
char	*p, saved;
int	r;

go:
    if ( request->state == REQUEST_READY ) return(0);
    start = beg + *checked;
    if ( !*checked ) {
	p = memchr(beg, '\r', end-beg);
	if ( !p ) {
	    if ( !(p = memchr(beg, '\n', end-beg)) )
		return(0);
	    saved = '\n';
	} else
	    saved = '\r';
	/* first line in request */
	*p = 0;
	r = parse_http_request(start, request, so);
	*checked = strlen(start);
	*p = saved;
	request->headers_off = p-beg+2;
	if ( r ) {
	    return(-1);
	}
	if ( !*checked ) return(-1);
	goto go;
    }
    /* checked points to last visited \r */
    if ( !request->data && (end - start >= 4) && !strncmp(start, "\r\n\r\n", 4) ) {
	if ( !request->content_length ) {
	    request->state = REQUEST_READY;
	    return(0);
	} else
	if ( request->content_length && !request->data ) {
	    request->leave_to_read = request->content_length;
	    if ( request->content_length <= 0 ) {
		request->state = REQUEST_READY;
		return(0);
	    }
	    request->data = alloc_buff(CHUNK_SIZE);
	    if ( !request->data ) {
		my_xlog(LOG_DBG|LOG_INFORM, "check_headers(): req_data.\n");
	    	return(-1);
	    }
	    start += 4;
	}
    } else
    if ( !request->data && (end - start >= 2) && !strncmp(start, "\n\n", 2) ) {
	if ( !request->content_length ) {
	    request->state = REQUEST_READY;
	    return(0);
	} else
	if ( request->content_length && !request->data ) {
	    request->leave_to_read = request->content_length;
	    request->data = alloc_buff(CHUNK_SIZE);
	    if ( !request->data ) return(-1);
	    start += 2;
	}
    }
    if ( request->content_length && request->leave_to_read ) {
	if ( request->data && (end-start > 0) ) {
	    if ( attach_data(start, end-start, request->data ) )
		return(-1);
	}
	request->leave_to_read -= end - start;
	/* we will read/send request body directly from/to client/server */
	request->state = REQUEST_READY;
	*checked = end-beg;
	return(0);
    }
    p = start;
    while( *p && ( *p == '\r' || *p == '\n' ) ) p++;
    if ( *p ) {
	char *t, saver = '\n';

	if ( !request->headers_off ) request->headers_off = p-beg;
	t = strchr(p, '\n');
	if ( !t ) {
	    t = strchr(p, '\r');
	    saver = '\r';
	}
	if ( !t ) return(0);
	if ( *t == '\n' && *(t-1) =='\r' ) {
	    t--;
	    saver = '\r';
	}
	*t = 0;
	/* check headers of my interest */
	my_xlog(LOG_HTTP|LOG_DBG, "check_headers(): ---> `%s'\n", p);
	if ( !request->data ) /* we don't parse POST data now */
		add_request_av(p, request);
	if ( !strncasecmp(p, "Content-length: ", 16) ) {
	    char	*x;
	    /* length */
	    x=p + 16; /* strlen("content-length: ") */
	    while( *x && IS_SPACE(*x) ) x++;
	    request->content_length = atoi(x);
	    request->flags |= RQ_HAS_CONTENT_LEN;
	}
	if ( !strncasecmp(p, "If-Modified-Since: ", 19) ) {
	    char	*x;
	    x=p + 19; /* strlen("content-length: ") */
	    while( *x && IS_SPACE(*x) ) x++;
	    bzero(&request->if_modified_since, sizeof(request->if_modified_since));
	    if (!http_date(x, &request->if_modified_since))
	    	request->flags |= RQ_HAS_IF_MOD_SINCE;
	}
	if ( !strncasecmp(p, "Pragma: ", 8) ) {
	    char	*x;
	    x=p + 8; /* strlen("pragma: ") */
	    while( *x && IS_SPACE(*x) ) x++;
	    if ( strstr(x, "no-cache") ) request->flags |= RQ_HAS_NO_CACHE;
	}
	if ( !strncasecmp(p, "Authorization: ", 15) ) {
	    request->flags |= RQ_HAS_AUTHORIZATION;
	}
	if ( !strncasecmp(p, "Host: ", 6) ) {
	    request->flags |= RQ_HAS_HOST;
	}
	if ( !strncasecmp(p, "Connection: ", 12) ) {
	    char *x = p+12;

	    while( *x && IS_SPACE(*x) ) x++;
	    if ( !strncasecmp(x, "close", 5) )
		request->flags |= RQ_HAS_CLOSE_CONNECTION;
	}
	if ( !strncasecmp(p, "Cache-Control: ", 15) ) {
	    char	*x;

	    x=p + 15; /* strlen("Cache-Control: ") */
	    while( *x && IS_SPACE(*x) ) x++;
	    if      ( !strncasecmp(x, "no-store", 8) )
			request->flags |= RQ_HAS_NO_STORE;
	    else if ( !strncasecmp(x, "no-cache", 8) )
			request->flags |= RQ_HAS_NO_CACHE;
	    else if ( !strncasecmp(x, "no-transform", 12) )
			request->flags |= RQ_HAS_NO_TRANSFORM;
	    else if ( !strncasecmp(x, "only-if-cached", 14) )
			request->flags |= RQ_HAS_ONLY_IF_CACHED;
	    else if ( sscanf(x, "max-age = %d", &request->max_age) == 1 )
			request->flags |= RQ_HAS_MAX_AGE;
	    else if ( sscanf(x, "min-fresh = %d", &request->min_fresh) == 1 )
			request->flags |= RQ_HAS_MIN_FRESH;
	    else if ( !strncasecmp(x, "max-stale", 9) ) {
		request->flags |= RQ_HAS_MAX_STALE;
		request->max_stale = 0;
		sscanf(x, "max-stale = %d", &request->max_stale);
	    }
	} else
	if ( !strncasecmp(p, "Range: ", 7) ) {
	    char *x;
	    /* we recognize "Range: bytes=xxx-" */
	    x = p + 7;
	    while( *x && IS_SPACE(*x) ) x++;
	    if ( !strncasecmp(x, "bytes=", 6) ) {
		int	from=-1,to=-1;
		/* x+6 must be 'xxx-' */
		sscanf(x+6,"%d-%d", &from, &to);
		if ( (from >= 0 ) && (to == -1 ) ) {
		    request->range_from = from;
		    request->range_to = to;
		}
	    }
	    request->flags |= RQ_HAVE_RANGE;
	}
	*t = saver;
	*checked = t - beg;
	goto go;
    }
    return(0);
}

int
parse_http_request(char* src, struct request *rq, int so)
{
char	*p, *httpv;
int	http_major, http_minor;

    p = strchr(src, ' ');
    if ( !p )
	return(-1);
    *p=0;
         if ( !strcasecmp(src, "get") )  rq->meth = METH_GET;
    else if ( !strcasecmp(src, "head") ) rq->meth = METH_HEAD;
    else if ( !strcasecmp(src, "put") )  rq->meth = METH_PUT;
    else if ( !strcasecmp(src, "post") ) rq->meth = METH_POST;
    else if ( !strcasecmp(src, "trace") ) rq->meth = METH_TRACE;
    else if ( !strcasecmp(src, "connect") ) rq->meth = METH_CONNECT;
    else if ( !strcasecmp(src, "PROPFIND") ) rq->meth = METH_PROPFIND;
    else if ( !strcasecmp(src, "PROPPATCH") ) rq->meth = METH_PROPPATCH;
    else if ( !strcasecmp(src, "MKCOL") ) rq->meth = METH_MKCOL;
    else if ( !strcasecmp(src, "DELETE") ) rq->meth = METH_DELETE;
    else if ( !strcasecmp(src, "COPY") ) rq->meth = METH_COPY;
    else if ( !strcasecmp(src, "MOVE") ) rq->meth = METH_MOVE;
    else if ( !strcasecmp(src, "LOCK") ) rq->meth = METH_LOCK;
    else if ( !strcasecmp(src, "UNLOCK") ) rq->meth = METH_UNLOCK;
    else if ( !strcasecmp(src, "PURGE") ) rq->meth = METH_PURGE;
    else if ( !strcasecmp(src, "OPTIONS") ) rq->meth = METH_OPTIONS;
    else {
	my_xlog(LOG_SEVERE, "parse_http_request(): Unrecognized method `%s'.\n", src);
	*p = ' ';
	return(-1);
    }
    IF_FREE(rq->method); rq->method = strdup(src);
    *p = ' ';
    p++;
    /* next space must be before HTTP */
    httpv = strrchr(p, 'H');
    if ( !httpv )
	return(-1);
    if ( (httpv <= p) )
	return(-1);
    httpv--;
    *httpv = 0;
    if ( rq->meth == METH_CONNECT ) {
	if ( parse_connect_url(p, httpv+1, &rq->url, so) ) {
	    *httpv = ' ';
	    return(-1);
	}
    }
    else if ( parse_url(p, httpv+1, &rq->url, so) ) {
	*httpv = ' ';
	return(-1);
    }
    *httpv = ' ';
    if ( sscanf(httpv+1, "HTTP/%d.%d", &http_major, &http_minor) == 2 ) {
	rq->http_major = http_major;
	rq->http_minor = http_minor;
    } else
	return(-1);
    return(0);
}

int
parse_connect_url(char* src, char *httpv, struct url *url, int so)
{
char	*ss, *host=NULL;

    if ( !src ) return(-1);
    ss = strchr(src, ':');
    if ( !ss ) {
	say_bad_request(so, "Bad request, no proto:", src, ERR_BAD_URL, NULL);
	return(-1);
    }
    *ss = 0;
    host = xmalloc(strlen(src)+1, "parse_connect_url():");
    if (!host)
	goto err;
    memcpy_to_lower(host, src, strlen(src)+1);
    url->host = host;
    url->port = atoi(ss+1);
    goto done;
err:
    *ss = ':';
    if (host) xfree(host);
    return(-1);
done:
    *ss = ':';
    return(0);
}

int
parse_url(char *src, char *httpv, struct url *url, int so)
{
char	*proto=NULL, *host=NULL, *path=NULL, *httpver = NULL;
char	*ss, *se, *he, *sx, *sa, holder;
char	number[10];
char	*login = NULL, *password = NULL;
int	p_len, h_len, i;
u_short	pval;

    if ( !src )
	return(-1);
    if ( *src == '/' ) {/* this is 'GET /path HTTP/1.x' request */
	se = src;
	proto = strdup("http");
	goto only_path;
    }
    ss = strchr(src, ':');
    if ( !ss ) {
	say_bad_request(so, "Bad request, no proto:", src, ERR_BAD_URL, NULL);
	return(-1);
    }
    if ( memcmp(ss, "://", 3) ) {
	say_bad_request(so, "Bad request:", src, ERR_BAD_URL, NULL);
	return(-1);
    }
    p_len = ss - src;
    proto = xmalloc(p_len+1, "parse_url(): proto");
    if ( !proto )
	return(-1);
    memcpy(proto, src, p_len); proto[p_len] = 0;
    ss += 3; /* skip :// */
    sx = strchr(ss, '/');
    se = strchr(ss, ':');
    sa = strchr(ss, '@');
    /* if we have @ and (there is no '/' or @ stay before '/') */ 
    if ( sa && ( !sx || ( sa < sx )) ) {
	/* ss   points to login				*/
	/* se+1 points to password			*/
	/* sa+1 points to host...			*/
	/* ss	se	 sa				*/
	/* login:password@hhost:port/path		*/
	if ( se < sa ) {
	    if ( se ) {
		*se = 0;
		login = xmalloc(ROUND(strlen(ss)+1, CHUNK_SIZE), "parse_url(): login");
		strcpy(login, ss);
		*se = ':';
		holder = *(sa);
		*(sa) = 0;
		password = xmalloc(ROUND(strlen(se+1)+1, CHUNK_SIZE), "parse_url(): password");
		strcpy(password, se+1);
	    	*(sa) = holder;
	    } else {
		holder = *sa;
		*sa = 0;
		login = xmalloc(ROUND(strlen(ss)+1, CHUNK_SIZE), "parse_url(): login2");
		strcpy(login, ss);
	        password = NULL;
		*sa = holder;
	    }
	    ss = sa+1;
	    sx = strchr(ss, '/');
	    se = strchr(ss, ':');
	    goto normal;
	} else {
	    /* ss   sa	 se			*/
	    /* login@host:port/path		*/
	    holder = *sa;
	    *sa = 0;
	    login = xmalloc(ROUND(strlen(ss)+1, CHUNK_SIZE), "parse_url(): login3");
	    strcpy(login, ss);
	    password = NULL;
	    *sa = holder;
	    ss = sa+1;
	    sx = strchr(ss, '/');
	    goto normal;
	}
    }
normal:;
    if ( se && (!sx || (sx>se)) ) {
	/* port is here */
	he = se;
	h_len = se-ss;
	host = xmalloc(h_len+1, "parse_url(): host");
	if ( !host ) {
	    IF_FREE(login);
	    IF_FREE(password);
	    xfree(proto);
	    return(-1);
	}
	memcpy_to_lower(host, ss, h_len); host[h_len] = 0;
	se++;
	for(i=0; (i<10) && *se && IS_DIGIT(*se); i++,se++ ) {
	    number[i]=*se;
	}
	number[i] = 0;
	if ( (pval=atoi(number)) != 0 )
		url->port = pval;
	    else {
		if ( so > 0) {
		    /* so can be -1 if called from icp.c */
		    say_bad_request(so, "Bad port value:", number,
			ERR_BAD_PORT, NULL);
		}
		IF_FREE(login);
		IF_FREE(password);
		xfree(proto);
		xfree(host);
		return(-1);
	}
    } else { /* there was no port */
	
	se = strchr(ss, '/');
	if ( !se )
	    se = src+strlen(src);
	h_len = se-ss;
	host = xmalloc(h_len+1, "parse_url(): host2");
	if ( !host ) {
	    IF_FREE(login);
	    IF_FREE(password);
	    xfree(proto);
	    return(-1);
	}
	memcpy_to_lower(host, ss, h_len); host[h_len] = 0;
	if ( !strcasecmp(proto, "http") ) url->port=80;
	if ( !strcasecmp(proto, "ftp") )  url->port=21;
    }
only_path:
    if ( *se == '/' ) {
	ss = se;
	for(i=0;*se++;i++);
	if ( i ) {
	    path = xmalloc(i+1, "parse_url(): 4");
	    if ( !path ) {
		IF_FREE(login);
		IF_FREE(password);
		IF_FREE(host);
		IF_FREE(proto);
		return(-1);
	    }
	    memcpy(path, ss, i);
	    path[i] = 0;
	}
    } else {
	path=xmalloc(2, "parse_url(): 5");
	if ( !path ) {
	    IF_FREE(login);
	    IF_FREE(password);
	    IF_FREE(host);
	    IF_FREE(proto);
	    return(-1);
	}
	path[0] = '/'; path[1] = 0;
    }
    if ( httpv ) {
	httpver = xmalloc(strlen(httpv) + 1, "parse_url(): httpver");
	if ( !httpver ) {
	    IF_FREE(login);
	    IF_FREE(password);
	    IF_FREE(host);
	    IF_FREE(proto);
	    return(-1);
	}
	memcpy(httpver, httpv, strlen(httpv)+1);
    }
    url->host  = host;
    url->proto = proto;
    url->path  = path;
    url->httpv = httpver;
    url->login = login;
    url->password = password;
    return(0);
}

int
parse_raw_url(char *src, struct url *url)
{
char	*proto=NULL, *host=NULL, *path=NULL;
char	*ss, *se, *he, *sx, *sa, holder;
char	number[10];
char	*login = NULL, *password = NULL;
int	p_len, h_len, i;
u_short	pval;

    if ( !src )
	return(-1);
    if ( *src == '/' ) {/* this is 'GET /path HTTP/1.x' request */
	se = src;
	proto = strdup("http");
	goto only_path;
    }
    ss = strchr(src, ':');
    if ( !ss ) {
	proto = strdup("http");
	ss = src;
	goto only_host_here;
    }
    if ( memcmp(ss, "://", 3) ) {
	proto = strdup("http");
	ss = src;
	goto only_host_here;
    }
    p_len = ss - src;
    proto = xmalloc(p_len+1, "parse_raw_url(): proto");
    if ( !proto )
	return(-1);
    memcpy(proto, src, p_len); proto[p_len] = 0;
    ss += 3; /* skip :// */
only_host_here:
    sx = strchr(ss, '/');
    se = strchr(ss, ':');
    sa = strchr(ss, '@');
    /* if we have @ and (there is no '/' or @ stay before '/') */ 
    if ( sa && ( !sx || ( sa < sx )) ) {
	/* ss   points to login				*/
	/* se+1 points to password			*/
	/* sa+1 points to host...			*/
	/* ss	se	 sa				*/
	/* login:password@hhost:port/path		*/
	if ( se < sa ) {
	    if ( se ) {
		*se = 0;
		login = xmalloc(ROUND(strlen(ss)+1, CHUNK_SIZE), "parse_raw_url(): login");
		strcpy(login, ss);
		*se = ':';
		holder = *(sa);
		*(sa) = 0;
		password = xmalloc(ROUND(strlen(se+1)+1, CHUNK_SIZE), "parse_raw_url(): password");
		strcpy(password, se+1);
	    	*(sa) = holder;
	    } else {
		holder = *sa;
		*sa = 0;
		login = xmalloc(ROUND(strlen(ss)+1, CHUNK_SIZE), "parse_raw_url(): login2");
		strcpy(login, ss);
	        password = NULL;
		*sa = holder;
	    }
	    ss = sa+1;
	    sx = strchr(ss, '/');
	    se = strchr(ss, ':');
	    goto normal;
	} else {
	    /* ss   sa	 se			*/
	    /* login@host:port/path		*/
	    holder = *sa;
	    *sa = 0;
	    login = xmalloc(ROUND(strlen(ss)+1, CHUNK_SIZE), "parse_raw_url(): login3");
	    strcpy(login, ss);
	    password = NULL;
	    *sa = holder;
	    ss = sa+1;
	    sx = strchr(ss, '/');
	    goto normal;
	}
    }
normal:;
    if ( se && (!sx || (sx>se)) ) {
	/* port is here */
	he = se;
	h_len = se-ss;
	host = xmalloc(h_len+1, "parse_raw_url(): host");
	if ( !host ) {
	    IF_FREE(login);
	    IF_FREE(password);
	    xfree(proto);
	    return(-1);
	}
	memcpy_to_lower(host, ss, h_len); host[h_len] = 0;
	se++;
	for(i=0; (i<10) && *se && IS_DIGIT(*se); i++,se++ ) {
	    number[i]=*se;
	}
	number[i] = 0;
	if ( (pval=atoi(number)) != 0 )
		url->port = pval;
	    else {
		IF_FREE(login);
		IF_FREE(password);
		xfree(proto);
		xfree(host);
		return(-1);
	}
    } else { /* there was no port */
	
	se = strchr(ss, '/');
	if ( !se )
	    se = src+strlen(src);
	h_len = se-ss;
	host = xmalloc(h_len+1, "parse_raw_url(): host2");
	if ( !host ) {
	    IF_FREE(login);
	    IF_FREE(password);
	    xfree(proto);
	    return(-1);
	}
	memcpy_to_lower(host, ss, h_len); host[h_len] = 0;
	if ( !strcasecmp(proto, "http") ) url->port=0;
	if ( !strcasecmp(proto, "ftp") )  url->port=21;
    }
only_path:
    if ( *se == '/' ) {
	ss = se;
	for(i=0;*se++;i++);
	if ( i ) {
	    path = xmalloc(i+1, "parse_raw_url(): 4");
	    if ( !path ) {
		IF_FREE(login);
		IF_FREE(password);
		IF_FREE(host);
		IF_FREE(proto);
		return(-1);
	    }
	    memcpy(path, ss, i);
	    path[i] = 0;
	}
    } else {
	path = xmalloc(2, "parse_raw_url(): 5");
	if ( !path ){
	    IF_FREE(login);
	    IF_FREE(password);
	    IF_FREE(host);
	    IF_FREE(proto);
	    return(-1);
	}
	path[0] = '/'; path[1] = 0;
    }
    url->host  = host;
    url->proto = proto;
    url->path  = path;
    url->login = login;
    url->password = password;
    return(0);
}

u_short
hash(struct url *url)
{
u_short		res = 0;
int		i;
char		*p;

    p = url->host;
    if ( p && *p ) {
	p = p+strlen(p)-1;
	i = 35;
	while ( (p >= url->host) && i ) i--,res += *p**p--;
    }
    p = url->path;
    if ( p && *p ) {
	p = p+strlen(p)-1;
	i = 35;
	while ( (p >= url->path) && i ) i--,res += *p**p--;
    }
    return(res & HASH_MASK);
}

void
release_obj(struct mem_obj *obj)
{
/* just decrement refs */

    pthread_mutex_lock(&obj->lock);
	obj->refs--;
    pthread_mutex_unlock(&obj->lock);
    if ( obj->refs < 0 ) {
    	my_xlog(LOG_DBG|LOG_INFORM, "release_obj(): obj->refs < 0 = %d\n", obj->refs);
	exit(0);
    }
}

void
leave_obj(struct mem_obj *obj)
{
/* thread leave this object
	1) decrement ref counter.
	2) if obj marked DEAD or NO_CACHE and !refs free it
	3) if doc expired, then set DEAD
	4) if doc was from disk and it must be erased - do it.
*/
u_short 		url_hash = hash(&obj->url);
struct	mem_obj		*child = NULL;
int			must_be_erased = FALSE, urll;
struct	disk_ref	*disk_ref = NULL;
char			*url_str = NULL;
struct	url		*url;

    if ( pthread_mutex_lock(&obj_chain) ) {
	fprintf(stderr, "leave_obj(): Failed mutex lock in leave.\n");
 	return;
    }
    if ( pthread_mutex_lock(&hash_table[url_hash].lock) ) {
	fprintf(stderr, "leave_obj(): Failed mutex lock in leave.\n");
	pthread_mutex_unlock(&obj_chain);
	return;
    }
    release_obj(obj);
    if ( !obj->refs ) {
	/* it is possible that object expired, but not changed,
	   and long time stay in memory (e.g. accelerator). in 
	   this case we will repeatedly check document freshness on server,
	   wasting server resources. So I'll delete all expired docs from
	   memory and from disk.
	*/
	if ( TEST(obj->flags, ANSW_HAS_EXPIRES) 
	     && (obj->times.expires <= global_sec_timer) )
	     	SET(obj->flags, FLAG_DEAD);
	else
	if ( TEST(obj->flags, ANSW_HAS_MAX_AGE)
	     && (obj->times.max_age <= current_obj_age(obj)) )
	     	SET(obj->flags, FLAG_DEAD);
    }
    if ( (obj->flags & (FLAG_DEAD|ANSW_NO_CACHE)) && !obj->refs ) {
	child = obj->child_obj;
	if ( obj->flags & FLAG_FROM_DISK ) {
	    my_xlog(LOG_HTTP|LOG_FTP|LOG_STOR|LOG_DBG, "leave_obj(): Must be erased from storage.\n");
	    must_be_erased = TRUE;
	    url = &obj->url;
	    urll = strlen(url->proto)+strlen(url->host)+strlen(url->path)+10;
	    urll+= 3 + 1; /* :// + \0 */
	    url_str = xmalloc(urll, "leave_obj(): url_str");
	    if ( obj->doc_type == HTTP_DOC )
		sprintf(url_str,"%s%s:%d", url->host, url->path, url->port);
	      else
		sprintf(url_str,"%s://%s%s:%d", url->proto, url->host, url->path, url->port);
	    disk_ref = obj->disk_ref;
	    obj->disk_ref = NULL;
	}
	destroy_obj(obj);
    }
    pthread_mutex_unlock(&hash_table[url_hash].lock);
    pthread_mutex_unlock(&obj_chain);
    if ( child ) leave_obj(child);
    if ( must_be_erased && url_str && disk_ref) {
	eraser_data_t	*ed;

	ed = xmalloc(sizeof(*ed), "");
	if ( ed ) {
	    ed->url = url_str;
	    ed->disk_ref = disk_ref;
	    dataq_enqueue(&eraser_queue, ed);
	} else {
	    xfree(url_str);
	    xfree(disk_ref);
	}
    }
}

void
free_request( struct request *rq)
{
struct	av	*av, *next;

    free_url(&rq->url);
    av = rq->av_pairs;
    while(av) {
	xfree(av->attr);
	xfree(av->val);
	next = av->next;
	xfree(av);
	av = next;
    }
    IF_FREE( rq->method );
    IF_FREE(rq->original_host);
    if ( rq->data ) free_container(rq->data);
    if ( rq->redir_mods ) leave_l_string_list(rq->redir_mods);
    if ( rq->cs_to_server_table ) leave_l_string_list(rq->cs_to_server_table);
    if ( rq->cs_to_client_table ) leave_l_string_list(rq->cs_to_client_table);
    IF_FREE(rq->matched_acl);
    IF_FREE(rq->source);
    IF_FREE(rq->tag);
    IF_FREE(rq->c_type);
    IF_FREE(rq->hierarchy);
    IF_FREE(rq->proxy_user);
    IF_FREE(rq->original_path);
    IF_FREE(rq->peer_auth);
    IF_FREE(rq->decoding_buff);
    remove_request_from_ip_hash(rq);
}

void
free_url(struct url *url)
{
    IF_FREE(url->host);
    IF_FREE(url->proto);
    IF_FREE(url->path);
    IF_FREE(url->httpv);
    IF_FREE(url->login);
    IF_FREE(url->password);
}

/*
 * %M - message
 * %R - reason (strerror, or free text)
 * %U - URL
 */
void
say_bad_request(int so, char* reason, char *r, int code, struct request *rq)
{
char	*hdr = "HTTP/1.0 400 Bad Request\nConent-Type: text/html\n\n<html>\
		<body>\
		<i><h2>Invalid request:</h2></i><p><pre>";
char	*rf= "</pre><b>";
char	*trailer="\
		</b><p>Please, check URL.<p>\
		<hr>\
		Generated by Oops.\
		</body>\
		</html>";
struct	err_module	*mod = err_first;
int			modflags = 0;

    while ( mod ) {
	mod->err(so, reason, r, code, rq, &modflags);
	mod = (struct err_module*)MOD_NEXT(mod);
	if ( TEST(modflags, MOD_AFLAG_BRK|MOD_AFLAG_OUT) )
	    break;
    }
    if ( !TEST(modflags, MOD_AFLAG_OUT) )
    {
	if (hdr ) writet(so, hdr, strlen(hdr), READ_ANSW_TIMEOUT);
	if ( r  ) writet(so, r, strlen(r), READ_ANSW_TIMEOUT);
	if ( rf ) writet(so, rf, strlen(rf), READ_ANSW_TIMEOUT);
	if ( reason ) writet(so, reason, strlen(reason), READ_ANSW_TIMEOUT);
	if ( trailer) writet(so, trailer, strlen(trailer), READ_ANSW_TIMEOUT);
    }
}

int
in_stop_cache(struct request *rq)
{
struct	string_list	*l = stop_cache;

    while(l) {
	if ( strstr((*rq).url.path, l->string) )
	    return(1);
	l = l->next;
    }

    if ( stop_cache_acl )
	return(check_acl_access(stop_cache_acl, rq));

    return(0);
}

void
increment_clients(void)
{
    if ( !pthread_mutex_lock(&clients_lock) ) {
	clients_number++;
	pthread_mutex_unlock(&clients_lock);
    } else {
	my_xlog(LOG_SEVERE, "increment_clients(): Can't lock clients_lock in increment.\n");
    }
    LOCK_STATISTICS(oops_stat);
	oops_stat.clients++;
    UNLOCK_STATISTICS(oops_stat);
}

void
decrement_clients(void)
{
    if ( !pthread_mutex_lock(&clients_lock) ) {
	clients_number--;
	pthread_mutex_unlock(&clients_lock);
    } else {
	my_xlog(LOG_SEVERE, "decrement_clients(): Can't lock clients_lock in decrement.\n");
    }
    LOCK_STATISTICS(oops_stat);
	oops_stat.clients--;
    UNLOCK_STATISTICS(oops_stat);
}

int
set_socket_options(int so)
{
#if	!defined(FREEBSD)
int	on = -1;
#if	defined(TCP_NODELAY)
     setsockopt(so, IPPROTO_TCP, TCP_NODELAY, (char*)&on, sizeof(on));
#endif
#endif /* !FREEBSD */
    return(0);
}

void
make_purge(int so, struct request *rq)
{
struct	mem_obj		*obj;
struct	output_object	*output;
char			*res, *result="<body>Unknown status</body>";
char			*succ = "200 Purged Successfully";
char			*fail = "404 Not Found";
int			newobj;

    if ( !rq->url.path ||
	 !rq->url.host ) return;
    obj = locate_in_mem(&rq->url, AND_USE|AND_PUT, &newobj, rq);
    if ( obj ) {
	if ( !newobj ) {
	    my_xlog(LOG_HTTP|LOG_DBG, "make_purge(): Document destroyed.\n");
	    res = succ;
	    result = "<body>Successfully removed</body>\n";
	    IF_STRDUP(rq->tag, "TCP_HIT");
	} else {
	    my_xlog(LOG_HTTP|LOG_DBG, "make_purge(): Document not found.\n");
	    res = fail;
	    result = "<body>Document not found\n</body>";
	    IF_STRDUP(rq->tag, "TCP_MISS");
	}
	SET(obj->flags, FLAG_DEAD);
	leave_obj(obj);
    } else {
	/* not found */
	res = fail;
	my_xlog(LOG_HTTP|LOG_DBG, "make_purge(): Document not found.\n");
	IF_STRDUP(rq->tag, "TCP_MISS");
    }
    output = malloc(sizeof(*output));
    if ( output ) {
	bzero(output, sizeof(*output));
	output->body = alloc_buff(128);
	put_av_pair(&output->headers,"HTTP/1.0", res);
	put_av_pair(&output->headers,"Expires:", "Thu, 01 Jan 1970 00:00:01 GMT");
	put_av_pair(&output->headers,"Content-Type:", "text/html");

	if ( output->body ) {
	    attach_data(result, strlen(result), output->body);
	}

	process_output_object(so, output, rq);
	free_output_obj(output);
    }
    log_access(0, rq, NULL);
}

int
obj_rate(struct mem_obj *obj)
{
    return(0);
}

void
insert_request_in_hash(struct request *rq)
{
int	index;
    if ( !rq ) return;
    index = rq->so % RQ_HASH_MASK;
    pthread_mutex_lock(&(rq_hash[index].lock));
    rq->next = rq_hash[index].link;
    if ( rq->next ) rq->next->prev = rq;
    rq->prev = NULL;
    rq_hash[index].link = rq;
    pthread_mutex_unlock(&(rq_hash[index].lock));
}

void
remove_request_from_hash(struct request *rq)
{
int	index;
    if ( !rq ) return;
    index = rq->so % RQ_HASH_MASK;
    pthread_mutex_lock(&(rq_hash[index].lock));
    if ( rq->next ) rq->next->prev = rq->prev;
    if ( rq->prev )
	rq->prev->next = rq->next;
      else
	rq_hash[index].link = rq->next;
    pthread_mutex_unlock(&(rq_hash[index].lock));
}

void
insert_request_in_ip_hash(struct request *rq)
{
int		index;
ip_hash_entry_t	*he = NULL;

    if ( !rq ) return;
    /* if it is already there */
    index = ((rq->client_sa.sin_addr.s_addr >> 16) ^ 
    	    (rq->client_sa.sin_addr.s_addr) ) % IP_HASH_MASK;
    pthread_mutex_lock(&ip_hash[index].lock);
    he = ip_hash[index].link;
    while ( he ) {
	if ( he->addr.s_addr == rq->client_sa.sin_addr.s_addr ) /* it is */
	    break;
	he = he->next;
    }
    if ( he ) {
	pthread_mutex_lock(&he->lock);
	he->refcount++;
	he->access = global_sec_timer;
	rq->ip_hash_ptr = he;
	pthread_mutex_unlock(&he->lock);
    } else {
	he = calloc(sizeof(*he),1);
	if ( he ) {
	    pthread_mutex_init(&he->lock, NULL);
	    he->addr = rq->client_sa.sin_addr;
	    he->refcount = 1;
	    he->access = global_sec_timer;
	    he->prev = NULL;
	    he->next = ip_hash[index].link;
	    if ( he->next ) he->next->prev = he;
	    ip_hash[index].link = he;
	    rq->ip_hash_ptr = he;
	}
    }
    pthread_mutex_unlock(&ip_hash[index].lock);
}

void
remove_request_from_ip_hash(struct request *rq)
{
int		index;
ip_hash_entry_t	*he;

    if ( !rq ) return;
    /* if it is already there */
    index = ((rq->client_sa.sin_addr.s_addr >> 16) ^ 
    	    (rq->client_sa.sin_addr.s_addr) ) % IP_HASH_MASK;
    pthread_mutex_lock(&ip_hash[index].lock);
    he = rq->ip_hash_ptr;
    if ( he ) {
	/* leave this entry */
	pthread_mutex_lock(&he->lock);
	if ( he->refcount > 0 ) he->refcount--;
	pthread_mutex_unlock(&he->lock);
    }
    pthread_mutex_unlock(&ip_hash[index].lock);
}
