#include        <stdio.h>
#include        <stdlib.h>
#include        <fcntl.h>
#include        <errno.h>
#include        <stdarg.h>
#include        <netdb.h>
#include        <unistd.h>
#include        <ctype.h>
#include        <signal.h>
#include	<string.h>
#include	<strings.h>
#include	<time.h>

#include        <sys/param.h>
#include        <sys/socket.h>
#include        <sys/types.h>
#include        <sys/stat.h>
#include        <sys/file.h>
#include	<sys/time.h>

#if	defined(SOLARIS) || defined(LINUX)
#include	<netinet/tcp.h>
#endif

#include        <netinet/in.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"
#ifdef		MODULES
#include	"modules.h"
extern struct	err_module	*err_first;
#endif
#define		READ_REQ_TIMEOUT	(10*60)		/* 10 minutes */

#define		REQUEST_EMPTY	0
#define		REQUEST_READY	1

/*extern	struct	hash_entry	hash_table[HASH_SIZE];*/

void		free_url(struct url *url);
void		free_request(struct request *rq);
void		leave_obj(struct mem_obj *);
u_short		hash(struct url *url);
void		send_not_cached(int so, struct request *rq, char *hdrs);
int		parse_http_request(char *start, struct request *rq, int so);
int		check_headers(struct request *rq, char *beg, char *end, int *checked, int so);
int		parse_url(char*, char*, struct url *, int);
void		release_obj(struct mem_obj*);
void		fill_mem_obj(int, struct request *, char* , struct mem_obj*);
void		send_from_mem(int, struct request *, char* , struct mem_obj*, int);
void		increment_clients();
void		decrement_clients();
int		parse_connect_url(char* src, char *httpv, struct url *url, int so);

#if	defined(DEMO)
static	int	served = 0;
#endif

void*
run_client(void *arg)
{
u_char			*buf=NULL;
int			got, rc;
u_char			*cp,*ip;
char			*headers;
struct	request		request;
time_t			started;
struct	mem_obj		*stored_url;
size_t			current_size;
int			status, checked_len=0, mod_flags;
int			mem_send_flags = 0, clsalen = sizeof(request.client_sa);
int			mysalen = sizeof(request.my_sa);
struct	group		*group;
int			miss_denied = TRUE;
int			so, new_object;

   so = (int)arg;
   fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK);

   increment_clients();
   set_socket_options(so);

re: /* here we go if client want persistent connection */
   bzero(&request, sizeof(request));
   getpeername(so, (struct sockaddr*)&request.client_sa, &clsalen);
   getsockname(so, (struct sockaddr*)&request.my_sa, &mysalen);
   request.request_time = started = time(NULL);
   RDLOCK_CONFIG ;
   group = inet_to_group(&request.client_sa.sin_addr);

   if ( group ) {
	pthread_mutex_lock(&group->group_mutex);
	group->cs0.requests++;
	pthread_mutex_unlock(&group->group_mutex);

	miss_denied = group->miss_deny;
   }
   if ( group && group->bandwidth )
	request.flags |= RQ_HAS_BANDWIDTH;
   UNLOCK_CONFIG;

   buf = xmalloc(CHUNK_SIZE, "run_client: for client request");
   if ( !buf ) {
	my_log("No mem for header!\n");
	goto done;
   }
   current_size = CHUNK_SIZE;
   cp = buf; ip = buf;
#if	defined(DEMO)
   if ( served > 5112 ) {
	decrement_clients();
	xfree(buf);
	close(so);
	return;
   } else {
	served++;
   }
#endif

   while(1) {
	got = readt(so, (char*)cp, current_size-(cp-ip), 100);
	if ( got == 0 ) {
	    my_xlog(LOG_FTP|LOG_HTTP, "Client closed connection\n");
	    goto done;
	}
	if ( got == -2 ) {
	    my_xlog(LOG_HTTP|LOG_FTP, "Read client input timeout\n");
	    if ( time(NULL) - started > READ_REQ_TIMEOUT ) {
		my_xlog(LOG_HTTP|LOG_FTP, "Client send too slow\n");
		goto done;
	    }
	    continue;
	}
	if ( got <  0 ) {
	    my_xlog(LOG_HTTP|LOG_FTP, "Failed to read from client\n");
	    goto done;
	}
	cp+=got;
	if ( cp - ip >= current_size ) {
	    char *nb = xmalloc(current_size+CHUNK_SIZE, "run_client: new block");
	    /* resize buf */
	    if ( !nb ) {
		my_log("No mem to read request\n");
		goto done;
	    }	    
	    memcpy(nb, buf, current_size);
	    free(buf);
	    buf=ip=(u_char*)nb;
	    cp=ip+current_size;
	    *cp=0;
	    current_size=current_size+CHUNK_SIZE;
	} else
	    *cp=0;
	status = check_headers(&request, (char*)ip, (char*)cp, &checked_len, so);
	if ( status ) {
	    my_xlog(LOG_HTTP|LOG_FTP, "Failed to check headers\n");
	    goto done;
	}
	if ( request.state == REQUEST_READY )
	    break;
    }
    if ( request.headers_off <= 0 ) {
	my_log("Something wrong with headers_off: %d\n", request.headers_off);
	goto done;
    }
    headers = (char*)buf + request.headers_off;
    RDLOCK_CONFIG ;
    if ((rc = deny_http_access(so, &request)) ) {
	my_xlog(LOG_HTTP|LOG_FTP, "Access banned\n");
	switch ( rc ) {
	case ACCESS_PORT:
		say_bad_request(so, "<font color=red>Access denied for requestsd port.\n</font>", "",
			ERR_BAD_PORT, &request);
		break;
	case ACCESS_DOMAIN:
		say_bad_request(so, "<font color=red>Access denied for requested domain.\n</font>", "",
			ERR_ACC_DOMAIN, &request);
		break;
	default:
		say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
			ERR_ACC_DENIED, &request);
		break;
	}
	UNLOCK_CONFIG ;
	goto done;
    }
    group = inet_to_group(&request.client_sa.sin_addr);
    if ( group->denytimes && (rc = denytime_check(group->denytimes)) ) {
	say_bad_request(so, "<font color=red>Your access to proxy service denied at this time.\n</font>", "",
		ERR_ACC_DENIED, &request);
	UNLOCK_CONFIG ;
	goto done;
    }
#ifdef	MODULES
    /* check for redirects */
    if ( check_redirect(so, &request, group, &mod_flags) ) {
	UNLOCK_CONFIG;
	goto done;
    }
    /* time to visit auth modules */
    mod_flags = 0;
    if ( check_auth(so, &request, group, &mod_flags) == MOD_CODE_ERR) {
	if ( !TEST(mod_flags, MOD_AFLAG_OUT) ) {
	    /* there was no output */
	    say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
			ERR_ACC_DENIED, &request);
	}
	UNLOCK_CONFIG;
	goto done;
    }
#endif
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

    if ( !request.url.host[0] ) {
	    say_bad_request(so, "No host part in URL\n", NULL,
		    ERR_BAD_URL, &request);
	    goto done;
    }
    if ( strcasecmp(request.url.proto, "ftp")   && /* ftp processed below */
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
	close(so); so = -1;
	goto done;
    }
    if ( in_stop_cache(&request) ) {
	if ( miss_denied ) {
	    say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
		ERR_ACC_DENIED, &request);
	    goto done;
	}
	send_not_cached(so, &request, headers);
	close(so); so = -1;
	goto done;
    }
    if ( request.flags & RQ_HAS_ONLY_IF_CACHED ) {
	stored_url = locate_in_mem(&request.url, AND_USE, &new_object);
	if ( !stored_url ) {
	    send_error(so, 504, "Gateway Timeout. Or not in cache");
	    goto done;
	}
	send_from_mem(so, &request, headers, stored_url, mem_send_flags);
	close(so); so = -1;
	leave_obj(stored_url);
	goto done;
    }

    if ( request.flags & RQ_HAS_NO_CACHE )
	mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;

    if ( request.flags &
	(RQ_HAS_MAX_AGE|RQ_HAS_MAX_STALE|RQ_HAS_MIN_FRESH) ) {
	stored_url = locate_in_mem(&request.url, AND_USE|AND_PUT, &new_object);
	if ( !stored_url ) {
	    my_log("Can't create or find memory object\n");
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
		my_log("Must revalidate: freshness_lifetime=%d, request.max_stale: %d\n",
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
	send_from_mem(so, &request, headers, stored_url, mem_send_flags);
	close(so); so = -1;
	leave_obj(stored_url);
	goto done;
    }
    stored_url = locate_in_mem(&request.url, AND_PUT|AND_USE, &new_object);
    if ( !stored_url ) {
	my_log("Can't create or find memory object\n");
	say_bad_request(so, "Can't create memory object.\n", "No memory?",
		ERR_INTERNAL, &request);
	goto done;
    }

    if ( new_object ) {
read_net:
	my_xlog(LOG_HTTP|LOG_FTP, "read <%s><%s><%d><%s> from Net\n", request.url.proto,
					     request.url.host,
					     request.url.port,
					     request.url.path);
	if ( miss_denied ) {
	    say_bad_request(so, "Please contact cachemaster\n", "Proxy access denied.\n",
		ERR_ACC_DENIED, &request);
	    stored_url->flags |= FLAG_DEAD;
	} else {
	    if ( !strcasecmp(request.url.proto, "ftp") )
		ftp_fill_mem_obj(so, &request, headers, stored_url);
	    else if ( !strcasecmp(request.url.proto, "http") )
		fill_mem_obj(so, &request, headers, stored_url);
	    else {
		say_bad_request(so, "Unsupported protocol\n", request.url.proto,
		    ERR_BAD_URL, &request);
		stored_url->flags |= FLAG_DEAD;
	    }
	}
	close(so); so = -1;
	leave_obj(stored_url);
    } else {
	if ( stored_url->flags & ANSW_HAS_MAX_AGE ) {
	    time_t age = current_obj_age(stored_url);
	    if ( stored_url->times.max_age &&
	         (age > stored_url->times.max_age) ) {
		mem_send_flags |= MEM_OBJ_MUST_REVALIDATE;
	    }
	}
	my_xlog(LOG_HTTP|LOG_FTP, "read <%s:%s:%s> from mem\n", request.url.proto,
					     request.url.host,
					     request.url.path);
	send_from_mem(so, &request, headers, stored_url, mem_send_flags);
	close(so); so = -1;
        leave_obj(stored_url);
    }
persistent:

done:
    if (buf)  free(buf);
    free_request(&request);
    if ( so != -1 ) close(so);
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

    obj = xmalloc(sizeof(*obj), "create_obj");
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
    free(obj);
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
    if ( obj->disk_ref ) xfree(obj->disk_ref);
    pthread_mutex_destroy(&obj->lock);
    pthread_mutex_destroy(&obj->state_lock);
    pthread_cond_destroy(&obj->state_cond);
    pthread_mutex_destroy(&obj->decision_lock);
    pthread_cond_destroy(&obj->decision_cond);
    decrease_hash_size(obj->hash_back, obj->resident_size);
    --total_objects;
    free(obj);
}

struct mem_obj*
locate_in_mem(struct url *url, int flags, int *new_object)
{
struct	mem_obj	*obj=NULL;
u_short 	url_hash = hash(url);
int		found=0;

    if ( new_object ) *new_object = FALSE;
    if ( pthread_mutex_lock(&obj_chain) ) {
	fprintf(stderr, "Failed mutex lock\n");
	return(NULL);
    }
    /* lock hash entry */
    if ( pthread_mutex_lock(&hash_table[url_hash].lock) ) {
	fprintf(stderr, "Failed mutex lock\n");
	pthread_mutex_unlock(&obj_chain);
	return(NULL);
    }
	obj=hash_table[url_hash].next;
	if ( !(flags & PUT_NEW_ANYWAY) ) while(obj) {
	    if ( (url->port==obj->url.port) &&
	         !strcmp(url->path, obj->url.path) &&
	         !strcasecmp(url->host, obj->url.host) &&
	         !strcasecmp(url->proto, obj->url.proto) &&
	         !(obj->flags & (FLAG_DEAD|ANSW_NO_CACHE)) ) {
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
		    pthread_mutex_unlock(&hash_table[url_hash].lock);
		    pthread_mutex_unlock(&obj_chain);
		    return(obj);
		}
	    obj=obj->next;
	}
	if ( !found && ( flags & AND_PUT ) ) {
		/* need to insert */
		obj=xmalloc(sizeof(struct mem_obj), "for object");
		if ( obj ) {
		    memset(obj, 0, sizeof(struct mem_obj));
		    /* copy url */
		    obj->url.port = url->port;
		    obj->url.proto = xmalloc(strlen(url->proto)+1, "for obj->url.proto");
		    if ( obj->url.proto ) {
			strcpy(obj->url.proto, url->proto);
		    } else {
			free(obj); obj = NULL;
			goto done;
		    }
		    obj->url.host = xmalloc(strlen(url->host)+1, "for obj->url.host");
		    if ( obj->url.host ) {
			strcpy(obj->url.host, url->host);
		    } else {
			free(obj->url.proto);
			free(obj); obj = NULL;
			goto done;
		    }
		    obj->url.path = xmalloc(strlen(url->path)+1, "for obj->url.path");
		    if ( obj->url.path ) {
			strcpy(obj->url.path, url->path);
		    } else {
			free(obj->url.proto);
			free(obj->url.host);
			free(obj); obj = NULL;
			goto done;
		    }
		    obj->url.httpv = xmalloc(strlen(url->httpv)+1, "locate_in_mem4");
		    if ( obj->url.httpv ) {
			strcpy(obj->url.httpv, url->httpv);
		    } else {
			free(obj->url.proto);
			free(obj->url.host);
			free(obj->url.path);
			free(obj); obj = NULL;
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
				my_xlog(LOG_HTTP|LOG_FTP|LOG_STOR, "Found on disk: %s\n", storage->path);
				/* order important. flags must be changed
				   when all done
				*/
				obj->disk_ref = disk_ref ;
				if ( new_object ) *new_object = FALSE;
				obj->writers = 0; /* like old object */
				if ( load_obj_from_disk(obj, disk_ref) ) {
				    obj->disk_ref = NULL ;
				    if ( new_object ) *new_object = TRUE;
				    obj->writers = 1; /* like old object */
				    xfree(disk_ref);
				    goto nf;
				}
				resident_size = calculate_resident_size(obj);
        			obj->resident_size = resident_size;
                		increase_hash_size(obj->hash_back, obj->resident_size);
				if ( !strcasecmp(url->proto,"ftp") ) obj->doc_type = FTP_DOC;
				SET(obj->flags, FLAG_FROM_DISK);
				CLR(obj->flags, ANSW_NO_CACHE);
				pthread_cond_broadcast(&obj->decision_cond);
			    }
			} else {
			    my_xlog(LOG_HTTP|LOG_FTP, "Not found\n");
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

    while( *sp && !isspace(*sp) && (*sp != ':') ) sp++;
    if ( !*sp ) {
	my_log("Invalid request string: %s\n", avtext);
	return(-1);
    }
    if ( *sp ==':' ) sp++;
    holder = *sp;
    *sp = 0;
    new = xmalloc(sizeof(*new), "for av pair");
    if ( !new ) goto failed;
    new_attr=xmalloc( strlen(attr)+1, "for new_attr" );
    if ( !new_attr ) goto failed;
    strcpy(new_attr, attr);
    *sp = holder;
    val = sp; while( *val && isspace(*val) ) val++;
    if ( !*val ) goto failed;
    new_val = xmalloc( strlen(val) + 1, "for val");
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
    if ( new ) free(new);
    if ( new_attr ) free(new_attr);
    if ( new_val ) free(new_val);
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
char	*p;
int	r;

go:
    if ( request->state == REQUEST_READY ) return(0);
    start = beg + *checked;
    if ( !*checked ) {
	p = memchr(beg, '\r', end-beg);
	if ( !p )
	    return(0);
	/* first line in request */
	*p = 0;
	r = parse_http_request(start, request, so);
	*checked = strlen(start);
	*p = '\r';
	request->headers_off = p-beg+2;
	if ( r ) {
	    return(-1);
	}
	if ( !*checked ) return(-1);
	goto go;
    }
    /* checked points to last visited \r */
    if ( !request->data && (end - start >= 4) && !strncmp(start, "\r\n\r\n", 4) ) {
	if ( request->meth != METH_POST ) {
	    request->state = REQUEST_READY;
	    return(0);
	} else
	if ( (request->meth == METH_POST) && !request->data ) {
	    request->leave_to_read = request->content_length;
	    if ( request->content_length <= 0 ) {
		request->state = REQUEST_READY;
		return(0);
	    }
	    request->data = alloc_buff(CHUNK_SIZE);
	    if ( !request->data ) {
		my_log("req_data\n");
	    	return(-1);
	    }
	    start += 4;
	}
    } else
    if ( !request->data && (end - start >= 2) && !strncmp(start, "\n\n", 2) ) {
	if ( request->meth != METH_POST ) {
	    request->state = REQUEST_READY;
	    return(0);
	} else
	if ( (request->meth == METH_POST) && !request->data ) {
	    request->leave_to_read = request->content_length;
	    request->data = alloc_buff(CHUNK_SIZE);
	    if ( !request->data ) return(-1);
	    start += 2;
	}
    }
    if ( (request->meth == METH_POST) && request->leave_to_read ) {
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
	/*my_log("--->'%s'\n", p);*/
	if ( !request->data ) /* we don't parse POST data now */
		add_request_av(p, request);
	if ( !strncasecmp(p, "Content-length: ", 16) ) {
	    char	*x;
	    /* length */
	    x=p + 16; /* strlen("content-length: ") */
	    while( *x && isspace(*x) ) x++;
	    request->content_length = atoi(x);
	    request->flags |= RQ_HAS_CONTENT_LEN;
	}
	if ( !strncasecmp(p, "If-Modified-Since: ", 19) ) {
	    char	*x;
	    x=p + 19; /* strlen("content-length: ") */
	    while( *x && isspace(*x) ) x++;
	    bzero(&request->if_modified_since, sizeof(request->if_modified_since));
	    if (!http_date(x, &request->if_modified_since))
	    	request->flags |= RQ_HAS_IF_MOD_SINCE;
	}
	if ( !strncasecmp(p, "Pragma: ", 8) ) {
	    char	*x;
	    x=p + 8; /* strlen("pragma: ") */
	    while( *x && isspace(*x) ) x++;
	    if ( strstr(x, "no-cache") ) request->flags |= RQ_HAS_NO_CACHE;
	}
	if ( !strncasecmp(p, "Authorization: ", 15) ) {
	    request->flags |= RQ_HAS_AUTHORIZATION;
	}
	if ( !strncasecmp(p, "Connection: ", 12) ) {
	    char *x = p+12;

	    while( *x && isspace(*x) ) x++;
	    if ( !strncasecmp(x, "close", 5) )
		request->flags |= RQ_HAS_CLOSE_CONNECTION;
	}
	if ( !strncasecmp(p, "Cache-Control: ", 15) ) {
	    char	*x;

	    x=p + 15; /* strlen("Cache-Control: ") */
	    while( *x && isspace(*x) ) x++;
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
    else {
	my_log("unrecognized method '%s'\n", src);
	*p = ' ';
	return(-1);
    }
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
    host = xmalloc(strlen(src)+1, "for parse_connect_url");
    if (!host)
	goto err;
    memcpy(host, src, strlen(src)+1);
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
    proto = xmalloc(p_len+1, "parse_url, proto");
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
		login = xmalloc(ROUND(strlen(ss)+1, CHUNK_SIZE), "login");
		strcpy(login, ss);
		*se = ':';
		holder = *(sa);
		*(sa) = 0;
		password = xmalloc(ROUND(strlen(se+1)+1, CHUNK_SIZE), "password");
		strcpy(password, se+1);
	    	*(sa) = holder;
	    } else {
		holder = *sa;
		*sa = 0;
		login = xmalloc(ROUND(strlen(ss)+1, CHUNK_SIZE), "login");
		strcpy(login, ss);
	        password = NULL;
		*sa = holder;
	    }
	    ss = sa+1;
	    sx = strchr(ss, '/');
	    se = strchr(ss, ':');
	    goto normal;
	}
	free(proto);
	return(-1);
    }
normal:;
    if ( se && (!sx || (sx>se)) ) {
	/* port is here */
	he = se;
	h_len = se-ss;
	host = xmalloc(h_len+1, "parse_url, host");
	if ( !host ) {
	    if ( login ) free(login);
	    if ( password ) free(password);
	    free(proto);
	    return(-1);
	}
	memcpy(host, ss, h_len); host[h_len] = 0;
	se++;
	for(i=0; (i<10) && *se && isdigit(*se); i++,se++ ) {
	    number[i]=*se;
	}
	number[i] = 0;
	if ( (pval=atoi(number)) )
		url->port = pval;
	    else {
		if ( so > 0) {
		    /* so can be -1 if called from icp.c */
		    say_bad_request(so, "Bad port value:", number,
			ERR_BAD_PORT, NULL);
		}
		if ( login ) free(login);
		if ( password ) free(password);
		free(proto);
		free(host);
		return(-1);
	}
    } else { /* there was no port */
	
	se = strchr(ss, '/');
	if ( !se )
	    se = src+strlen(src);
	h_len = se-ss;
	host = xmalloc(h_len+1, "parse_url, host");
	if ( !host ) {
	    if ( login ) free(login);
	    if ( password ) free(password);
	    free(proto);
	    return(-1);
	}
	memcpy(host, ss, h_len); host[h_len] = 0;
	if ( !strcasecmp(proto, "http") ) url->port=80;
	if ( !strcasecmp(proto, "ftp") )  url->port=21;
    }
    if ( *se == '/' ) {
	ss = se;
	for(i=0;*se++;i++);
	if ( i ) {
	    path = xmalloc(i+1, "parse_url4");
	    if ( !path ){
		if ( login ) free(login);
		if ( password ) free(password);
		if (host) free(host);
		if (proto)free(proto);
		return(-1);
	    }
	    memcpy(path, ss, i);
	    path[i] = 0;
	}
    } else {
	path=xmalloc(2, "parse_url5");
	if ( !path ){
	    if ( login ) free(login);
	    if ( password ) free(password);
	    if (host) free(host);
	    if (proto)free(proto);
	    return(-1);
	}
	path[0] = '/';path[1] = 0;
    }
    if ( httpv ) {
	httpver = xmalloc(strlen(httpv) + 1, "parse_url, httpver");
	if ( !httpver ) {
	    if ( login ) free(login);
	    if ( password ) free(password);
	    if (host) free(host);
	    if (proto)free(proto);
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

u_short
hash(struct url *url)
{
u_short		res = 0;
int		i;
char		*p;

    p = url->host;
    if ( p && *p ) {
	p = p+strlen(p)-1;
	i = 5;
	while ( (p >= url->host) && i ) i--,res += *p**p--;
    }
    p = url->path;
    if ( p && *p ) {
	p = p+strlen(p)-1;
	i = 5;
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
    	my_log("obj->refs <0 = %d\n", obj->refs);
	exit(0);
    }
}
void
leave_obj(struct mem_obj *obj)
{
/* thread leave this object
	1) decrement ref counter.
	2) if obj marked DEAD or NO_CACHE and !refs free it
*/
u_short 		url_hash = hash(&obj->url);
struct	mem_obj		*child = NULL;
int			must_be_erased = FALSE, urll;
struct	disk_ref	*disk_ref = NULL;
char			*url_str = NULL;
struct	url		*url;

    if ( pthread_mutex_lock(&obj_chain) ) {
	fprintf(stderr, "Failed mutex lock in leave\n");
 	return;
    }
    if ( pthread_mutex_lock(&hash_table[url_hash].lock) ) {
	fprintf(stderr, "Failed mutex lock in leave\n");
	pthread_mutex_unlock(&obj_chain);
	return;
    }
    release_obj(obj);
    if ( (obj->flags & (FLAG_DEAD|ANSW_NO_CACHE)) && !obj->refs ) {
	child = obj->child_obj;
	if ( obj->flags & FLAG_FROM_DISK ) {
	    my_xlog(LOG_HTTP|LOG_FTP|LOG_STOR, "Must be erased from storage\n");
	    must_be_erased = TRUE;
	    url = &obj->url;
	    urll = strlen(url->proto)+strlen(url->host)+strlen(url->path)+10;
	    urll+= 3 + 1; /* :// + \0 */
	    url_str = xmalloc(urll, "url_str");
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
	RDLOCK_CONFIG;
	WRLOCK_DB;
	erase_from_disk(url_str, disk_ref);
	UNLOCK_DB;
	UNLOCK_CONFIG;
	xfree(url_str);
	xfree(disk_ref);
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
    if ( rq->data ) free_container(rq->data);
}
void
free_url(struct url *url)
{
    if (url->host)	free(url->host);
    if (url->proto)	free(url->proto);
    if (url->path)	free(url->path);
    if (url->httpv)	free(url->httpv);
    if (url->login)	free(url->login);
    if (url->password)	free(url->password);
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
#ifdef	MODULES
struct	err_module	*mod = err_first;
int			modflags = 0;

    while ( mod ) {
	mod->err(so, reason, r, code, rq, &modflags);
	mod = (struct err_module*)MOD_NEXT(mod);
	if ( TEST(modflags, MOD_AFLAG_BRK|MOD_AFLAG_OUT) )
	    break;
    }
    if ( !TEST(modflags, MOD_AFLAG_OUT) )
#endif
    {
	writet(so, hdr, strlen(hdr), READ_ANSW_TIMEOUT);
	writet(so, r, strlen(r), READ_ANSW_TIMEOUT);
	writet(so, rf, strlen(rf), READ_ANSW_TIMEOUT);
	writet(so, reason, strlen(reason), READ_ANSW_TIMEOUT);
	writet(so, trailer, strlen(trailer), READ_ANSW_TIMEOUT);
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

    return(0);
}

void
increment_clients()
{
    if ( !pthread_mutex_lock(&clients_lock) ) {
	clients_number++;
	pthread_mutex_unlock(&clients_lock);
    } else {
	my_log("Can't lock clients_lock in increment.\n");
    }
    LOCK_STATISTICS(oops_stat);
	oops_stat.clients++;
    UNLOCK_STATISTICS(oops_stat);
}
void
decrement_clients()
{
    if ( !pthread_mutex_lock(&clients_lock) ) {
	clients_number--;
	pthread_mutex_unlock(&clients_lock);
    } else {
	my_log("Can't lock clients_lock in decrement\n");
    }
    LOCK_STATISTICS(oops_stat);
	oops_stat.clients--;
    UNLOCK_STATISTICS(oops_stat);
}
int
set_socket_options(int so)
{
int	on = -1;
#if	!defined(FREEBSD)
#if	defined(TCP_NODELAY)
     setsockopt(so, IPPROTO_TCP, TCP_NODELAY, (char*)&on, sizeof(on));
#endif
#endif
    return(0);
}
