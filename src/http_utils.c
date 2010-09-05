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
#include	"modules.h"

#define		AND_PUT		1
#define		AND_USE		2

#define		SWITCH_TO_READER_ON(obj) \
		{\
			lock_obj(obj);\
			obj->writers--;\
			obj->readers++;\
			role = ROLE_READER;\
			unlock_obj(obj);\
		}
#define	DECR_READERS(o) {\
		lock_obj(o);\
		o->readers--;\
		unlock_obj(o);\
		}
#define	INCR_READERS(o) {\
		lock_obj(o);\
		o->readers++;\
		unlock_obj(o);\
		}
#define	DECR_WRITERS(o) {\
		lock_obj(o);\
		o->writers--;\
		unlock_obj(o);\
		}
#define	INCR_WRITERS(o) {\
		lock_obj(o);\
		o->writers++;\
		unlock_obj(o);\
		}

#define		DONT_CHANGE_HTTPVER	1

int		no_direct_connections	= FALSE;

static  unsigned int rnd_ctx = 1;

static	char	*build_direct_request(char *meth, struct url *url, char *headers, struct request *rq, int flags);
static	char	*build_parent_request(char*, struct url*, char *, struct request *, int);
static	int	can_recode_rq_content(struct request*);
static	void	change_state(struct mem_obj*, int);
static	void	check_new_object_expiration(struct request*, struct mem_obj*);
static	char	*check_rewrite_charset(char *, struct request *, struct av *, int*);
static	int	content_chunked(struct mem_obj *);
static	int	continue_load(struct request*, int, int, struct mem_obj *);
static	int	downgrade(struct request *, struct mem_obj *);
static	int	loop_detected(char*);
static	struct	mem_obj	*check_validity(int, struct request*, char *, struct mem_obj*);
static	void	process_vary_headers(struct mem_obj*, struct request*);
static	void	pump_data(struct mem_obj*, struct request *, int, int);
static	void	send_data_from_obj(struct request*, int, struct mem_obj *, int);
static	int	srv_connect(int, struct url *url, struct request*);
static	int	srv_connect_silent(int, struct url *url, struct request*);

inline	static	int	add_header_av(char* avtext, struct mem_obj *obj);
inline	static	void	analyze_header(char *p, struct server_answ *a);
inline	static	void	change_state_notify(struct mem_obj *obj);
inline	static	int	is_attr(struct av*, char*);
inline	static	int	is_oops_internal_header(struct av *);
inline	static	void	lock_obj_state(struct mem_obj *);
inline	static	void	unlock_obj_state(struct mem_obj *);
inline	static	void	lock_decision(struct mem_obj *);
inline	static	void	unlock_decision(struct mem_obj *);


void
send_not_cached(int so, struct request *rq, char *headers)
{
int			server_so = -1, r, received = 0, pass=0, to_write;
char			*answer = NULL, *p, *origin;
struct	url		*url = &rq->url;
char			*meth, *source;
struct timeval		start_tv, stop_tv;
struct server_answ	answ_state;
int			delta_tv;
int			have_code = 0;
unsigned int		sent = 0;
struct mem_obj		*obj;
int			header_size = 0;
int			recode_request = FALSE, recode_answer = FALSE;
char			*table = NULL;
ERRBUF ;

    if ( rq->meth == METH_GET ) meth="GET";
    else if ( rq->meth == METH_PUT ) meth="PUT";
    else if ( rq->meth == METH_POST ) meth="POST";
    else if ( rq->meth == METH_TRACE ) meth="TRACE";
    else if ( rq->meth == METH_HEAD ) meth="HEAD";
    else if ( rq->meth == METH_OPTIONS ) meth="OPTIONS";
    else if ( rq->meth == METH_PROPFIND ) meth="PROPFIND";
    else if ( rq->meth == METH_PROPPATCH ) meth="PROPPATCH";
    else if ( rq->meth == METH_DELETE ) meth="DELETE";
    else if ( rq->meth == METH_MKCOL ) meth="MKCOL";
    else if ( rq->meth == METH_COPY ) meth="COPY";
    else if ( rq->meth == METH_MOVE ) meth="MOVE";
    else if ( rq->meth == METH_LOCK ) meth="LOCK";
    else if ( rq->meth == METH_UNLOCK ) meth="UNLOCK";
    else
	return;
    IF_STRDUP(rq->tag, "TCP_MISS");
    obj = locate_in_mem(&rq->url, AND_PUT|AND_USE|PUT_NEW_ANYWAY|NO_DISK_LOOKUP, NULL, NULL);
    if ( !obj ) {
	my_xlog(OOPS_LOG_SEVERE, "send_not_cached(): Can't create new_obj.\n");
	goto done;
    }
    bzero(&answ_state, sizeof(answ_state));
    gettimeofday(&start_tv, NULL);
    if ( parent_port ) {
        server_so = parent_connect(so, parent_host, parent_port, rq);
    } else {
        SET(rq->flags, RQ_SERVED_DIRECT);
        server_so = srv_connect(so, url, rq);
    }

    if ( server_so == -1 )
	goto done;

    set_socket_options(server_so);
    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(OOPS_LOG_SEVERE, "send_not_cached(): fcntl(): %m\n");
    if ( fcntl(server_so, F_SETFL, fcntl(server_so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(OOPS_LOG_SEVERE, "send_not_cached(): fcntl(): %m\n");

    if ( parent_port && parent_auth ) {
	IF_FREE(rq->peer_auth); rq->peer_auth = NULL;
	rq->peer_auth = strdup(parent_auth);
    }
    answer = parent_port?build_parent_request(meth, &rq->url, NULL, rq, DONT_CHANGE_HTTPVER):
		         build_direct_request(meth, &rq->url, NULL, rq, DONT_CHANGE_HTTPVER);
    if ( !answer )
	goto done;

    if ( rq->cs_to_server_table
		&& rq->cs_to_server_table->list
		&& rq->cs_to_server_table->list->string
		&& can_recode_rq_content(rq) )
	recode_request = TRUE;

    /* push whole request to server */
    if ( recode_request )
	r = writet_cv_cs(server_so, answer, strlen(answer), READ_ANSW_TIMEOUT,
			rq->cs_to_server_table->list->string, TRUE);
      else
	r = writet(server_so, answer, strlen(answer), READ_ANSW_TIMEOUT);
    xfree(answer); answer = NULL;
    if ( r < 0 ) {
	say_bad_request(so, "Can't send", STRERROR_R(ERRNO, ERRBUFS),
			ERR_TRANSFER, rq);
	goto done;
    }
    answer = xmalloc(ANSW_SIZE+1, "send_not_cached(): 1");
    if ( !answer ) goto done;
    if ( rq->leave_to_read || rq->data ) {
	char	*cp = NULL;
	int	rest= 0;
	/* send whole content to server				*/

	if ( rq->data ) {
	    cp  = rq->data->data;
	    rest= rq->data->used;
	}

	while ( rest > 0 ) {
	    int to_send;
	    to_send = MIN(2048, rest);
	    if ( recode_request )
		r = writet_cv_cs(server_so, cp, to_send, 100,
			rq->cs_to_server_table->list->string, TRUE);
	      else
		r = writet(server_so, cp, to_send, 100);
	    if ( r < 0 )
		goto done;
	    rest -= r;
	    cp   += r;
	}
	/* now if we have something to read from client - do it */
	while ( rq->leave_to_read > 0 ) {
	    r = readt(so, answer, MIN(ANSW_SIZE, rq->leave_to_read),
	    			  READ_ANSW_TIMEOUT);
	    if ( r < 0 )
		goto done;

	    rq->leave_to_read -= r;
	    if ( recode_request )
		r = writet_cv_cs(server_so, answer, r, READ_ANSW_TIMEOUT,
			rq->cs_to_server_table->list->string, TRUE);
	      else
		r = writet(server_so, answer, r, READ_ANSW_TIMEOUT);
	    if ( r <= 0 )
		goto done;
	}
#if	defined(LINUX)
	/* at least redhat 6.02 have such feature: close() for the
	   socket with unread data reset connection (send RST flag).
	   This confuse browsers. So read any pending data (actually
	   can be only \n or \n\n after request body
	*/
	while( wait_for_read(so, 1000) > 0 ) {
	    int rc = readt(so, answer, ANSW_SIZE, 10);
	    if ( rc <= 0 ) goto done;
	}
#endif /* LINUX */
    }
    forever() {
	r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
	if ( r < 0 ) {
	    if ( !sent ) say_bad_request(so, "Can't read", STRERROR_R(ERRNO, ERRBUFS),
					 ERR_TRANSFER, rq);
	    goto done;
	}
        if ( r == 0 ) /*done*/
	    goto done;
	received += r;
	rq->doc_received += r;
	if ( !have_code ) {
	    /* try to find it */
	    int http_maj, http_min,code ;
	    answer[r] = 0;
	    if ( sscanf(answer, "HTTP/%d.%d %d", &http_maj, &http_min, &code) == 3 ) {
		have_code = code;
	    } else {
		/* this is not a HTTP answer, just pump it to browser */
		writet(so, answer, r, READ_ANSW_TIMEOUT);
		pump_data(obj, rq, so, server_so);
		received = rq->received;
		goto done;
	    }
	}
	if ( !(answ_state.state & GOT_HDR) ) {
	    obj->size += r;
	    sent += r;
	    if ( !obj->container ) {
		struct buff *new;

		new = alloc_buff(CHUNK_SIZE);
		if ( !new ) goto done;
		obj->container = new;
	    }
	    if ( attach_data(answer, r, obj->container) ) {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_not_cached(): attach_data().\n");
		goto done;
	    }
	    if ( check_server_headers(&answ_state, obj, obj->container, rq) ) {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_not_cached(): check_server_headers().\n");
                if ( obj->container ) {
                    writet(so, obj->container->data, obj->container->used, READ_ANSW_TIMEOUT);
                    pump_data(obj, rq, so, server_so);
                    received = rq->received;
                }
		goto done;
	    }
	    if ( answ_state.state & GOT_HDR ) {
		struct	av	*header;
		struct	buff	*hdrs_to_send;

		obj->flags|= answ_state.flags;
		header_size = obj->container->used;
		header = obj->headers;
		if ( !header ) goto done ;
		hdrs_to_send = alloc_buff(512);
		if ( !hdrs_to_send ) goto done;
		while(header) {
	    	my_xlog(OOPS_LOG_DBG, "send_not_cached(): Sending ready header `%s' -> `%s'.\n",
			header->attr, header->val);
		    if ( !is_oops_internal_header(header) ) {

			if ( rq->src_charset[0] && rq->cs_to_client_table
				&& rq->cs_to_client_table->list
				&& rq->cs_to_client_table->list->string
				&& is_attr(header, "Content-Type") && header->val ) {
			    char *s = NULL, *d = NULL, ct_buf[64];

			    /* we change charset only in 'text / *' */
			    if ( strlen(header->val) >= sizeof(ct_buf) ) {
				s = strdup(header->val);
			    } else {
				strncpy(ct_buf, header->val, sizeof(ct_buf)-1);
				ct_buf[sizeof(ct_buf)-1] = 0;
				s = ct_buf;
			    }
			    if ( s
			    	&& (d = check_rewrite_charset(s, rq, header, &recode_answer)) ) {
				my_xlog(OOPS_LOG_DBG, "send_not_cached(): Rewriten header=`%s'.\n", d);
				attach_data(d, strlen(d), hdrs_to_send);
				attach_data("\r\n", 2, hdrs_to_send);
				xfree(d);
				if ( s && (s != ct_buf) )
				    xfree(s);
				table = rq->cs_to_client_table->list->string;
				recode_answer = TRUE;
				header = header->next;
				continue;
			    }
			    if ( s && (s != ct_buf) )
				xfree(s);
			} /* Content-Type: ... */
			attach_av_pair_to_buff(header->attr, header->val, hdrs_to_send);
		    }
		    header = header->next;
		}
		attach_av_pair_to_buff("", "", hdrs_to_send);
		if ( recode_answer )
		    writet_cv_cs(so, hdrs_to_send->data, hdrs_to_send->used, READ_ANSW_TIMEOUT,
			table, TRUE);
		  else
		    writet(so, hdrs_to_send->data, hdrs_to_send->used, READ_ANSW_TIMEOUT);
		if ( TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) )
		    update_transfer_rate(rq, hdrs_to_send->used);
		rq->doc_sent += hdrs_to_send->used;
		free_container(hdrs_to_send);
		if ( obj->container && obj->container->next ) {
		    if ( recode_answer )
			writet_cv_cs(so, obj->container->next->data, obj->container->next->used, READ_ANSW_TIMEOUT,
				table, FALSE);
		      else
			writet(so, obj->container->next->data, obj->container->next->used, READ_ANSW_TIMEOUT);
		    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) )
			update_transfer_rate(rq, obj->container->next->used);
		    if ( rq->sess_bw )
			update_sess_transfer_rate(rq, obj->container->next->used);
		    rq->doc_sent += obj->container->next->used;
		}
		if ( obj->content_length
		    && (sent >= obj->container->used + obj->content_length) )
		    goto done;
		rq->doc_size = obj->content_length;
	    }
	    continue ;
	}
	to_write = r;
	p = answer;
	while( to_write ) {
	    r = MIN(to_write, 2048);
	    pass++;
	    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) ) {
		if ( pass%2 ) SLOWDOWN ;
		r = MIN(to_write, 512);
	    }
	    if ( rq->sess_bw ) {
		if ( pass%2 ) SLOWDOWN_SESS ;
		r = MIN(to_write, 512);
	    }
	    /* if client close connection we'll note here */
	    if ( recode_answer )
		r = writet_cv_cs(so, p, r, READ_ANSW_TIMEOUT, table, FALSE);
	      else
		r = writet(so, p, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 )
		goto done;
	    sent += r;
	    rq->doc_sent += r;
	    to_write -= r;
	    p += r;
	    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) ) update_transfer_rate(rq, r);
	    if ( rq->sess_bw ) update_sess_transfer_rate(rq, r);
	    if ( TEST(obj->flags,ANSW_KEEP_ALIVE) && header_size && obj->content_length ) {
		if ( sent >= header_size+obj->content_length )
		    goto done;
	    }
	}
	if (     obj->content_length
	     && (sent >= obj->container->used + obj->content_length) )
	    goto done;
    }

done:
    if ( server_so != -1 ) CLOSE(server_so);
    if ( answer ) xfree(answer);
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( !have_code ) have_code = 555;
    source = parent_port?(TEST(rq->flags, RQ_GO_DIRECT)?"DIRECT":"PARENT"):"DIRECT";
    if ( parent_port ) origin = parent_host;
	else	       origin = url->host;

    IF_STRDUP(rq->hierarchy, source);
    IF_STRDUP(rq->source, origin);
    rq->code = have_code;
    rq->received = received;
    log_access(delta_tv, rq, obj);
    if ( obj ) { obj->flags|=FLAG_DEAD; leave_obj(obj);}
    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_not_cached(): not_cached done.\n");
    return;
}

void
send_from_mem(int so, struct request *rq, char *headers, struct mem_obj *obj, int flags)
{
int			server_so = -1;
struct	mem_obj		*new_obj = NULL;
struct	timeval		start_tv, stop_tv;
time_t			now;
int			delta_tv, received, rc;
int			have_code = 0;
char			*tcp_tag = "TCP_HIT", *meth;
#define			ROLE_READER	1
#define			ROLE_WRITER	2
#define			ROLE_VALIDATOR	3
int			role, no_more_logs = FALSE, source_type;
char			*origin;
struct	sockaddr_in	peer_sa;
hash_entry_t            *he = NULL;

    if ( rq->meth == METH_GET ) meth="GET";
    else if ( rq->meth == METH_PUT ) meth="PUT";
    else if ( rq->meth == METH_POST ) meth="POST";
    else if ( rq->meth == METH_HEAD ) meth="HEAD";
    else
	return;

    gettimeofday(&start_tv, NULL);
    if ( flags & MEM_OBJ_MUST_REVALIDATE ) goto revalidate;

    if ( !(rq->flags & RQ_HAS_IF_MOD_SINCE) ) goto prepare_send_mem;

    now = time(NULL);
    if ( ( obj->flags & ANSW_HAS_EXPIRES ) &&
         	( now < obj->times.expires ) ) {
	my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_from_mem(): Document not expired, send from mem.\n");
	goto prepare_send_mem;
    }
    goto revalidate;

prepare_send_mem:
    role = ROLE_READER;
    INCR_READERS(obj);
    IF_STRDUP(rq->tag, tcp_tag);
    send_data_from_obj(rq, so, obj, flags);
    DECR_READERS(obj);
    goto done;

revalidate:
    INCR_WRITERS(obj);
    if ( obj->writers > 1 ) {
	/* another thread revalidate(d) object		*/
	/* just wait for decision			*/
	role = ROLE_VALIDATOR;
	tcp_tag = "TCP_REFRESH_HIT";
	lock_decision(obj);
	IF_STRDUP(rq->tag, tcp_tag);
	while(!obj->decision_done )
	    pthread_cond_wait(&obj->decision_cond, &obj->decision_lock);
	unlock_decision(obj);
	if ( !obj->child_obj ) {
	    /*--------------------------------------------------*/
	    /* old object is valid				*/
	    /* switch to READER role, because we will use	*/
	    /* old content					*/
	    /*--------------------------------------------------*/
	    SWITCH_TO_READER_ON(obj);
	    send_data_from_obj(rq, so, obj, flags);
	    DECR_READERS(obj);
	    goto done;
	}
	/* else switch to child object, which is now valid	*/
	DECR_WRITERS(obj);
	new_obj=obj->child_obj;
	lock_obj(new_obj);
	new_obj->refs++;
	new_obj->readers++;
	unlock_obj(new_obj);	
	send_data_from_obj(rq, so, new_obj, flags);
	DECR_READERS(new_obj);
	goto done;
    } else {
	/* this thread will write in obj if need		*/
	role = ROLE_WRITER;
	lock_decision(obj);
	obj->decision_done = FALSE ;
	/* if obj had child obj and hold refs to it - release	*/
        if ( obj->child_obj )
		DECREMENT_REFS(obj->child_obj);
	obj->child_obj = NULL;
    retry:
	if ( !TEST(rq->flags, RQ_NO_ICP|RQ_GO_DIRECT) && !parent_port && peers && (icp_so != -1)
	 && (rq->meth == METH_GET)
	 && !destination_is_local(rq->url.host) ) {
	    struct icp_queue_elem *new_qe;
	    struct timeval tv = start_tv;
	    bzero((void*)&peer_sa, sizeof(peer_sa));
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Sending icp requests.\n");
	    new_qe = (struct icp_queue_elem*)xmalloc(sizeof(*new_qe),"fill_mem_obj(): new_qe");
	    if ( !new_qe ) goto icp_failed;
	    bzero(new_qe, sizeof(*new_qe));
	    pthread_cond_init(&new_qe->icpr_cond, NULL);
	    pthread_mutex_init(&new_qe->icpr_mutex, NULL);
	    new_qe->waitors = 1;
	    new_qe->rq_n    = rand_r(&rnd_ctx);
	    pthread_mutex_lock(&new_qe->icpr_mutex);
	    if ( !send_icp_requests(rq, new_qe, &he) ) {
		/* was placed in queue	*/
		struct timespec  ts;
		tv.tv_sec  += icp_timeout/1000000;
		tv.tv_usec += icp_timeout%1000000;
		if ( tv.tv_usec > 1000000 ) {
		    tv.tv_sec++;
		    tv.tv_usec-=1000000;
		}
		ts.tv_sec  = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec*1000;
		/* wait for answers */
		if ( !new_qe->status && pthread_cond_timedwait(&new_qe->icpr_cond,&new_qe->icpr_mutex,&ts) ) {
		    /* failed */
		    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): icp timed out.\n");
		} else {
		    /* success */
		    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): icp success.\n");
		}
		new_qe->rq_n = 0;
		pthread_mutex_unlock(&new_qe->icpr_mutex);
                if ( he ) {
                    rc = delete_hash_entry(icp_requests_hash, he, NULL);
                    if ( rc != 0 )
                        abort();
                }
		if ( new_qe->status ) {
		    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Fetch from neighbour.\n");
		    peer_sa = new_qe->peer_sa;
		    source_type = new_qe->type;
		    server_so = peer_connect_silent(so, &new_qe->peer_sa, rq);
		    icp_request_destroy(new_qe);
		    xfree(new_qe);
		    goto server_connect_done;
		} else {
		    if ( no_direct_connections ) {
		   /* what now ? */
		    }
		    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Direct.\n");
		}
		icp_request_destroy(new_qe);
		xfree(new_qe);
		goto icp_failed;
	    } else {
		pthread_mutex_unlock(&new_qe->icpr_mutex);
		pthread_mutex_destroy(&new_qe->icpr_mutex);
		pthread_cond_destroy(&new_qe->icpr_cond);
		xfree(new_qe);
	    }

    icp_failed:;
	} /* all icp things */
	/* now make decision - object is valid or not		*/
        if ( parent_port 
             && !TEST(rq->flags, RQ_GO_DIRECT)
             && !destination_is_local(rq->url.host) ) {
	    server_so = parent_connect_silent(so, parent_host, parent_port, rq);
            source_type = PEER_PARENT;
	} else {
            SET(rq->flags, RQ_SERVED_DIRECT);
	    server_so = srv_connect_silent(so, &obj->url, rq);
            source_type = SOURCE_DIRECT;
        }

    server_connect_done:;
	if ( server_so == -1 ) {
	    /* send old content, but mark obj dead		*/
	    SET(obj->flags, FLAG_DEAD);
	    SWITCH_TO_READER_ON(obj);
	    obj->decision_done = TRUE ;
	    unlock_decision(obj);
	    pthread_cond_broadcast(&obj->decision_cond);
	    send_data_from_obj(rq, so, obj, flags);
	    DECR_READERS(obj);
	    goto done;
	}
	new_obj = check_validity(server_so, rq, meth, obj);
	if ( new_obj ) {
            if ( (source_type != SOURCE_DIRECT)
                && ((new_obj->status_code == STATUS_GATEWAY_TIMEOUT)
                     || (new_obj->status_code == STATUS_FORBIDEN)) ) {
                /* peer was not able... */
	        SET(new_obj->flags, FLAG_DEAD);
                leave_obj(new_obj); new_obj = NULL;
                SET(rq->flags, RQ_GO_DIRECT);
                if ( server_so != -1 ) close(server_so);
                server_so = -1;
                goto retry;
            }
	    obj->child_obj = new_obj;
	    obj->decision_done = TRUE ;
	    unlock_decision(obj);
	    pthread_cond_broadcast(&obj->decision_cond);
	    /* increment references to new_obs, as obj refers	*/
	    /* to it						*/
	    INCREMENT_REFS(new_obj);
	    /* old object is invalid anymore 			*/
	    SET(obj->flags, FLAG_DEAD);
	    tcp_tag = "TCP_REFRESH_MISS";
	    IF_STRDUP(rq->tag, tcp_tag);
	    /* continue load to new_obj */
	    if ( rq->proto == PROTO_FTP ) {
		ftp_fill_mem_obj(so, rq, headers, new_obj);
		no_more_logs = TRUE;
	    } else
		continue_load(rq, so, server_so, new_obj);
	    DECR_WRITERS(new_obj);
	    new_obj->response_time	= time(NULL);
	    goto done;
	} else {
	    /*--------------------------------------------------*/
	    /* old object is valid				*/
	    /* switch to READER role, because we will use	*/
	    /* old content					*/
	    obj->decision_done = TRUE ;
	    unlock_decision(obj);
	    pthread_cond_broadcast(&obj->decision_cond);
	    /*--------------------------------------------------*/
	    tcp_tag = "TCP_REFRESH_HIT";
	    IF_STRDUP(rq->tag, tcp_tag);
	    SWITCH_TO_READER_ON(obj);
	    send_data_from_obj(rq, so, obj, flags);
	    DECR_READERS(obj);
	    goto done;
	}
    }

done:
    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_from_mem(): From mem sended.\n");
    if ( new_obj ) leave_obj(new_obj);
    if ( server_so != -1 ) CLOSE(server_so);
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( obj->status_code ) have_code = obj->status_code;
	else		    have_code = 555;
    if ( new_obj ) received = new_obj->size;
         else	   received =     obj->size;
    if ( parent_port && !TEST(rq->flags, RQ_GO_DIRECT) )
    		origin = parent_host;
	else
		origin = obj->url.host;

    if ( !no_more_logs ) {
	IF_STRDUP(rq->hierarchy, "NONE");
	IF_STRDUP(rq->source, origin);
	rq->code = have_code;
	rq->received = received;
	log_access(delta_tv, rq, obj);
    }
    LOCK_STATISTICS(oops_stat);
	oops_stat.hits0++;
	oops_stat.hits++;
    UNLOCK_STATISTICS(oops_stat);
    return;
}

static void
send_data_from_obj(struct request *rq, int so, struct mem_obj *obj, int flags)
{
int 		r, received, send_hot_pos, pass = 0, sf = 0;
unsigned int	sended, ssended, state;
struct	buff	*send_hot_buff;
char		convert_from_chunked = FALSE, downgrade_minor = FALSE;
char		ungzip = FALSE;
int		convert_charset = FALSE;
int		partial_content = FALSE;
int		rest_in_chunk = 0, content_length_sent = 0, downgrade_flags;
char		*table = NULL;
int		osize =  0;
struct pollarg	pollarg;

    downgrade_flags = downgrade(rq, obj);
    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_data_from_obj(): Downgrade flags: %x\n", downgrade_flags);

    if ( TEST(downgrade_flags, DOWNGRADE_ANSWER) )
	downgrade_minor = TRUE;
    if ( TEST(downgrade_flags, UNCHUNK_ANSWER) )
	convert_from_chunked = TRUE;
    if ( TEST(downgrade_flags, UNGZIP_ANSWER) )
	ungzip = TRUE;

    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(OOPS_LOG_SEVERE, "send_data_from_obj(): fcntl(): %m\n");
    sended = 0;
    received = obj->size;
    send_hot_buff = NULL;
    send_hot_pos = 0;

go_again:
    lock_obj_state(obj);
    forever() {
	state = obj->state;
	switch(state) {
	  case OBJ_READY:
	    unlock_obj_state(obj);
	    goto send_ready;
	  case OBJ_EMPTY:
	    pthread_cond_wait(&obj->state_cond, &obj->state_lock);
	    continue;
	  case OBJ_INPROGR:
	    if ( sended < obj->size ) {
		unlock_obj_state(obj);
		goto send_ready;
	    }
	    pthread_cond_wait(&obj->state_cond, &obj->state_lock);
	    continue;
	}
    }

send_ready:
    if ( !send_hot_buff ) {
    	struct	av	*header = obj->headers;
	struct	buff	*hdrs_to_send;

	if ( !header ) goto done ;
	hdrs_to_send = alloc_buff(512);
	if ( !hdrs_to_send ) goto done;
	/* we pay attention to 'Range:' iff
	   1) object is ready (it is all here)
	   2) doc have no chunked content
	   3) range is like 'nnn-'
	 */
	if ( TEST(rq->flags, RQ_HAVE_RANGE)
	     &&  (obj->state == OBJ_READY)
	     &&  !content_chunked(obj)
	     &&  ((rq->range_from >= 0) && (rq->range_to == -1))) {

		struct buff *tb = NULL;
		char	buff[80];

		partial_content = TRUE;
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG,"We will send partial content\n");
		attach_av_pair_to_buff("HTTP/1.0", "206 Partial Content", hdrs_to_send);
		header = header->next;
		/* now build Content-Range header	*/
		/* find object size			*/
		if ( obj->container && obj->container->next )
		    tb = obj->container->next;
		while ( tb != NULL ) {
		    osize += tb->used;
		    tb = tb->next;
		}
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG,"Total obj size: %d starting from: %d\n",
			osize, rq->range_from);
		if ( rq->range_from > osize ) {
		    /* this is VERY strange				*/
		    /* either object or request or user file is wrong	*/
		    /* we can mark doc as dead, but this open path to	*/
		    /* DoS(?) - by sending wrong requests user can purge*/
		    /* any valid document. So we simply ajust values	*/
		    rq->range_from = osize;
		}
		snprintf(buff, sizeof(buff)-1, "bytes %d-%d/%d", rq->range_from, osize, osize);
		attach_av_pair_to_buff("Content-Range:", buff, hdrs_to_send);
	} else {
	    /* first must be "HTTP/1.x 200 ..." */
	    if ( downgrade_minor ) {
		attach_av_pair_to_buff("HTTP/1.0", header->val, hdrs_to_send);
		header = header->next;
	    }
	} /* partial content */
	while(header) {
	    my_xlog(OOPS_LOG_DBG, "send_data_from_obj(): Sending ready header `%s' -> `%s'.\n",
		    header->attr, header->val);
	    if (   !is_attr(header, "Age:") &&
                   !is_attr(header, "Set-cookie:") &&
		   !is_oops_internal_header(header) &&

			/* we must not send Tr.-Enc. and Cont.-Len. if we convert
			 * from chunked							*/

		   !(convert_from_chunked && is_attr(header, "Transfer-Encoding")) &&
			/* we alvays ungzip gzipped content	*/
		   !(ungzip && is_attr(header, "Content-Encoding"))&&
	    	   !((convert_from_chunked||partial_content||ungzip) && is_attr(header, "Content-Length")) ){

		if ( !content_length_sent )
		    content_length_sent = is_attr(header, "Content-Length");
		if ( rq->src_charset[0] && rq->cs_to_client_table && is_attr(header, "Content-Type") && header->val ) {
		    char *s = NULL, *d = NULL, ct_buf[64];

		    /* we change charset only in 'text/ *' */
		    if ( strlen(header->val) >= sizeof(ct_buf) ) {
			s = strdup(header->val);
		    } else {
			strncpy(ct_buf, header->val, sizeof(ct_buf)-1);
			ct_buf[sizeof(ct_buf)-1] = 0;
			s = ct_buf;
		    }
		    if ( s
		    	&& (d = check_rewrite_charset(s, rq, header, &convert_charset)) ) {
			my_xlog(OOPS_LOG_DBG, "send_data_from_obj(): Rewriten header = `%s'.\n", d);
			attach_data(d, strlen(d), hdrs_to_send);
			attach_data("\r\n", 2, hdrs_to_send);
			xfree(d);
			if ( s && (s != ct_buf) )
			    xfree(s);
			table = rq->cs_to_client_table->list->string;
			convert_charset = TRUE;
			header = header->next;
			continue;
		    }
		    if ( s && (s != ct_buf) )
			xfree(s);
		} /* Content-Type: ... */
		attach_av_pair_to_buff(header->attr, header->val, hdrs_to_send);
	    }
	    header = header->next;
	}
	/* send header from memory */
	if ( flags & MEM_OBJ_WARNING_110 ) {
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_data_from_obj(): Send Warning: 110 oops Stale document.\n");
	    attach_av_pair_to_buff("Warning:", "110 oops Stale document", hdrs_to_send);
	}
	if ( flags & MEM_OBJ_WARNING_113 ) {
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_data_from_obj(): Send Warning: 113 oops Heuristic expiration used.\n");
	    attach_av_pair_to_buff("Warning:", "113 oops Heuristic expiration used", hdrs_to_send);
	}
	if ( ungzip ) {
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_data_from_obj(): Send Warning: 14 oops Converted from gzip.\n");
	    attach_av_pair_to_buff("Warning:", "14 oops Transformation from gzip applied", hdrs_to_send);
	}
	if ( !content_length_sent && partial_content ) {
	    char clbuf[32];
	    snprintf(clbuf, sizeof(clbuf)-1,"%d", osize-rq->range_from);
	    attach_av_pair_to_buff("Content-Length:", clbuf, hdrs_to_send);
	    content_length_sent = TRUE;
	}
	if ( !content_length_sent && ungzip && obj->ungzipped_cont_len) {
	    char clbuf[32];
	    snprintf(clbuf, sizeof(clbuf)-1, "%d", obj->ungzipped_cont_len);
	    attach_av_pair_to_buff("Content-Length:", clbuf, hdrs_to_send);
	    content_length_sent = TRUE;
	}
	if ( obj->x_content_length && !content_length_sent ) {
	    char clbuf[32];
	    snprintf(clbuf, sizeof(clbuf)-1, "%d", obj->x_content_length);
	    attach_av_pair_to_buff("Content-Length:", clbuf, hdrs_to_send);
	    content_length_sent = TRUE;
	}
	{
	    char agebuf[32];
	    snprintf(agebuf, sizeof(agebuf)-1, "%d", (int)current_obj_age(obj));
	    attach_av_pair_to_buff("Age:", agebuf, hdrs_to_send);
	}
	rq->doc_size = obj->content_length;
	/* end of headers */
	attach_av_pair_to_buff("","", hdrs_to_send);
	if ( convert_charset && rq->cs_to_client_table
			     && rq->cs_to_client_table->list
			     && rq->cs_to_client_table->list->string)
	    writet_cv_cs(so, hdrs_to_send->data, hdrs_to_send->used, READ_ANSW_TIMEOUT,
		rq->cs_to_client_table->list->string, TRUE);
	  else
	    writet(so, hdrs_to_send->data, hdrs_to_send->used, READ_ANSW_TIMEOUT);
        my_xlog(OOPS_LOG_HTTP, "send_data_from_obj(): Headers sent: %d bytes\n", hdrs_to_send->used);
	free_container(hdrs_to_send);
	if ( !obj->container ) goto done;
	if ( partial_content ) {
	    struct buff *tb;
	    int		temp_pos_counter;
	    sended = obj->container->used;
	    tb = obj->container->next;
	    temp_pos_counter = 0;
	    while ( tb ) {
		if ( (temp_pos_counter + tb->used) > rq->range_from ) {
		    break;
		}
		temp_pos_counter +=  tb->used;
		sended += tb->used;
		tb = tb->next;
	    } /* while ( tb ) */
	    if ( tb ) {
		send_hot_buff = tb;
		send_hot_pos = rq->range_from - temp_pos_counter;
	    } else {
		/* something is VERY bad... */
		if ( temp_pos_counter != osize )
			my_xlog(OOPS_LOG_SEVERE, "send_data_from_obj(): Something is wrong with partial content: sended = %d, osize = %d\n",
				temp_pos_counter, osize);
		goto done;
	    }
	} else {
	    send_hot_pos = 0;
	    send_hot_buff = obj->container->next;
	    sended = obj->container->used;
	} /* partial content */
	if ( !partial_content) pre_body(so, obj, rq, NULL);
#if	defined(HAVE_ZLIB)
	if ( ungzip ) {
	    bzero(&rq->strm, sizeof(rq->strm));
	    rq->decoding_buff = xmalloc(DECODING_BUF_SZ, "decoding");
	    rq->strmp = &rq->strm;
	    if ( Z_OK != inflateInit2(rq->strmp, -MAX_WBITS) ) {
		rq->strmp = NULL;
	    } else
		rq->flags |= RQ_CONVERT_FROM_GZIPPED;
	}
#endif
    }
    if ( (state == OBJ_READY) && (sended >= obj->size) ) {
	my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_data_from_obj(): obj is ready: sended(%d) >= obj->size(%d).\n", sended, obj->size);
	goto done;
    }
    if ( (++pass)%2 && TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) )
	SLOWDOWN ;
    if ( rq->sess_bw && pass%2 ) SLOWDOWN_SESS;
    pollarg.fd = so;
    pollarg.request = FD_POLL_WR;
    r = poll_descriptors(1, &pollarg, READ_ANSW_TIMEOUT*1000);
    if ( r <= 0 ) goto done;
    ssended = sended;
    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) )
	sf |= RQ_HAS_BANDWIDTH;
    if ( convert_from_chunked )
	sf |= RQ_CONVERT_FROM_CHUNKED;
    if ( IS_HUPED(&pollarg) )
	goto done;
    if ( (r = send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, &rest_in_chunk, sf, obj, table, rq)) != 0 ) {
	my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_data_from_obj(): send_data_from_buff_no_wait(): Send error: %m\n");
	goto done;
    }
    my_xlog(OOPS_LOG_HTTP, "send_data_from_obj(): sended=%d, ssended=%d\n", sended, ssended);
    if ( rest_in_chunk == -1 )
	goto done;
    if ( (state == OBJ_READY) && (sended == ssended) )
	goto done;
    if ( (state == OBJ_INPROGR) && (sended == ssended) ) {
	/* this must not happen, log it */
	if ( obj->url.host && obj->url.path )
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_data_from_obj(): Impossible event on `%s%s'.\n",
		    obj->url.host, obj->url.path);
	goto done;
    }
    if ( !r && convert_from_chunked && !rest_in_chunk ) {
	/* we sent nothing... this can be because we convert from chunked
	 * ans we have only part of chunk size value stored in buff. like this:
	 * | ..... 2f| - e.g currently available buff contain
	 * only begin of chunk size, without ending CRLF
	 * If object is ready, this means something wrong, just return.
	 * If object is in progress, we have to wait some time.			*/
	if ( obj->state == OBJ_READY )
	    goto done;
	/* else object in progress, sleep a little */
	my_sleep(1);
	goto go_again;
    }
    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW)) update_transfer_rate(rq, sended-ssended);
    if ( rq->sess_bw ) update_sess_transfer_rate(rq, sended-ssended);
    rq->doc_sent += sended-ssended;
    goto go_again;

done:
#if	defined(HAVE_ZLIB)
    if (rq->strmp) inflateEnd(rq->strmp);
#endif
    return;
}

/* return new object if old is invalid	*/
/* otherwise returns NULL		*/
static struct mem_obj *
check_validity(int server_so,
	struct request	*rq,
	char		*meth,
	struct mem_obj	*obj)
{
char			*fake_header = NULL;
char			mk1123buff[50];
struct	mem_obj 	*new_obj = NULL;
char			*answer = NULL;
struct	server_answ	answer_stat;
int			r;
struct	buff		*to_server_request = NULL;

    if ( rq->proto == PROTO_FTP ) {
	/* ftp always must be reloaded */
	new_obj = locate_in_mem(&rq->url, AND_PUT|AND_USE|PUT_NEW_ANYWAY|NO_DISK_LOOKUP, NULL, NULL);
	if ( !new_obj ) {
	    my_xlog(OOPS_LOG_SEVERE, "check_validity(): Can't create new_obj.\n");
	    goto validate_err;
	}
	return(new_obj);
    }
    /* send If-modified-Since request	*/
    /* prepare faked header		*/
    if ( obj->times.last_modified ) {
        if (!mk1123time(obj->times.last_modified, mk1123buff, sizeof(mk1123buff)) ) {
	    my_xlog(OOPS_LOG_SEVERE, "check_validity(): Can't mk1123time.\n");
	    goto validate_err;
	}
    }
    else /* No Last-Modified */
    if (!mk1123time(obj->times.date, mk1123buff, sizeof(mk1123buff)) ) {
	my_xlog(OOPS_LOG_SEVERE, "check_validity(): Can't mk1123time.\n");
	goto validate_err;
    }
    fake_header = xmalloc(19 + strlen(mk1123buff) + 3, "check_validity(): for fake header");
    if ( !fake_header ) {
	my_xlog(OOPS_LOG_SEVERE, "check_validity(): Can't create fake header.\n");
	goto validate_err;
    }
    sprintf(fake_header, "If-Modified-Since: %s\r\n", mk1123buff);

    if ( parent_port && parent_auth ) {
	IF_FREE(rq->peer_auth); rq->peer_auth = NULL;
	rq->peer_auth = strdup(parent_auth);
    }
    answer = parent_port?build_parent_request(meth, &rq->url, fake_header, rq, 0):
		         build_direct_request(meth, &rq->url, fake_header, rq, 0);
    if ( !answer )
	goto validate_err;
    to_server_request = alloc_buff(2*CHUNK_SIZE);
    if ( !to_server_request ) {
	my_xlog(OOPS_LOG_SEVERE, "check_validity(): No mem.\n");
	goto validate_err;
    }
    r = attach_data(answer, strlen(answer), to_server_request);
    if ( r || attach_data("\r\n", 2, to_server_request) )
	goto validate_err;
    if ( rq->cs_to_server_table
		&& rq->cs_to_server_table->list
		&& rq->cs_to_server_table->list->string)
	r = writet_cv_cs(server_so, to_server_request->data,
				    to_server_request->used, READ_ANSW_TIMEOUT,
				rq->cs_to_server_table->list->string, TRUE);
      else
	r = writet(server_so, to_server_request->data, to_server_request->used,
    		READ_ANSW_TIMEOUT);
    xfree(answer); answer = NULL;
    xfree(fake_header); fake_header = NULL;
    free_container(to_server_request); to_server_request = NULL;

    new_obj = locate_in_mem(&rq->url, AND_PUT|AND_USE|PUT_NEW_ANYWAY|NO_DISK_LOOKUP, NULL, NULL);
    if ( !new_obj ) {
	my_xlog(OOPS_LOG_SEVERE, "check_validity(): Can't create new_obj.\n");
	goto validate_err;
    }

    new_obj->request_time = time(NULL);
    bzero(&answer_stat, sizeof(answer_stat));
    answer = xmalloc(ANSW_SIZE, "check_validity(): send_from_mem3");
    if ( !answer ) {
	goto validate_err;
    }

    if ( fcntl(server_so, F_SETFL, fcntl(server_so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(OOPS_LOG_SEVERE, "check_validity(): fcntl(): %m\n");
    forever() {
	struct pollarg pollarg;

	pollarg.fd = server_so;
	pollarg.request = FD_POLL_RD;
	r = poll_descriptors(1, &pollarg, READ_ANSW_TIMEOUT*1000);
	if ( r < 0  ) {
	    my_xlog(OOPS_LOG_SEVERE, "check_validity(): select: error on new_obj.\n");
	    goto validate_err;
	}
	if ( r == 0 ) {
	    my_xlog(OOPS_LOG_SEVERE, "check_validity(): select: timed out on new_obj.\n");
	    goto validate_err;
	}
	if ( IS_HUPED(&pollarg) ) {
	    my_xlog(OOPS_LOG_SEVERE, "check_validity(): Server closed connection too early.\n");
	    goto validate_err;
	}
	if ( !IS_READABLE(&pollarg) )
	    continue;
	r = recv(server_so, answer, ANSW_SIZE, 0);
	if ( r <  0 ) {
	    if ( ERRNO == EAGAIN ) {
		my_xlog(OOPS_LOG_SEVERE, "check_validity(): Hmm, again select say ready, but read fails.\n");
		continue;
	    }
	    my_xlog(OOPS_LOG_SEVERE, "check_validity(): select error: %m\n");
	    goto validate_err;
	}
	if ( r == 0 ) {
	    my_xlog(OOPS_LOG_SEVERE, "check_validity(): Server closed connection too early.\n");
	    goto validate_err;
	}
	if ( !new_obj->container ) {
		struct	buff *new;
		new = alloc_buff(CHUNK_SIZE);
		if ( !new ) {
		    my_xlog(OOPS_LOG_SEVERE, "check_validity(): Can't create container.\n");
		    goto validate_err;
		}
		new_obj->container = new;
	}
	if ( !(answer_stat.state & GOT_HDR) ) {
	    new_obj->size += r;
	    if ( attach_data(answer, r, new_obj->container) ) {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "check_validity(): attach_data() error.\n");
		goto validate_err;
	    }
	    if ( check_server_headers(&answer_stat, new_obj, new_obj->container, rq) ) {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "check_validity(): check_server_headers().\n");
		goto validate_err;
	    }
	    if ( answer_stat.state & GOT_HDR ) {
		new_obj->times		= answer_stat.times;
		new_obj->status_code 	= answer_stat.status_code;
		new_obj->flags	       |= answer_stat.flags;

		new_obj->flags|= answer_stat.flags;
		new_obj->times = answer_stat.times;

		if ( new_obj->status_code == STATUS_NOT_MODIFIED ) {
		    SET(new_obj->flags, FLAG_DEAD);
		    leave_obj(new_obj);
		    new_obj = NULL;
		    goto validate_done;
		}

		if ( (new_obj->status_code == STATUS_GATEWAY_TIMEOUT) 
		        || (new_obj->status_code == STATUS_FORBIDEN) )
		    goto validate_done;

		if ( !new_obj->times.date ) new_obj->times.date = time(NULL);
		check_new_object_expiration(rq, new_obj);
		if ( new_obj->status_code == STATUS_OK ) {
		    process_vary_headers(obj, rq);
		    goto validate_done;
		}
		/* else send answer to user */
		obj->flags |= FLAG_DEAD;
		goto validate_err;
	    } /* GOT_HDR */
	} /* !GOT_HDR */
    
    }

validate_err:
    if ( answer ) xfree(answer);
    if ( fake_header ) xfree(fake_header);
    if ( to_server_request ) free_container(to_server_request);
    if ( new_obj ) {
	SET(new_obj->flags, FLAG_DEAD);
	leave_obj(new_obj);
    }
    return(NULL);

validate_done:
    if ( answer ) xfree(answer);
    if ( fake_header ) xfree(fake_header);
    if ( to_server_request ) free_container(to_server_request);
    return(new_obj);
}

void
fill_mem_obj(int so, struct request *rq, char * headers, struct mem_obj *obj, int sso, int type, struct sockaddr_in *psa)
{
int			server_so = -1, r;
char			*answer = NULL;
struct	url		*url = &rq->url;
char			*meth, *source;
struct	server_answ	answ_state;
int			maxfd;
unsigned int		received = 0, sended = 0, header_size, resident_size;
struct	buff		*send_hot_buff=NULL;
int			send_hot_pos=0;
struct	timeval		tv, start_tv, stop_tv;
int			delta_tv;
int			have_code = 0, pass = 0, rc;
struct	buff		*to_server_request = NULL;
char			origin[MAXHOSTNAMELEN];
struct	sockaddr_in	peer_sa;
int			source_type, downgrade_flags=0;
int			body_size, sf = 0, rest_in_chunk = 0, on_chunk_border=TRUE;
char			*table = NULL;
struct	av		*header = NULL;
int			convert_charset = FALSE;
time_t			last_read = global_sec_timer;
hash_entry_t            *he = NULL;
ERRBUF ;

    if ( rq->meth == METH_GET ) meth="GET";
    else if ( rq->meth == METH_PUT ) meth="PUT";
    else if ( rq->meth == METH_POST ) meth="POST";
    else if ( rq->meth == METH_HEAD ) meth="HEAD";
    else {
	DECR_WRITERS(obj);
	return;
    }
    IF_STRDUP(rq->tag, "TCP_MISS");
    sf |= (rq->flags & (RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW));
    gettimeofday(&start_tv, NULL);
    if ( sso > 0) {
	source_type = type;
	server_so = sso;
	if ( psa ) peer_sa = *psa;
	    else
		   bzero(&peer_sa, sizeof(peer_sa));
	goto server_connect_done;
    }
    if ( !TEST(rq->flags, RQ_NO_ICP) && !parent_port && peers && (icp_so != -1)
	 && (rq->meth == METH_GET)
	 && !destination_is_local(rq->url.host) ) {
	struct icp_queue_elem *new_qe;
	struct timeval tv = start_tv;
	bzero((void*)&peer_sa, sizeof(peer_sa));
	my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Sending icp requests.\n");
	new_qe = (struct icp_queue_elem*)xmalloc(sizeof(*new_qe),"fill_mem_obj(): new_qe");
	if ( !new_qe ) goto icp_failed;
	bzero(new_qe, sizeof(*new_qe));
	pthread_cond_init(&new_qe->icpr_cond, NULL);
	pthread_mutex_init(&new_qe->icpr_mutex, NULL);
	new_qe->waitors = 1;
	new_qe->rq_n    = rand_r(&rnd_ctx);
	pthread_mutex_lock(&new_qe->icpr_mutex);
	if ( !send_icp_requests(rq, new_qe, &he) ) {
	    /* was placed in queue	*/
	    struct timespec  ts;
	    tv.tv_sec  += icp_timeout/1000000;
	    tv.tv_usec += icp_timeout%1000000;
	    if ( tv.tv_usec > 1000000 ) {
		tv.tv_sec++;
		tv.tv_usec-=1000000;
	    }
	    ts.tv_sec  = tv.tv_sec;
	    ts.tv_nsec = tv.tv_usec*1000;
	    /* wait for answers */
	    if ( !new_qe->status && pthread_cond_timedwait(&new_qe->icpr_cond,&new_qe->icpr_mutex,&ts) ) {
		/* failed */
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): icp timed out.\n");
	    } else {
		/* success */
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): icp success.\n");
	    }
	    new_qe->rq_n = 0;
	    pthread_mutex_unlock(&new_qe->icpr_mutex);
            if ( he ) {
                rc = delete_hash_entry(icp_requests_hash, he, NULL);
                if ( rc != 0 ) /* this must never happen */
                    abort();
            }
	    if ( new_qe->status ) {
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Fetch from neighbour.\n");
		peer_sa = new_qe->peer_sa;
		source_type = new_qe->type;
		server_so = peer_connect(so, &new_qe->peer_sa, rq);
		icp_request_destroy(new_qe);
		xfree(new_qe);
		goto server_connect_done;
	    } else {
		if ( no_direct_connections ) {
		   /* what now ? */
		}
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Direct.\n");
	    }
	    icp_request_destroy(new_qe);
	    xfree(new_qe);
	    goto icp_failed;
	} else {
	    pthread_mutex_unlock(&new_qe->icpr_mutex);
	    pthread_mutex_destroy(&new_qe->icpr_mutex);
	    pthread_cond_destroy(&new_qe->icpr_cond);
	    xfree(new_qe);
	}

 icp_failed:;
    } /* all icp things */

retry:
    if (parent_port && !destination_is_local(rq->url.host) && !TEST(rq->flags, RQ_GO_DIRECT)) {
        source_type = PEER_PARENT;
        server_so = parent_connect(so, parent_host, parent_port, rq);
    } else {
        source_type = SOURCE_DIRECT;
        SET(rq->flags, RQ_SERVED_DIRECT);
        server_so = srv_connect(so, url, rq);
    }

    /*
     * if it happens that we used parent_connect and parrent_connect determine 
     * that actually it will be direct request, then set correct source_type
     */
    if ( TEST(rq->flags, RQ_GO_DIRECT) ) source_type = SOURCE_DIRECT;

 server_connect_done:

    switch(source_type) {
    struct peer *peer;

    case SOURCE_DIRECT:
	source="DIRECT";
	strncpy(origin, obj->url.host, sizeof(origin)-1);
	origin[sizeof(origin)-1] = 0;
	break;
    case PEER_PARENT:
	source="PARENT";
	if ( parent_port ) {
	    RDLOCK_CONFIG ;
	    strncpy(origin, parent_host, sizeof(origin)-1);
	    origin[sizeof(origin)-1] = 0;
	    IF_FREE(rq->peer_auth); rq->peer_auth = NULL;
	    if ( parent_auth ) rq->peer_auth = strdup(parent_auth);
	    UNLOCK_CONFIG ;
	} else {
	    RDLOCK_CONFIG ;
	    peer = peer_by_http_addr(&peer_sa);
	    if ( peer ) {
		IF_FREE(rq->peer_auth); rq->peer_auth = NULL;
		if ( peer->my_auth ) rq->peer_auth = strdup(peer->my_auth);
		if ( peer->name )
		    strncpy(origin, peer->name, sizeof(origin)-1);
		else
		    strncpy(origin, "unknown_peer", sizeof(origin)-1);
		origin[sizeof(origin)-1] = 0;
	    }
	    UNLOCK_CONFIG ;
	}
	break;
    case PEER_SIBLING:
	source="SIBLING";
	RDLOCK_CONFIG ;
	peer = peer_by_http_addr(&peer_sa);
	if ( peer ) {
	    IF_FREE(rq->peer_auth);  rq->peer_auth = NULL;
	    if ( peer->my_auth ) rq->peer_auth = strdup(peer->my_auth);
	    if ( peer->name )
		strncpy(origin, peer->name, sizeof(origin)-1);
	    else
		strncpy(origin, "unknown_peer", sizeof(origin)-1);
	    origin[sizeof(origin)-1] = 0;
	}
	UNLOCK_CONFIG ;
	break;
    default:
	source="UNKNOWN";
	strncpy(origin, "UNKNOWN", sizeof(origin));
	break;
    }

    if ( server_so == -1 ) {
	obj->flags |= FLAG_DEAD;
	change_state(obj, OBJ_READY);
	goto error;
    }

    set_socket_options(server_so);

    /* push whole request to server */
    to_server_request = alloc_buff(4*CHUNK_SIZE);
    if ( !to_server_request ) {
	change_state(obj, OBJ_READY);
	obj->flags |= FLAG_DEAD;
	goto error;
    }

    answer = (source_type==SOURCE_DIRECT)?build_direct_request(meth, &rq->url, NULL, rq, 0):
    			 build_parent_request(meth, &rq->url, NULL, rq, 0);

    if ( !answer ) {
	change_state(obj, OBJ_READY);
	obj->flags |= FLAG_DEAD;
	goto error;
    }
    if ( attach_data(answer, strlen(answer), to_server_request) ) {
	free_container(to_server_request);
	change_state(obj, OBJ_READY);
	obj->flags |= FLAG_DEAD;
	goto error;
    }
    xfree(answer); answer = NULL;

    if ( rq->cs_to_server_table
		&& rq->cs_to_server_table->list
		&& rq->cs_to_server_table->list->string)
	r = writet_cv_cs(server_so, to_server_request->data,
				    to_server_request->used, READ_ANSW_TIMEOUT,
				rq->cs_to_server_table->list->string, TRUE);
      else
	r = writet(server_so, to_server_request->data, to_server_request->used, READ_ANSW_TIMEOUT);
    free_container(to_server_request); to_server_request = NULL;

    if ( r < 0 ) {
	say_bad_request(so, "Can't send", STRERROR_R(ERRNO, ERRBUFS),
			ERR_TRANSFER, rq);
	change_state(obj, OBJ_READY);
	obj->flags |= FLAG_DEAD;
	goto error;
    }

    obj->request_time = time(NULL);
    answer = xmalloc(ANSW_SIZE+1, "fill_mem_obj(): 2");
    if ( !answer ) {
	obj->flags |= FLAG_DEAD;
	change_state(obj, OBJ_READY);
	goto error;
    }

    bzero(&answ_state, sizeof(answ_state));

    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): fcntl(): %m\n");
    if ( fcntl(server_so, F_SETFL, fcntl(server_so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): fcntl(): %m\n");
    forever() {
	struct pollarg pollarg[2];

	pollarg[0].fd = server_so;
	pollarg[0].request = FD_POLL_RD;
	pollarg[1].fd = 0;
	pollarg[1].request = 0;
	if ( server_so > so ) maxfd = server_so;
	    else	      maxfd = so;
	if ( (obj->state == OBJ_INPROGR) && (received > sended) && (so != -1) ) {
	    if ( (++pass)%2 && TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) ) {
		r = traffic_load(rq);
		tv.tv_sec = 0;tv.tv_usec = 0;
		if ( r < 75 ) /* low load */
		    goto ignore_gr_bw_overload;
		else if ( r < 95 ) /* start to slow down */
		    tv.tv_usec = 250000;
		else if ( r < 100 )
		    tv.tv_usec = 500000;
		else
		    tv.tv_sec = MIN(2, r/100);
                if ( fetch_with_client_speed && (obj->refs==1) && !on_chunk_border ) {
                    my_msleep(tv.tv_sec*1000+tv.tv_usec/1000);
                    continue;
                }
		r = poll_descriptors(1, &pollarg[0],
			tv.tv_sec*1000+tv.tv_usec/1000);
		if ( r < 0 ) {
		    obj->flags |= FLAG_DEAD;
		    change_state(obj, OBJ_READY);
		    goto error;
		}
		if ( r== 0 ) continue;
		goto read_s;
	    }

	ignore_gr_bw_overload:
	    if ( rq->sess_bw ) {
		r = sess_traffic_load(rq);
		tv.tv_sec = 0;tv.tv_usec = 0;
		if ( r < 75 ) /* low load */
		    goto ignore_bw_overload;
		else if ( r < 95 ) /* start to slow down */
		    tv.tv_usec = 250000;
		else if ( r < 100 )
		    tv.tv_usec = 500000;
		else
		    tv.tv_sec = MIN(3,r/100);
                if ( fetch_with_client_speed && (obj->refs==1) && !on_chunk_border ) {
                    my_msleep(tv.tv_sec*1000+tv.tv_usec/1000);
                    continue;
                }
		r = poll_descriptors(1, &pollarg[0],
			tv.tv_sec*1000+tv.tv_usec/1000);
		if ( r < 0 ) {
		    obj->flags |= FLAG_DEAD;
		    change_state(obj, OBJ_READY);
		    goto error;
		}
		if ( r== 0 ) continue;
		goto read_s;
	    }
	ignore_bw_overload:
	    pollarg[1].fd = so;
	    pollarg[1].request = FD_POLL_WR;
	}

        if ( fetch_with_client_speed && (obj->refs == 1) ) {
            /* If single user read this doc - then load with user speed */
            if ( (received > sended) && (pollarg[1].fd > 0) 
                 && !on_chunk_border) {
                /* want only send */
                pollarg[0].fd = -1;
                pollarg[0].request = pollarg[0].answer = 0;
                last_read = global_sec_timer;
            }
        }

	tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
	r = poll_descriptors(2, &pollarg[0], READ_ANSW_TIMEOUT*1000);
	if ( r < 0 ) {
	    my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): select: %m\n");
	    change_state(obj, OBJ_READY);
	    obj->flags |= FLAG_DEAD;
	    goto error;
	}
	if ( r == 0 ) {
	    my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): select: timed out.\n");
	    change_state(obj, OBJ_READY);
	    obj->flags |= FLAG_DEAD;
	    goto error;
	}
	if ( (so != -1) && (IS_WRITEABLE(&pollarg[1])||IS_HUPED(&pollarg[1])) ) {
	    unsigned int	ssended = sended;
	    r--;
	    if ( IS_HUPED(&pollarg[1]) ) {
		so = -1;
		goto client_so_closed;
	    }
	    if ( (rc = send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, &rest_in_chunk, sf, obj, table, rq)) != 0 )
		so = -1;
	    if ( rest_in_chunk == -1 ) { /* was last chunk */
		obj->state = OBJ_READY;
		change_state_notify(obj);
		my_xlog(OOPS_LOG_DBG, "fill_mem_obj(): was last chunk.\n");
		goto done;
	    }
            on_chunk_border = FALSE;
	    rq->doc_sent += sended-ssended;
	    if ( !rc && (sended == ssended) ) {
		if ( IS_READABLE(&pollarg[0]) || IS_HUPED(&pollarg[0]) )
		    goto read_s;
		if ( global_sec_timer - last_read > READ_ANSW_TIMEOUT ) {
		    /* server died on the fly 	*/
		    my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): server died on the fly.\n");
		    change_state(obj, OBJ_READY);
		    obj->flags |= FLAG_DEAD;
		    goto error;
		}
		/* we stay on chunk border, server data not ready - sleep */
                on_chunk_border = TRUE;
		my_msleep(5);
		/* and wait again */
		continue;
	    }

	    if ( !rc && (sended == ssended) && TEST(downgrade_flags, UNCHUNK_ANSWER) ) {
		if ( IS_READABLE(&pollarg[0]) || IS_HUPED(&pollarg[0]) )
		    goto read_s;
		/* we stay on chunk border, server data not ready - sleep */
		my_sleep(1);
		/* and wait again */
		continue;
	    }

	    if ( !rc && TEST(sf, RQ_CONVERT_FROM_CHUNKED) && !rest_in_chunk ) {
		if ( IS_READABLE(&pollarg[0]) || IS_HUPED(&pollarg[0]) )
		    goto read_s;
		/* we stay on chunk border, server data not ready - sleep */
		my_sleep(1);
		/* and wait again */
		continue;
	    }
	    if ( rq->flags & (RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW)) update_transfer_rate(rq, sended-ssended);
	    if ( rq->sess_bw) update_sess_transfer_rate(rq, sended-ssended);
	    if ((obj->flags & ANSW_KEEP_ALIVE) && obj->content_length) {
		/* e.g. www.securityfocus.com answer with Connection: Keep-Alive
		 * even if requested "Close"
		 */
		if ( obj->container )
			header_size = obj->container->used;
		  else
			header_size = 0;
		if ( sended-header_size >= obj->content_length) {
		    obj->state = OBJ_READY;
		    change_state_notify(obj);
		    goto done;
		}
	    }
	}

    client_so_closed:
	if ( so == -1 ) {
	    lock_obj(obj);
	    if ( (obj->refs <= 1) && !FORCE_COMPLETION(obj) ) /* we are only who refers to this obj */ {
		obj->state =  OBJ_READY;
		obj->flags |= FLAG_DEAD;
	    }
	    unlock_obj(obj);
	    if ( obj->state == OBJ_READY ) {
		change_state_notify(obj);
		goto error;	/* no one heard */
	    }
	}

    read_s:
	if ( !IS_READABLE(&pollarg[0]) ) {
	    if ( IS_HUPED(&pollarg[0]) ) {
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "fill_mem_obj(): Connection closed by server.\n");
		obj->state =  OBJ_READY;
		obj->flags |= FLAG_DEAD;
		change_state_notify(obj);
		goto error;
	    }
	    if ( r ) {
		/* this is solaris 2.6 select bug(?) workaround */
		my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): select bug(?).\n");
		obj->state =  OBJ_READY;
		obj->flags |= FLAG_DEAD;
		change_state_notify(obj);
		goto error;
	    }
	    continue;
	}
	r = recv(server_so, answer, ANSW_SIZE, 0);
	if ( r < 0  ) {
	    /* Error reading from server */
	    if ( ERRNO == EAGAIN ) {
		my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): Hmm, server_so was ready, but read failed.\n");
		continue;
	    }
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): read failed: %m\n");
	    change_state(obj, OBJ_READY);
	    obj->flags |= FLAG_DEAD;
	    goto error;
	}
	if ( r == 0 ) {
	    /* Server closed connection */
	    if ( obj->content_length && obj->container ) {
		if ( received < obj->container->used+obj->content_length )
		    /* we received as much as we suppose */
		    obj->flags |= FLAG_DEAD;
	    }
	    change_state(obj, OBJ_READY);
	    if ( !send_hot_buff && (sended == 0) )
		send_hot_buff = obj->container;
	    while( (so != -1) && send_hot_buff &&
	           (received > sended) && (rest_in_chunk != -1)) {
		unsigned int	ssended;
		struct pollarg pollarg;
		int	rc;

		if ( (++pass)%2 && TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) )
		    SLOWDOWN ;
		if ( pass%2 && rq->sess_bw )
		    SLOWDOWN_SESS ;
		tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
		pollarg.fd = so;
		pollarg.request = FD_POLL_WR;
		r = poll_descriptors(1, &pollarg, READ_ANSW_TIMEOUT*1000);
		if ( r <= 0 ) break;
		if ( IS_HUPED(&pollarg) )
		    goto done;
		ssended = sended;
		if ( (rc = send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, &rest_in_chunk, sf, obj, table, rq)) != 0 )
		    so = -1;
		if ( ssended == sended )
			goto done;
		rq->doc_sent += sended-ssended;
		if ( rq->flags & (RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW)) update_transfer_rate(rq, sended-ssended);
		if ( rq->sess_bw ) update_sess_transfer_rate(rq, sended-ssended);
	    }
	    goto done;
	}
	/* there is something to read */
	last_read = global_sec_timer;
	if ( !obj->container ) {
	    struct	buff *new;
	    new = alloc_buff(CHUNK_SIZE);
	    if ( !new ) {
		my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): Can't create container.\n");
		change_state(obj, OBJ_READY);
		obj->flags |= FLAG_DEAD;
		goto error;
	    }
	    obj->container = new;
	}
	if ( !(answ_state.state & GOT_HDR) ) {
	    received += r;
	    obj->size += r;
	    if ( attach_data(answer, r, obj->container) ) {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "fill_mem_obj(): attach_data().\n");
		obj->flags |= FLAG_DEAD;
		change_state(obj, OBJ_READY);
		goto error;
	    }
	    if ( (obj->state < OBJ_INPROGR)
	         && check_server_headers(&answ_state, obj, obj->container, rq) ) {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "fill_mem_obj(): check_server_headers().\n");
		/*
		    If we can't parse server header - let client do it.
		    This can be old server, which can send only content without
		    headers.
		*/
		send_hot_buff = obj->container;
		send_hot_pos  = 0;
		sended = 0;
		obj->flags |= FLAG_DEAD;
		change_state(obj, OBJ_INPROGR);
		if ( obj->container ) {
		    writet(so, obj->container->data, obj->container->used,
		        READ_ANSW_TIMEOUT);
		    pump_data(obj, rq, so, server_so);
		    received = rq->received;
		    goto done;
                }
		continue;
	    }
	    if ( answ_state.state & GOT_HDR ) {
		struct	buff	*hdrs_to_send;

		send_hot_buff = obj->container;
		send_hot_pos  = 0;
		sended = 0;
		obj->flags|= answ_state.flags;
		obj->times = answ_state.times;
		if ( !obj->times.date ) obj->times.date = global_sec_timer;
		check_new_object_expiration(rq, obj);
		obj->status_code = answ_state.status_code;
                if ( (source_type!=SOURCE_DIRECT) && !TEST(rq->flags, RQ_GO_DIRECT)
                     && ((obj->status_code == STATUS_GATEWAY_TIMEOUT)
                            || (obj->status_code == STATUS_FORBIDEN)) ) {
                    /* retry direct */
                    SET(rq->flags, RQ_GO_DIRECT);
                    if ( server_so ) close(server_so); server_so = -1;
                    received = 0;
                    sended = 0;
                    if ( obj->container) free_container(obj->container);
                    obj->container = NULL;
                    IF_FREE(answer); answer = NULL;
                    if ( to_server_request ) free_container(to_server_request);
                    to_server_request = NULL;
                    if ( obj->headers ) free_avlist(obj->headers);
                    obj->headers = NULL;
                    goto retry;
                }
		if ( obj->status_code != STATUS_OK )
			obj->flags |= FLAG_DEAD;
		if (!(obj->flags & ANSW_NO_STORE) )
			obj->flags &= ~ANSW_NO_CACHE;

		if ( obj->headers && rq->av_pairs ) {
		    /* save Vary: headers */
		    char	*p, *t, *tok_ptr, *value;
		    char	*vary = attr_value(obj->headers, "Vary:" ), *temp_vary;

		    if ( vary && (temp_vary = strdup(vary)) ) {
			my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Vary = `%s'.\n", vary);
			/* 1. skip spaces */
			p = temp_vary;
			while ( *p && IS_SPACE(*p) ) p++;
			t = p;
			/* split on ',' */
			while ( (p = (char*)strtok_r(t, " ,", &tok_ptr)) != 0 ) {
			    int	a_len;
			    char	a_buf[128], pref[] ="X-oops-internal-rq-", *fav;

			    t = NULL;
			    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Chk hdr: %s\n", p);
			    value = attr_value(rq->av_pairs, p);
			    if ( value ) {
				/* format and attach */
				a_len = sizeof(pref)+strlen(p)+1;
				if ( a_len <= sizeof(a_buf) ) {
				    fav = a_buf;
				} else {
				    fav = xmalloc(a_len, "fill_mem_obj(): fav");
				}
				if ( fav ) {
				    sprintf(fav, "%s%s:", pref, p);
				    insert_header(fav, value, obj);
				    if ( fav != a_buf ) xfree(fav);
				    received = obj->size;
				} /* if fav */
			    } /* value */
			} /* while tokens */
			IF_FREE(temp_vary);
			my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Vary = `%s'.\n", vary);
		    }
		}
		change_state(obj, OBJ_INPROGR);

		header_size = obj->container->used;
		if ( obj->container->next )
			body_size = obj->container->next->used;
		    else
			body_size = 0;
		downgrade_flags = downgrade(rq, obj);
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Downgrade flags: %x\n", downgrade_flags);
		hdrs_to_send = alloc_buff(512); /* most headers fit this (?) */
		if ( !hdrs_to_send ) goto error;
		header = obj->headers;
		if ( !header ) goto error ;
		/* first must be "HTTP/1.x 200 ..." */
		if ( TEST(downgrade_flags, DOWNGRADE_ANSWER) ) {
		    attach_av_pair_to_buff("HTTP/1.0", header->val, hdrs_to_send);
		    header = header->next;
		}
		while(header) {
	    	my_xlog(OOPS_LOG_DBG, "fill_mem_obj(): Sending ready header `%s' -> `%s'.\n", header->attr, header->val);
	    	if ( 
			/* we must not send Tr.-Enc. and Cont.-Len. if we convert
			 * from chunked							*/

			   !(TEST(downgrade_flags, UNCHUNK_ANSWER) && is_attr(header, "Transfer-Encoding"))
			   && !(TEST(downgrade_flags, UNCHUNK_ANSWER) && is_attr(header, "Content-Length"))
			   && !is_attr(header, "Proxy-Authenticate:")
			   && !is_oops_internal_header(header) ) {
			if ( rq->src_charset[0] && rq->cs_to_client_table && is_attr(header, "Content-Type") && header->val ) {
			    char *s = NULL, *d = NULL, ct_buf[64];

			    /* we change charset only in 'text/ *' */
			    if ( strlen(header->val) >= sizeof(ct_buf) ) {
				s = strdup(header->val);
			    } else {
				strncpy(ct_buf, header->val, sizeof(ct_buf)-1);
				ct_buf[sizeof(ct_buf)-1] = 0;
				s = ct_buf;
			    }
			    if ( s
			    	&& (d = check_rewrite_charset(s, rq, header, &convert_charset)) ) {
				my_xlog(OOPS_LOG_DBG, "fill_mem_obj(): Rewriten header = `%s'.\n", d);
				attach_data(d, strlen(d), hdrs_to_send);
				attach_data("\r\n", 2, hdrs_to_send);
				xfree(d);
				if ( s && (s != ct_buf) )
				    xfree(s);
				table = rq->cs_to_client_table->list->string;
				convert_charset = TRUE;
				header = header->next;
				continue;
			    }
			    if ( s && (s != ct_buf) )
				xfree(s);
			} /* Content-Type: ... */
			attach_av_pair_to_buff(header->attr, header->val, hdrs_to_send);
		    }
		    header = header->next;
		}
		attach_av_pair_to_buff("", "", hdrs_to_send);
		if ( convert_charset && rq->cs_to_client_table
				     && rq->cs_to_client_table->list
				     && rq->cs_to_client_table->list->string)
		    writet_cv_cs(so, hdrs_to_send->data, hdrs_to_send->used, READ_ANSW_TIMEOUT,
			rq->cs_to_client_table->list->string, TRUE);
		  else
		    writet(so, hdrs_to_send->data, hdrs_to_send->used, READ_ANSW_TIMEOUT);
		free_container(hdrs_to_send);

		pre_body(so, obj, rq, NULL);

		sended = obj->container->used;
		send_hot_buff = obj->container;
		send_hot_pos  = obj->container->used;
		rq->doc_size = obj->content_length;

		if ( TEST(downgrade_flags, UNCHUNK_ANSWER) ) {
		    sf |= RQ_CONVERT_FROM_CHUNKED;
		}
		if ( TEST(obj->flags, ANSW_SHORT_CONTAINER) ) {
		    if ( obj->container->next ) {
			if ( convert_charset && rq->cs_to_client_table
				     && rq->cs_to_client_table->list
				     && rq->cs_to_client_table->list->string)
			    writet_cv_cs(so, obj->container->next->data,
					 obj->container->next->used,
					 READ_ANSW_TIMEOUT,
					 rq->cs_to_client_table->list->string,
					 TRUE);
			else
			    writet(so, obj->container->next->data, 
				   obj->container->next->used,
				   READ_ANSW_TIMEOUT);
			rq->doc_sent += obj->container->next->used;
		    }
		    pump_data(obj, rq, so, server_so);
		    received = rq->received;
		    goto done1;
		}
	    }
	} else {
	    body_size += r;
	    /* store data in hot_buff */
	    if ( store_in_chain(answer, r, obj) ) {
		my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): Can't store.\n");
		obj->flags |= FLAG_DEAD;
		change_state(obj, OBJ_READY);
		goto error;
	    }
	    received += r;
	    obj->size += r;
	    rq->doc_received += r;
	    change_state_notify(obj);
	}
    }

error:
    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): load error.\n");
    if ( server_so != -1 ) CLOSE(server_so);
    IF_FREE(answer);
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( obj->status_code ) have_code = obj->status_code;
	else		    have_code = 555;

    IF_STRDUP(rq->tag, "TCP_ERROR");
    IF_STRDUP(rq->source, origin);
    IF_STRDUP(rq->hierarchy, source);
    rq->code = have_code;
    rq->received = received;
    log_access(delta_tv, rq, obj);
    DECR_WRITERS(obj);
    return;

done:
    obj->response_time = global_sec_timer;
    resident_size = calculate_resident_size(obj);
    obj->x_content_length = obj->x_content_length_sum;
    if ( !obj->content_length && !content_chunked(obj) )
	/* we don't know size */
    obj->flags |= FLAG_DEAD;
    /* if object too large remove it right now */
    if ( resident_size > maxresident ) {
	my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Obj is too large - remove it.\n");
	obj->flags |= FLAG_DEAD;
    } else {
	obj->resident_size = resident_size;
	increase_hash_size(obj->hash_back, obj->resident_size);
    }

done1:
    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "fill_mem_obj(): Loaded successfully: received: %d\n", received);
    if ( server_so != -1 ) CLOSE(server_so);
    IF_FREE(answer);
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( obj->status_code ) have_code = obj->status_code;
	else		    have_code = 555;
    IF_STRDUP(rq->hierarchy, source);
    IF_STRDUP(rq->source, origin);
    rq->code = have_code;
    rq->received = received;
    log_access(delta_tv, rq, obj);
    DECR_WRITERS(obj);
    return;
}

static int
continue_load(struct request *rq, int so, int server_so, struct mem_obj *obj)
{
int			maxfd, pass = 0, sf = 0;
unsigned int		received = 0, received0 = 0, sended = 0, ssended;
struct	buff		*send_hot_buff;
int			send_hot_pos;
struct	timeval		tv;
int			r, rc, rest_in_chunk = 0, downgrade_flags = 0;
char			*answer=NULL;
struct	av		*header;
char			*table = NULL;
struct	buff		*hdrs_to_send = NULL;
int			convert_charset = FALSE, on_chunk_border = TRUE;
time_t			last_read = global_sec_timer;

    received = received0 = obj->size;
    send_hot_buff = obj->container;
    send_hot_pos = 0;

    downgrade_flags = downgrade(rq, obj);
    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "continue_load(): Downgrade flags: %x\n", downgrade_flags);
    header = obj->headers;
    if ( !header ) goto error ;
    hdrs_to_send = alloc_buff(512);
    if ( !hdrs_to_send ) goto done;
    if ( TEST(downgrade_flags, DOWNGRADE_ANSWER) ) {
	attach_av_pair_to_buff("HTTP/1.0", header->val, hdrs_to_send);
	header = header->next;
    }
    while(header) {
	if ( 
	    /* we must not send Tr.-Enc. and Cont.-Len. if we convert
	     * from chunked						*/

		!(TEST(downgrade_flags, UNCHUNK_ANSWER) && is_attr(header, "Transfer-Encoding")) &&
		!(TEST(downgrade_flags, UNCHUNK_ANSWER) && is_attr(header, "Content-Length")) ){

	    if ( rq->src_charset[0] && rq->cs_to_client_table && is_attr(header, "Content-Type") && header->val ) {
		char *s = NULL, *d = NULL, ct_buf[64];

		/* we change charset only in 'text/ *' */
		if ( strlen(header->val) >= sizeof(ct_buf) ) {
		    s = strdup(header->val);
		} else {
		    strncpy(ct_buf, header->val, sizeof(ct_buf)-1);
		    ct_buf[sizeof(ct_buf)-1] = 0;
		    s = ct_buf;
		}
		if ( s
			&& (d = check_rewrite_charset(s, rq, header, &convert_charset)) ) {
		    my_xlog(OOPS_LOG_DBG, "continue_load(): Rewriten header = `%s'.\n", d);
		    attach_data(d, strlen(d), hdrs_to_send);
		    attach_data("\r\n", 2, hdrs_to_send);
		    xfree(d);
		    if ( s && (s != ct_buf) )
			xfree(s);
		    table = rq->cs_to_client_table->list->string;
		    convert_charset = TRUE;
		    header = header->next;
		    continue;
		}
		if ( s && (s != ct_buf) )
		    xfree(s);
	    } /* Content-Type: ... */
	    attach_av_pair_to_buff(header->attr, header->val, hdrs_to_send);
	}
	header = header->next;
    }
    attach_av_pair_to_buff("", "", hdrs_to_send);
    if ( convert_charset && rq->cs_to_client_table
		     && rq->cs_to_client_table->list
		     && rq->cs_to_client_table->list->string)
	writet_cv_cs(so, hdrs_to_send->data, hdrs_to_send->used, READ_ANSW_TIMEOUT,
			rq->cs_to_client_table->list->string, TRUE);
	  else
	writet(so, hdrs_to_send->data, hdrs_to_send->used, READ_ANSW_TIMEOUT);
		free_container(hdrs_to_send);

    rq->doc_size = obj->content_length;
    sended = obj->container->used;
    send_hot_buff = obj->container;
    send_hot_pos  = obj->container->used;

    if ( TEST(downgrade_flags, UNCHUNK_ANSWER) ) {
	sf |= RQ_CONVERT_FROM_CHUNKED;
    }
    if (TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW)) sf |= RQ_HAS_BANDWIDTH;
    if ( !(obj->flags & ANSW_NO_STORE) )
	obj->flags &= ~ANSW_NO_CACHE;

    if ( TEST(obj->flags, ANSW_SHORT_CONTAINER) ) {
	my_xlog(OOPS_LOG_SEVERE, "continue_load(): pumping.\n");
        if ( obj->container->next ) {
            if ( convert_charset && rq->cs_to_client_table
		        && rq->cs_to_client_table->list
                        && rq->cs_to_client_table->list->string)
                writet_cv_cs(so, obj->container->next->data,
                        obj->container->next->used,
                        READ_ANSW_TIMEOUT,
                        rq->cs_to_client_table->list->string, TRUE);
        else
            writet(so, obj->container->next->data, 
	        obj->container->next->used, READ_ANSW_TIMEOUT);
            rq->doc_sent += obj->container->next->used;
        }
        pump_data(obj, rq, so, server_so);
        received = rq->received;
        goto error;
    }

    answer = xmalloc(ANSW_SIZE+1, "continue_load(): 1");
    if ( ! answer )  {
	my_xlog(OOPS_LOG_SEVERE, "continue_load(): no mem.\n");
	change_state(obj, OBJ_READY);
	obj->flags |= FLAG_DEAD;
	goto error;
    }
    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_xlog(OOPS_LOG_SEVERE, "continue_load(): fcntl(): %m\n");
    forever() {
	struct	pollarg pollarg[2];

	pollarg[0].fd = server_so; pollarg[0].request = FD_POLL_RD;
	pollarg[1].fd = 0; pollarg[1].request = 0;
	if ( server_so > so ) maxfd = server_so;
	    else	      maxfd = so;
	if ( (obj->state == OBJ_INPROGR) && (received > sended) && (so != -1) ) {
	    if ( (++pass)%2 && TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) ) {
		r = traffic_load(rq);
		tv.tv_sec = 0;tv.tv_usec = 0;
		if ( r < 75 ) /* low load */
		    goto ignore_gr_bw_overload;
		else if ( r < 95 ) /* start to slow down */
		    tv.tv_usec = 250000;
		else if ( r < 100 )
		    tv.tv_usec = 500000;
		else
		    tv.tv_sec = MIN(2, r/100);
                if ( fetch_with_client_speed && (obj->refs==1) && !on_chunk_border ) {
                    my_msleep(tv.tv_sec*1000+tv.tv_usec/1000);
                    continue;
                }
		r = poll_descriptors(1, &pollarg[0], tv.tv_sec*1000+tv.tv_usec/1000);
		if ( r < 0 ) {
		    obj->flags |= FLAG_DEAD;
		    change_state(obj, OBJ_READY);
		    goto error;
		}
		if ( r== 0 ) continue;
		goto read_s;
	    }

	ignore_gr_bw_overload:
	    if ( rq->sess_bw ) {
		r = sess_traffic_load(rq);
		tv.tv_sec = 0;tv.tv_usec = 0;
		if ( r < 75 ) /* low load */
		    goto ignore_bw_overload;
		else if ( r < 95 ) /* start to slow down */
		    tv.tv_usec = 250000;
		else if ( r < 100 )
		    tv.tv_usec = 500000;
		else
		    tv.tv_sec = MIN(3,r/100);
                if ( fetch_with_client_speed && (obj->refs==1) && !on_chunk_border ) {
                    my_msleep(tv.tv_sec*1000+tv.tv_usec/1000);
                    continue;
                }
		r = poll_descriptors(1, &pollarg[0], tv.tv_sec*1000+tv.tv_usec/1000);
		if ( r < 0 ) {
		    obj->flags |= FLAG_DEAD;
		    change_state(obj, OBJ_READY);
		    goto error;
		}
		if ( r== 0 ) continue;
		goto read_s;
	    }

	ignore_bw_overload:
	    pollarg[1].fd = so;
	    pollarg[1].request = FD_POLL_WR;
	}

        if ( fetch_with_client_speed && (obj->refs == 1) ) {
            /* If single user read this doc - then load with user speed */
            if ( (received > sended) && (pollarg[1].fd > 0) 
                 && !on_chunk_border) {
                /* want only send */
                pollarg[0].fd = -1;
                pollarg[0].request = pollarg[0].answer = 0;
                last_read = global_sec_timer;
            }
        }

	tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
	r = poll_descriptors(2, &pollarg[0], READ_ANSW_TIMEOUT*1000);
	if ( r < 0 ) {
	    my_xlog(OOPS_LOG_SEVERE, "continue_load(): select: %m\n");
	    obj->flags |= FLAG_DEAD;
	    change_state(obj, OBJ_READY);
	    goto error;
	}
	if ( r == 0 ) {
	    my_xlog(OOPS_LOG_SEVERE, "continue_load(): select: timed out.\n");
	    obj->flags |= FLAG_DEAD;
	    change_state(obj, OBJ_READY);
	    goto error;
	}
	if ( (so != -1) && (IS_WRITEABLE(&pollarg[1])||IS_HUPED(&pollarg[1])) ) {
	    r--;
	    if ( IS_HUPED(&pollarg[1]) ) {
		so = -1;
		goto are_we_alone;
	    }
	    ssended = sended;
	    if ( (rc = send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, &rest_in_chunk, sf, obj, table, rq)) != 0 ) {
		so = -1;
		goto are_we_alone;
	    }
            on_chunk_border = FALSE;
	    if ( !rc && (sended == ssended) && TEST(downgrade_flags, UNCHUNK_ANSWER) ) {
		if ( IS_READABLE(&pollarg[0]) || IS_HUPED(&pollarg[0]) )
		    goto read_s;
		if ( global_sec_timer - last_read > READ_ANSW_TIMEOUT ) {
		    /* server died on the fly 	*/
		    my_xlog(OOPS_LOG_SEVERE, "fill_mem_obj(): server died on the fly.\n");
		    change_state(obj, OBJ_READY);
		    obj->flags |= FLAG_DEAD;
		    goto error;
		}
		/* we stay on chunk border, server data not ready - sleep */
                on_chunk_border = TRUE;
		my_msleep(5);
		/* and wait again */
		continue;
	    }
	    if ( rest_in_chunk == -1 ) {
		my_xlog(OOPS_LOG_DBG, "continue_load(): We sent last chunk, rec-sent = %d\n", received-sended);
		change_state(obj, OBJ_READY);
		goto done;
	    }
	    rq->doc_sent += sended-ssended;
	    if ( rq->flags & (RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW))
		update_transfer_rate(rq, sended-ssended);
	    if ( rq->sess_bw) update_sess_transfer_rate(rq, sended-ssended);
	    if ( TEST(obj->flags, ANSW_KEEP_ALIVE) && obj->content_length) {
		if ( sended >= obj->container->used + obj->content_length ) {
		    change_state(obj, OBJ_READY);
		    goto done;
		}
	    }
	}

   are_we_alone:
	if ( so == -1 ) {
	    lock_obj(obj);
	    if ( (obj->refs <= 1) && !FORCE_COMPLETION(obj) ) /* we are only who refers to this obj */ {
		my_xlog(OOPS_LOG_DBG, "continue_load(): We alone: %d\n", obj->refs);
		obj->state = OBJ_READY;
		obj->flags |= FLAG_DEAD;
	    }
	    unlock_obj(obj);
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "continue_load(): Send failed: %m\n");
	    if ( obj->state == OBJ_READY ) {
		change_state_notify(obj);
		goto error;	/* no one heard */
	    }
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "continue_load(): Continue to load - we are not alone.\n");
	}

    read_s:;
	if ( !IS_READABLE(&pollarg[0]) ) {
	    if ( r ) {
		/* this is solaris 2.6 select bug(?) workaround */
		my_xlog(OOPS_LOG_SEVERE, "continue_load(): select bug(?).\n");
		obj->state =  OBJ_READY;
		obj->flags |= FLAG_DEAD;
		change_state_notify(obj);
		goto error;
	    }
	    continue;
	}
	r = recv(server_so, answer, ANSW_SIZE, 0);
	if ( r < 0  ) {
	    if ( ERRNO == EAGAIN )  {
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "continue_load(): Hmm in continue load.\n");
		continue;
	    }
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "continue_load(): Read failed: %m\n");
	    obj->flags |= FLAG_DEAD;
	    change_state(obj, OBJ_READY);
	    goto error;
	}
	if ( r == 0 ) {
	    if ( obj->content_length && obj->container ) {
		if ( received < obj->container->used+obj->content_length )
		    /* we received not as much as we suppose */
		    obj->flags |= FLAG_DEAD;
	    }
	    change_state(obj, OBJ_READY);
	    while( (so != -1) && (received > sended) ) {
		struct pollarg  pollarg;
		int		rc;

		if ( (++pass)%2 && TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) )
		    SLOWDOWN ;
		if ( rq->sess_bw && pass%2 )
		    SLOWDOWN_SESS ;
		pollarg.fd = so;
		pollarg.request = FD_POLL_WR;
		tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
		r = poll_descriptors(1, &pollarg, READ_ANSW_TIMEOUT*1000);
		if ( r <= 0 ) break;
		if ( IS_HUPED(&pollarg) )
		    goto done;
		ssended = sended;
		if ( (rc = send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, &rest_in_chunk, sf, obj, table, rq)) != 0 )
		    so = -1;
		if ( ssended == sended )
		    goto done;
		rq->doc_sent += sended-ssended;
		if ( TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW)) update_transfer_rate(rq, sended-ssended);
		if ( rq->sess_bw ) update_sess_transfer_rate(rq, sended-ssended);
	    }
	    goto done;
	}
	last_read = global_sec_timer;
	/* store data in hot_buff */
	if ( store_in_chain(answer, r, obj) ) {
	    my_xlog(OOPS_LOG_SEVERE, "continue_load(): Can't store.\n");
	    obj->flags |= FLAG_DEAD;
	    change_state(obj, OBJ_READY);
	    goto error;
	}
	rq->doc_received += r;
	received += r;
	obj->size += r;
	obj->state = OBJ_INPROGR;
	change_state_notify(obj);
    }

done:
    obj->resident_size = calculate_resident_size(obj);
    obj->x_content_length = obj->x_content_length_sum;
	/*received + sizeof(*obj)+(obj->container?obj->container->used:0);*/
    increase_hash_size(obj->hash_back, obj->resident_size);

error:
    IF_FREE(answer);
    return(0);
}

int
send_data_from_buff(int so, struct buff **hot, int *pos, unsigned int *sended, int *rest_in_chunk, int flags, struct mem_obj *obj, char *table)
{
int		r, to_send;
struct	buff	*b = *hot;
struct	timeval tv;
struct	pollarg	pollarg;

    if ( !*hot )
	return(0);

do_it:
    to_send = b->used - *pos;
    if ( !to_send ) {
	if ( !b->next ) return(0);
	*hot = b->next;
	b = b->next;
	*pos = 0;
	goto do_it;
    }
    if ( to_send < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_data_from_buff(): What the fuck? to_send = %d\n", to_send);
	return(-1);
    }
    tv.tv_sec = READ_ANSW_TIMEOUT; tv.tv_usec = 0 ;

    pollarg.fd = so;
    pollarg.request = FD_POLL_WR;
    r = poll_descriptors(1, &pollarg, READ_ANSW_TIMEOUT*1000);
    if ( r <= 0 )
	return(r);
    r = write(so, b->data+*pos, to_send);
    if ( (r < 0) && (ERRNO == EWOULDBLOCK) ) return(0);
    if ( r < 0 )
	return(r);
    *pos += r; *sended += r;
    goto do_it;
}

/* send data from memory buffs
   so 		 - socket to client
   hot		 - current buff
   pos		 - offset in buff data
   sended	 - address of 'sended' variable (updated in accordance with progress)
   rest_in_chunk - for chunked content
   flags	 - flags (chunked, BW-control, ...)
   obj		 - object (we need it to set x-content_len for chunked content)
   recode	 - recode table if we do charset conversion on the fly
*/
int
send_data_from_buff_no_wait(int so, struct buff **hot, int *pos, unsigned int *sended, int *rest_in_chunk, int flags, struct mem_obj *obj, char *table, struct request *rq)
{
int		r, to_send, cz_here, faked_sent, chunk_size, ss, sp;
struct	buff	*b = *hot;
char		*cb, *ce, *cd;
char		ch_sz[32];	/* buffer to collect chunk size	*/
u_char		recode_buff[2048];
char		*source;

    /* first, send decoded content if present */
send_decoded:
    if ( rq && rq->decoding_buff && (rq->decoded_beg < rq->decoded_end ) ) {
	r = send(so, rq->decoded_beg, rq->decoded_end-rq->decoded_beg, 0);
	if ( r == -1 ) {
	    if ( errno == EWOULDBLOCK ) return(0);
	    return(-1);
	}
	rq->decoded_beg += r;
	if ( rq->decoded_end < rq->decoded_beg )
	    return(0);
	/* if all decoding_buff sent, fill it again */
    }

    if ( !*hot )
	return(-1);
    if ( TEST(flags, RQ_CONVERT_FROM_CHUNKED) && !rest_in_chunk ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_data_from_buff_no_wait(): Check yourself: sending chunked in send_data_from_buff.\n");
	return(-1);
    }
    if ( TEST(flags, RQ_CONVERT_FROM_CHUNKED ) )
	goto send_chunked;

do_it:
#if	defined(HAVE_ZLIB)
    if ( rq && obj
	    && TEST(rq->flags, RQ_CONVERT_FROM_GZIPPED)
	    && !rq->inflate_started
	    && rq->decoding_buff ) {
	/* we must process gzip header here */
	unsigned char	gzheader[512];
	struct	buff	*gzb = obj->container, *tgzb = obj->container;
	int		gzhlen = 0, left_to_copy, rc;
	unsigned char	gzflags;

	if ( gzb && gzb->next ) gzb = gzb->next;
	while ( gzb && (gzhlen <= sizeof(gzheader) ) ) {
	    left_to_copy = MIN(gzb->curr_size, sizeof(gzheader) - gzhlen);
	    memcpy(gzheader+gzhlen, gzb->data, left_to_copy);
	    gzhlen += left_to_copy;
	    gzb = gzb->next;
	}
	if ( gzhlen >= 10 ) {
	    /* we can analyze it, as 10 is minimal gzip header len */
	    if ( !(gzheader[0] == 0x1f && gzheader[1] == 0x8b)
	    	|| gzheader[2] != Z_DEFLATED ) {
		/* wrong magic or method*/
		CLR(rq->flags, RQ_CONVERT_FROM_GZIPPED);
		goto do_it;
	    }
	    gzflags = gzheader[3];
	    if ( gzflags ) {
		/* I don't want to have deal with			*/
		/* must be fixed if any server will send any flags	*/
		/* with gzipped content					*/
		CLR(rq->flags, RQ_CONVERT_FROM_GZIPPED);
		goto do_it;
	    }
	} else
	    return(0); /* we need more data */
	/* gzheader contain begin of the gzipped content, we can start	*/
	rq->strm.next_in = gzheader + 10 ;
	rq->strm.avail_in = gzhlen  - 10 ;
	rq->strm.next_out = (unsigned char*)rq->decoding_buff;
	rq->strm.avail_out = DECODING_BUF_SZ;
	rq->strm.total_out = 0;
	rc = inflate(rq->strmp, Z_SYNC_FLUSH);
	if ( rc == Z_OK || rc ==  Z_STREAM_END) {
	    int		moved_far, count; /* how much inflated	*/

	    if ( rc == Z_OK )
		moved_far = rq->strm.total_in + 10;
	      else
		moved_far = rq->strm.avail_in + 10;
	    /* find hotbuf and offset again		*/
	    if ( tgzb && tgzb->next )
		    tgzb = tgzb->next;
		else {
		    /* something wrong						*/
		    my_xlog(OOPS_LOG_SEVERE, "Something vrong in ungzip\n");
		    CLR(rq->flags, RQ_CONVERT_FROM_GZIPPED);
		    goto do_it;
		}
	    count = 0;
	    while ( tgzb ) {
		if ( count + tgzb->curr_size > moved_far )
		    break;
		tgzb = tgzb->next;
	    }
	    if ( !tgzb ) {
		/* something wrong						*/
		my_xlog(OOPS_LOG_SEVERE, "Something vrong in ungzip\n");
		CLR(rq->flags, RQ_CONVERT_FROM_GZIPPED);
		goto do_it;
	    }
	    *sended += moved_far ;
	    *pos = moved_far - count ;
	    *hot = tgzb;
	    if (rq->decoding_buff) {
		rq->decoded_beg=rq->decoding_buff;
		rq->decoded_end=rq->decoding_buff + rq->strm.total_out;
		if ( table ) {
		    u_char	*s, *d;
		    int		i;
	
		    s = (u_char*)rq->decoding_buff;
		    d = (u_char*)rq->decoding_buff;
		    i = 0;
		    while ( i < rq->strmp->total_out ) {
			if ( *s >= 128 )
			    *d = table[*s-128];
			else
			    *d = *s;
			s++;d++;
			i++;
		    }
		}
	    }
	    rq->inflate_started = TRUE;
	    goto send_decoded;
	} else {
	    /* something wrong						*/
	    CLR(rq->flags, RQ_CONVERT_FROM_GZIPPED);
	    goto do_it;
	}
    }
#endif
    to_send = b->used - *pos;
    if ( !to_send ) {
	if ( !b->next ) return(0);
	*hot = b->next;
	b = b->next;
	*pos = 0;
	goto do_it;
    }
    if ( to_send < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_data_from_buff_no_wait(): What the fuck1? to_send = %d\n", to_send);
	return(-1);
    }
    /** send no more than 512 bytes at once if we control bandwith
     *	 because bandwidth control will be difficult if we will send by large
     *	 chunks
     *  send no more than 2048 bytes anyway. large writes apply high load on system
     **/
    if ( TEST(flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) )
		to_send = MIN(to_send, 512);
	else	to_send = MIN(to_send, 2048);

#if	defined(HAVE_ZLIB)
    if ( rq && TEST(rq->flags, RQ_CONVERT_FROM_GZIPPED) && rq->strmp ) {
	int	rc;
	source = (b->data+*pos);
	rq->strmp->next_in  = (unsigned char*)source;
	rq->strmp->avail_in = to_send;
	rq->strmp->total_in = 0;
	rq->strmp->next_out = (unsigned char*)rq->decoding_buff;
	rq->strmp->avail_out= DECODING_BUF_SZ;
	rq->strmp->total_out = 0;
	rc = inflate(rq->strmp, Z_SYNC_FLUSH);
	if ( (rc != Z_OK) && (rc != Z_STREAM_END) ) {
	    my_xlog(OOPS_LOG_SEVERE, "inflate: %d\n", rc);
	    return(-1);
	}
	if ( rc == Z_OK ) {
	    *pos += rq->strmp->total_in;
	    *sended += rq->strmp->total_in;
	} else { /* rc == Z_STREAM_END */
	    *pos += rq->strmp->avail_in;
	    *sended += rq->strmp->avail_in;
	}
	rq->decoded_beg = rq->decoding_buff;
	rq->decoded_end = rq->decoding_buff + rq->strmp->total_out;
	if ( table ) {
	    u_char	*s, *d;
	    int		i;

	    s = (u_char*)rq->decoding_buff;
	    d = (u_char*)rq->decoding_buff;
	    i = 0;
	    while ( i < rq->strmp->total_out ) {
		if ( *s >= 128 )
		    *d = table[*s-128];
		else
		    *d = *s;
		s++;d++;
		i++;
	    }
	}
	goto send_decoded;
    }
#endif

    if ( table ) {
	u_char *s, *d;
	int  i = to_send;

	s = (u_char*)(b->data+*pos);
	d = recode_buff;
	i = 0;
	while ( i < to_send ) {
	    if ( *s >= 128 )
		*d = table[*s-128];
	      else
		*d = *s;
	    s++;d++;
	    i++;
	}
	source = (char*)recode_buff;
    } else
	source = b->data+*pos;

    r = send(so, source, to_send, 0);
    if ( (r < 0) && (ERRNO == EWOULDBLOCK) ) {
	my_xlog(OOPS_LOG_HTTP,"send_data_from_buff_no_wait(): EWOULDBLOCK.\n");
	return(0);
    }
    if ( TEST(flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) && (r>0) ) {
	*pos += r; *sended += r;
	return(0);
    }
    if ( r < 0 )
	return(r);
    *pos += r; *sended += r;
    if ( r < to_send ) {/* it can't accept more data now */
	return(0);
    }
    goto do_it;

send_chunked:
    faked_sent = 0;

do_it_chunked:
    if ( !*rest_in_chunk ) {
	/* we stay on a new chunk,extract current chunk size */
	cb = b->data + *pos;
	ce = b->data + b->used;

    find_chunk_size_again:
	cz_here = FALSE;
	cd = ch_sz;
	*cd = 0;
	ss = *sended;
	sp = *pos;
	while ( ( cb < ce ) && IS_SPACE(*cb) ) {
	    cb++;
	    (*sended)++;
	    (*pos)++;
	}
	if ( ce == cb ) {
	    if ( b->next ) {
		b = b->next;
		*hot = b;
		*pos = 0;
		*sended += faked_sent;
		goto send_chunked;
	    } else {
		*sended = sp;
		*pos = sp;
		return(0);
	    }
	}

    number2:
	while( cb < ce ) {
	    *cd++ = *cb++;
	    *cd = 0;
	    faked_sent++;
	    if ( cd - ch_sz >= sizeof(ch_sz) - 1 ) {
		return(-1);
	    }
	    if ( strstr(ch_sz, "\r\n") ) {
		cz_here=TRUE;
		break;
	    }
	}
	if ( (ce == cb) && !cz_here ) {
	    if ( b->next ) {
		b = b->next;
		*pos = 0;
		cb = b->data + *pos;
		ce = b->data + b->used;
		goto number2;
	    } else {
		return(0);
	    }
	}
	if ( cz_here ) {
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_data_from_buff_no_wait(): Got chunk size: %s\n", ch_sz);
	    *hot = b;
	    *pos = cb - b->data;
	    *sended += faked_sent;
	    cd = ch_sz;
	    r = sscanf(ch_sz, "%x", &chunk_size);
	    if ( r != 1) {
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_data_from_buff_no_wait(): No cs in %s\n", ch_sz);
		return(-1);
	    }
	    if ( !chunk_size ) {
		/* it is last */
		*rest_in_chunk = -1;
		return(0);
	    }
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "send_data_from_buff_no_wait(): Got chunk size: %d\n", chunk_size);
	    *rest_in_chunk = chunk_size;
	    if ( obj ) {
		obj->x_content_length_sum += chunk_size;
	    }
	    goto do_it_chunked;
	} else {
	    if ( !b->next ) {
		return(0);
	    }
	    b = b->next;
	    cb = b->data;
	    ce = b->data + b->used;
	    goto find_chunk_size_again;
	}
    } else {
	/* send from current position till the minimum(chunksize,b->used) */
	to_send = MIN(b->used - *pos, (uint32_t)*rest_in_chunk);
	if ( !to_send ) {
	    /* this canbe only end of buffer */
	    if ( !b->next ) return(0);
	    *hot = b->next;
	    b = b->next;
	    *pos = 0;
	    goto send_chunked;
 	}
   	if ( to_send < 0 ) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_data_from_buff_no_wait(): What the fuck2? to_send = %d\n", to_send);
	    return(-1);
	}
	if ( TEST(flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) ) to_send = MIN(to_send, 512);
	   else				     to_send = MIN(to_send, 2048);
	if ( table ) {
	    u_char *s, *d;
	    int  i = to_send;

	    s = (u_char*)(b->data+*pos);
	    d = recode_buff;
	    i = 0;
	    while ( i < to_send ) {
		if ( *s >= 128 )
		    *d = table[*s-128];
		  else
		    *d = *s;
		s++; d++;
		i++;
	    }
	    source = (char*)recode_buff;
	} else
	    source = b->data+*pos;
	r = send(so, source, to_send, 0);
	if ( r == 0 )
	    return(-1);
	if ( (r < 0) && (ERRNO == EWOULDBLOCK) ) {
	    return(0);
	}
	if ( r < 0 ) {
	    return(r);
	}
	*pos += r; *sended += r; *rest_in_chunk -= r;
	if ( TEST(flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) && *rest_in_chunk )
	    /* we will return (to recalculate traffic load) only when we
	       have something to send
	    */
	    return(0);
	if ( r < to_send ) /* it can't accept more data now */
	    return(0);
	goto send_chunked;
    }
}

void
lock_obj(struct mem_obj *obj)
{
    pthread_mutex_lock(&obj->lock);
}

void
unlock_obj(struct mem_obj *obj)
{
    pthread_mutex_unlock(&obj->lock);
}

inline
static void
lock_obj_state(struct mem_obj *obj)
{
    pthread_mutex_lock(&obj->state_lock);
}

inline
static void
unlock_obj_state(struct mem_obj *obj)
{
    pthread_mutex_unlock(&obj->state_lock);
}

inline
static void
lock_decision(struct mem_obj *obj)
{
    pthread_mutex_lock(&obj->decision_lock);
}

inline
static void
unlock_decision(struct mem_obj *obj)
{
    pthread_mutex_unlock(&obj->decision_lock);
}

void
change_state(struct mem_obj *obj, int new_state)
{
    lock_obj_state(obj);
    obj->state = new_state;
    unlock_obj_state(obj);
    change_state_notify(obj);
}

inline
static void
change_state_notify(struct mem_obj *obj)
{
    pthread_cond_broadcast(&obj->state_cond);
}


void
free_chain(struct buff *buff)
{
struct	buff	*next;
    while(buff) {
	next = buff->next;
	xfree(buff->data);
	xfree(buff);
	buff = next;
    }
}

/* send answer like

HTTP/1.0 XXX message\r\n\r\n

*/
void
send_error(int so, int code, char * message)
{
char	*hdr = NULL;

    hdr = xmalloc(
    	8 /* HTTP/1.0 */ +
    	1 /* */ +
    	3 /* XXX */ +
    	4 /* \r\n\r\n */ +
	1 /* */ +
	strlen(message) /* message */ +
    	1 /* \0 */, "For error message");
    if ( !hdr ) {
	return;
    }
    sprintf(hdr, "HTTP/1.0 %3d %s\r\n\r\n",
	code,
	message);
    writet(so, hdr, strlen(hdr), READ_ANSW_TIMEOUT);
    xfree(hdr);
    return;
}

inline
static int
is_attr(struct av *av, char *attr)
{
    if ( !av || !av->attr || !attr ) return(FALSE);
    return(!strncasecmp(av->attr, attr, strlen(attr)));
}

inline
static int
is_oops_internal_header(struct av *av)
{
    if ( !av || !av->attr ) return(FALSE);
    if ( !strncmp(av->attr, "X-oops-internal", 15) )
	return(TRUE);
    return(FALSE);
}

int
send_av_pair(int so, char* attr, char* val)
{
char	*buf;
int	r;

    if ( !attr ) return(-1);
    if ( *attr == 0 ) {
	return(writet(so, CRLF, 2, READ_ANSW_TIMEOUT));
    }
    if ( !val ) return(-1);
    buf = xmalloc(strlen(attr) + 1 + strlen(val) + 3, "send_av_pair(): 1");
    if ( !buf ) {
	my_xlog(OOPS_LOG_SEVERE, "send_av_pair(): No mem at send_av_pair.\n");
	return(-1);
    }
    sprintf(buf, "%s %s\r\n", attr, val);
    r = writet(so, buf, strlen(buf), READ_ANSW_TIMEOUT);
    xfree(buf);
    return(r);
}

char*
format_av_pair(char* attr, char* val)
{
char	*buf;

    if ( *attr )
	buf = xmalloc(strlen(attr) + 1 + strlen(val) + 3, "format_av_pair(): 1");
    else
	buf = xmalloc(3, "format_av_pair(): 2");
    if ( !buf ) {
	my_xlog(OOPS_LOG_SEVERE, "format_av_pair(): No mem at send_av_pair.\n");
	return(NULL);
    }
    if ( *attr )
	sprintf(buf, "%s %s\r\n", attr, val);
    else
	sprintf(buf, "\r\n");
    return(buf);
}

time_t
current_obj_age(struct mem_obj *obj)
{
time_t	apparent_age, corrected_received_age, response_delay;
time_t	corrected_initial_age, resident_time, current_age;

    apparent_age = 		MAX(0, obj->response_time - obj->times.date);
    corrected_received_age =	MAX(apparent_age, obj->times.age);
    response_delay =		obj->response_time - obj->request_time;
    corrected_initial_age =	corrected_received_age + response_delay;
    resident_time = 		time(NULL) - obj->response_time;
    current_age = 		corrected_initial_age + resident_time;

    my_xlog(OOPS_LOG_DBG, "current_obj_age(): obj->times.date: %d\n", (utime_t)(obj->times.date));
    my_xlog(OOPS_LOG_DBG, "current_obj_age(): obj->response_time: %d\n", (utime_t)(obj->response_time));
    my_xlog(OOPS_LOG_DBG, "current_obj_age(): apparent_age: %d\n", apparent_age);
    my_xlog(OOPS_LOG_DBG, "current_obj_age(): corrected_received_age: %d\n", corrected_received_age);
    my_xlog(OOPS_LOG_DBG, "current_obj_age(): responce_delay: %d\n", response_delay);
    my_xlog(OOPS_LOG_DBG, "current_obj_age(): corrected_initial_age: %d\n", corrected_initial_age);
    my_xlog(OOPS_LOG_DBG, "current_obj_age(): resident_time: %d\n", resident_time);
    my_xlog(OOPS_LOG_DBG, "current_obj_age(): current_age: %d\n", current_age);

    return(current_age);
}
/* return positive freshness time if got from headers
   or negative if heuristic
*/
time_t
obj_freshness_lifetime(struct mem_obj *obj)
{
    if ( obj->flags & ANSW_HAS_MAX_AGE ) return(obj->times.max_age);
    if ( obj->flags & ANSW_HAS_EXPIRES ) return(MAX(0,obj->times.expires -
						obj->times.date));
    return(-24*3600);
}

int
destination_is_local(char* host)
{
struct	sockaddr_in	dst_sa;

    if ( !host ) return(FALSE);
    if ( is_local_dom(host) )
	    return( TRUE );
    if ( local_networks_sorted && local_networks_sorted_counter ) {
	bzero(&dst_sa, sizeof(dst_sa));
	if ( str_to_sa(host, (struct sockaddr*)&dst_sa) )
	    return(FALSE);
	return( is_local_net(&dst_sa) );
    }
    return(FALSE);
}

static int
srv_connect(int client_so, struct url *url, struct request *rq)
{
int 			server_so = -1, r;
struct	sockaddr_in 	server_sa;
ERRBUF ;

    int			flags = 0;

    r = check_redir_connect(&server_so, rq, &flags);
    if ( server_so != -1 )
	return(server_so);
    if ( r == MOD_CODE_ERR ) {
	say_bad_request(client_so, "Can't connect to host.", STRERROR_R(ERRNO, ERRBUFS),
			ERR_TRANSFER, rq);
	return(-1);
    }
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(client_so, "Can't create socket", STRERROR_R(ERRNO, ERRBUFS),
			ERR_INTERNAL, rq);
	return(-1);
    }
    bind_server_so(server_so, rq);
    if ( str_to_sa(url->host, (struct sockaddr*)&server_sa) ) {
	say_bad_request(client_so, "Can't translate name to address", url->host, ERR_DNS_ERR, rq);
	CLOSE(server_so);
	return(-1);
    }
    server_sa.sin_port = htons(url->port);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	say_bad_request(client_so, "Can't connect to host.", STRERROR_R(ERRNO, ERRBUFS),
			ERR_TRANSFER, rq);
	CLOSE(server_so);
	return(-1);
    }
    return(server_so);
}

static int
srv_connect_silent(int client_so, struct url *url, struct request *rq)
{
int 			server_so = -1, r;
struct	sockaddr_in 	server_sa;
    int			flags = 0;

    r = check_redir_connect(&server_so, rq, &flags);
    if ( server_so != -1 )
	return(server_so);
    if ( r == MOD_CODE_ERR ) {
	return(-1);
    }

    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	return(-1);
    }
    bind_server_so(server_so, rq);
    if ( str_to_sa(url->host, (struct sockaddr*)&server_sa) ) {
	CLOSE(server_so);
	return(-1);
    }
    server_sa.sin_port = htons(url->port);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	CLOSE(server_so);
	return(-1);
    }
    return(server_so);
}

int
parent_connect(int client_so, char *parent_host, int parent_port, struct request *rq)
{
int 			server_so = -1, r;
struct	sockaddr_in 	server_sa;
struct	sockaddr_in	dst_sa;
ERRBUF ;

    if ( !TEST(rq->flags, RQ_GO_DIRECT) ) {
        bzero(&dst_sa, sizeof(dst_sa));
	if ( local_networks_sorted && local_networks_sorted_counter ) {
	    if (str_to_sa(rq->url.host, (struct sockaddr*)&dst_sa) )
		bzero(&dst_sa, sizeof(dst_sa));
	}
	if ( is_local_dom(rq->url.host) || is_local_net(&dst_sa) ) {
	    SET(rq->flags, RQ_GO_DIRECT);
	    return( srv_connect(client_so, &rq->url, rq) );
	}
    } else  /* RQ_GO_DIRECT is already ON */
	    return( srv_connect(client_so, &rq->url, rq) );
    if ( str_to_sa(parent_host, (struct sockaddr*)&server_sa) ) {
	say_bad_request(client_so, "Can't translate parent name to address", parent_host, ERR_DNS_ERR,rq);
	return(-1);
    }
    server_sa.sin_port = htons((unsigned short)parent_port);
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(client_so, "Can't create socket", STRERROR_R(ERRNO, ERRBUFS),
			ERR_INTERNAL, rq);
	return(-1);
    }
    bind_server_so(server_so, rq);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	say_bad_request(client_so, "Can't connect to parent", STRERROR_R(ERRNO, ERRBUFS),
			ERR_TRANSFER, rq);
	CLOSE(server_so);
	return(-1);
    }
    return(server_so);
}
int
parent_connect_silent(int client_so, char *parent_host, int parent_port, struct request *rq)
{
int 			server_so = -1, r;
struct	sockaddr_in 	server_sa;
struct	sockaddr_in	dst_sa;

    if ( !TEST(rq->flags, RQ_GO_DIRECT) ) {
        bzero(&dst_sa, sizeof(dst_sa));
	if ( local_networks_sorted && local_networks_sorted_counter ) {
	    if (str_to_sa(rq->url.host, (struct sockaddr*)&dst_sa) )
		bzero(&dst_sa, sizeof(dst_sa));
	}
	if ( is_local_dom(rq->url.host) || is_local_net(&dst_sa) ) {
	    SET(rq->flags, RQ_GO_DIRECT);
	    return( srv_connect(client_so, &rq->url, rq) );
	}
    } else  /* RQ_GO_DIRECT is already ON */
	    return( srv_connect(client_so, &rq->url, rq) );
    if ( str_to_sa(parent_host, (struct sockaddr*)&server_sa) ) {
	return(-1);
    }
    server_sa.sin_port = htons((unsigned short)parent_port);
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	return(-1);
    }
    bind_server_so(server_so, rq);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	CLOSE(server_so);
	return(-1);
    }
    return(server_so);
}

int
peer_connect(int client_so, struct sockaddr_in *peer_sa, struct request *rq)
{
int 			server_so = -1, r;
struct	peer		*peer;
ERRBUF ;

    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "peer_connect(): Connecting to peer...\n");
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(client_so, "Can't create socket", STRERROR_R(ERRNO, ERRBUFS),
			ERR_INTERNAL, rq);
	return(-1);
    }
    bind_server_so(server_so, rq);
    r = connect(server_so, (struct sockaddr*)peer_sa, sizeof(*peer_sa));
    if ( r == -1 ) {
	say_bad_request(client_so, "Can't connect to parent", STRERROR_R(ERRNO, ERRBUFS),
			ERR_TRANSFER, rq);
	CLOSE(server_so);
	RDLOCK_CONFIG ;
	peer = peer_by_http_addr(peer_sa);
	if ( peer ) {
	    if ( peer->state == PEER_UP ) {
		peer->down_time = global_sec_timer;
		peer->state = PEER_DOWN;
		/* we will avoid connect to this server some time */
	    }
	}
	UNLOCK_CONFIG ;
	return(-1);
    }
    return(server_so);
}

int
peer_connect_silent(int client_so, struct sockaddr_in *peer_sa, struct request *rq)
{
int 			server_so = -1, r;
struct	peer		*peer;

    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "peer_connect_silent(): Connecting to peer...\n");
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	return(-1);
    }
    bind_server_so(server_so, rq);
    r = connect(server_so, (struct sockaddr*)peer_sa, sizeof(*peer_sa));
    if ( r == -1 ) {
	CLOSE(server_so);
	RDLOCK_CONFIG ;
	peer = peer_by_http_addr(peer_sa);
	if ( peer ) {
	    if ( peer->state == PEER_UP ) {
		peer->down_time = global_sec_timer;
		peer->state = PEER_DOWN;
		/* we will avoid connect to this server some time */
	    }
	}
	UNLOCK_CONFIG ;
	return(-1);
    }
    return(server_so);
}

static char*
build_direct_request(char *meth, struct url *url, char *headers, struct request *rq, int flags)
{
int	rlen, authorization_done = FALSE;
char	*answer = NULL, *fav=NULL, *httpv, *host=NULL;
struct	buff 	*tmpbuff;
struct	av	*av;
int	via_inserted = FALSE;

    if ( !TEST(flags, DONT_CHANGE_HTTPVER) && force_http11) {
	httpv = "HTTP/1.1";
	if ( !TEST(rq->flags, RQ_HAS_HOST) ) host = rq->url.host;
    } else {
	httpv = url->httpv;
	if ( !TEST(rq->flags, RQ_HAS_HOST) ) host = rq->url.host;
    }
    tmpbuff = alloc_buff(CHUNK_SIZE);
    if ( !tmpbuff ) return(NULL);
    rlen = strlen(meth) + 1/*sp*/ + strlen(url->path) + 1/*sp*/ +
           strlen(httpv) + 2/* \r\n */;
    answer = xmalloc(ROUND(rlen+1,CHUNK_SIZE), "build_direct_request(): 1"); /* here answer is actually *request* buffer */
    if ( !answer )
	goto fail;
    sprintf(answer, "%s %s %s\r\n", meth, url->path, httpv);
    if ( attach_data(answer, strlen(answer), tmpbuff) )
	goto fail;
    if ( headers ) { /* attach what was requested */
	if ( attach_data(headers, strlen(headers), tmpbuff) )
	    goto fail;
    }
    if ( host && (fav=format_av_pair("Host:", host)) ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
	xfree(fav);fav = NULL;
    }
    av = rq->av_pairs;
    while ( av ) {
	if ( is_attr(av, "Proxy-Connection:") )
	    goto do_not_insert;
	if ( is_attr(av, "Proxy-Authorization:") ) /* hop-by-hop */
	    goto do_not_insert;
	if ( is_attr(av, "Connection:") )
	    goto do_not_insert;
	if ( is_attr(av, "Via:") && insert_via && !via_inserted ) {
	    /* attach my Via: */
	    if ( (fav = format_av_pair(av->attr, av->val)) != 0 ) {
		char	*buf;

		buf = strchr(fav, '\r');
		if ( buf ) *buf = 0;
		if ( !buf ) {
		    buf = strchr(fav, '\n');
		    if ( buf ) *buf = 0;
		}
		if ( loop_detected(fav) ) {
		    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "build_direct_request(): Loop detected: %s\n", fav);
		    goto fail;
		}
		/* ", host_name:port (oops ver)" */
		buf = malloc(strlen(fav)+2+strlen(host_name)+7+10+strlen(version)+2+1);
		if ( !buf ) goto fail;
		sprintf(buf,"%s, %s:%d (Oops %s)\r\n", fav, host_name, http_port, version);
		if ( attach_data(buf, strlen(buf), tmpbuff) ) {
		    xfree(buf);
		    goto fail;
		}
		via_inserted = TRUE;
		xfree(buf);
		xfree(fav); fav = NULL;
	    }
	    goto do_not_insert;
	}
	if ( (fav=format_av_pair(av->attr, av->val)) != 0 ) {
	    if ( is_attr(av, "Authorization:") ) {
		/* we prefer "in-header"-supplied Authorization: */
		authorization_done = TRUE;
	    }
	    if ( attach_data(fav, strlen(fav), tmpbuff) )
		goto fail;
	    xfree(fav);fav = NULL;
	}
  do_not_insert:
	av = av->next;
    }
    if ( rq->url.login && !authorization_done ) {
	char	log_pass[1024], *b64e;
	strncpy(log_pass, rq->url.login, sizeof(log_pass)-1);
	strncat(log_pass, ":", sizeof(log_pass) - strlen(log_pass) - 1);
	log_pass[sizeof(log_pass)-1] = 0;
	if ( rq->url.password )
	    strncat(log_pass, rq->url.password, sizeof(log_pass) - strlen(log_pass) - 1);
	b64e = base64_encode(log_pass);
	if ( b64e ) {
	    strncpy(log_pass, "Basic ", sizeof(log_pass)-1);
	    strncat(log_pass, b64e, sizeof(log_pass) - strlen(log_pass) -1 );
	    log_pass[sizeof(log_pass)-1] = 0;
	    xfree(b64e);
	    fav = format_av_pair("Authorization:", log_pass);
	    if ( fav ) {
		if ( attach_data(fav, strlen(fav), tmpbuff) )
		    goto fail;
		xfree(fav); fav = NULL;
	    }
	}
    }
    if ( (fav = format_av_pair("Connection:", "close")) != 0 ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
	xfree(fav);fav = NULL;
    }
    if ( insert_x_forwarded_for ) {
	char	*ip_addr = my_inet_ntoa(&rq->client_sa);
	int	r;

	if ( ip_addr ) {
	    r = attach_data("X-Forwarded-For: ", sizeof("X-Forwarded-For: ")-1,
			tmpbuff);
	    if ( !r )
	        r = attach_data(ip_addr, strlen(ip_addr), tmpbuff);
	    if ( !r )
		r = attach_data("\r\n", 2, tmpbuff);
	    xfree(ip_addr);
	}
    }
    if ( insert_via && !via_inserted ) {
	char *buf;

	buf = malloc(4+1+strlen(host_name)+7+10+strlen(version)+2+1);
	if ( !buf ) goto fail;
	sprintf(buf,"Via: %s:%d (Oops %s)\r\n", host_name, http_port, version);
	if ( attach_data(buf, strlen(buf), tmpbuff) ) {
	    xfree(buf);
	    goto fail;
	}
	xfree(buf);
	xfree(fav);fav = NULL;
    }
    /* CRLF  */
    if ( attach_data("\r\n", 2, tmpbuff) )
	goto fail;
    if ( attach_data("", 1, tmpbuff) )
	goto fail;
    IF_FREE(answer);
    answer = tmpbuff->data;
    tmpbuff->data = NULL;
    free_chain(tmpbuff);
    return answer;
fail:
    IF_FREE(fav);
    if (tmpbuff) free_chain(tmpbuff);
    IF_FREE(answer);
    return NULL;
}

static char*
build_parent_request(char *meth, struct url *url, char *headers, struct request *rq, int flags)
{
int	rlen, via_inserted = FALSE;
char	*answer, *httpv, *fav=NULL, *host=NULL;
struct	buff 	*tmpbuff;
struct	av	*av;
char		*lp = NULL;
int		lp_length = 0;

    if ( TEST(rq->flags, RQ_GO_DIRECT) ) {
	return(build_direct_request(meth, url, headers, rq, flags));
    }

    if ( !TEST(flags, DONT_CHANGE_HTTPVER) && force_http11) {
	httpv = "HTTP/1.1";
	if ( !TEST(rq->flags, RQ_HAS_HOST) ) host = rq->url.host;
    } else {
	httpv = url->httpv;
	if ( !TEST(rq->flags, RQ_HAS_HOST) ) host = rq->url.host;
    }
    tmpbuff = alloc_buff(CHUNK_SIZE);
    if ( !tmpbuff ) return(NULL);
    /* GET proto://host/path HTTP/1.x */
    rlen = strlen(meth) +
    	1/*sp*/ +
	strlen(url->proto) +
	3 + /* :// */
	strlen(url->host) + 
	10 + /* port */
	strlen(url->path) + 1/*sp*/ +
	strlen(httpv) + 2/* \r\n */;

    if ( url->login ) {

	lp_length += strlen(url->login) + 1;
	if ( url->password ) lp_length += strlen(url->password) + 1;
	lp_length++;
	lp = xmalloc(lp_length,"");
	if ( lp ) {
	    if ( url->password )
		    sprintf(lp,"%s:%s@", url->login,url->password);
		else
		    sprintf(lp,"%s@", url->login);
	    rlen += lp_length;
	}
    }
    answer = xmalloc(ROUND(rlen+1, CHUNK_SIZE), "build_parent_request(): 1"); /* here answer is actually *request* buffer */
    if ( !answer )
	return NULL;

    if ( !strcasecmp(url->proto, "http" ) ) {
	sprintf(answer, "%s %s://%s%s:%d%s %s\r\n", meth, url->proto, lp?lp:"",
		url->host,url->port, url->path, httpv);
    } else {
	sprintf(answer, "%s %s://%s%s%s %s\r\n", meth, url->proto, lp?lp:"",
	    url->host, url->path, httpv);
    }
    if ( attach_data(answer, strlen(answer), tmpbuff) )
	goto fail;
    my_xlog(OOPS_LOG_DBG|OOPS_LOG_HTTP, "build_parent_request(): %s", answer);
    if ( headers ) { /* attach what was requested */
	if ( attach_data(headers, strlen(headers), tmpbuff) )
	    goto fail;
    }
    if ( host && (fav=format_av_pair("Host:", host)) ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
        my_xlog(OOPS_LOG_DBG|OOPS_LOG_HTTP, "build_parent_request(): %s", fav);
	xfree(fav);fav = NULL;
    }
    av = rq->av_pairs;
    while ( av ) {
	if ( is_attr(av, "Connection:") ) /* hop-by-hop */
	    goto do_not_insert;
	if ( is_attr(av, "Proxy-Connection:") ) /* hop-by-hop */
	    goto do_not_insert;
	if ( is_attr(av, "Proxy-Authorization:") ) /* hop-by-hop */
	    goto do_not_insert;
	if ( is_attr(av, "Via:") && insert_via && !via_inserted ) {
	    /* attach my Via: */
	    if ( (fav = format_av_pair(av->attr, av->val)) != 0 ) {
		char	*buf;
		buf = strchr(fav, '\r');
		if ( buf ) *buf = 0;
		if ( !buf ) {
		    buf = strchr(fav, '\n');
		    if ( buf ) *buf = 0;
		}
		if ( loop_detected(fav) ) {
		    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "build_parent_request(): Loop detected: %s\n", fav);
		    goto fail;
		}
		/* ", host_name:port (oops ver)" */
		buf = malloc(strlen(fav)+2+strlen(host_name)+7+10+strlen(version)+2+1);
		if ( !buf ) goto fail;
		sprintf(buf,"%s, %s:%d (Oops %s)\r\n", fav, host_name, http_port, version);
		if ( attach_data(buf, strlen(buf), tmpbuff) ) {
		    xfree(buf);
		    goto fail;
		}
                my_xlog(OOPS_LOG_DBG|OOPS_LOG_HTTP, "build_parent_request(): %s", buf);
		via_inserted = TRUE;
		xfree(buf);
		xfree(fav); fav = NULL;
	    }
	    goto do_not_insert;
	}
	if ( (fav = format_av_pair(av->attr, av->val)) != 0 ) {
	    if ( attach_data(fav, strlen(fav), tmpbuff) )
		goto fail;
            my_xlog(OOPS_LOG_DBG|OOPS_LOG_HTTP, "build_parent_request(): %s", fav);
	    xfree(fav);fav = NULL;
	}
  do_not_insert:
	av = av->next;
    }
    if ( rq->peer_auth
	&& (fav = format_av_pair("Proxy-Authorization: Basic", rq->peer_auth)) != 0 ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
        my_xlog(OOPS_LOG_DBG|OOPS_LOG_HTTP, "build_parent_request(): %s", fav);
	xfree(fav);fav = NULL;
    }
    if ( (fav = format_av_pair("Connection:", "close")) != 0 ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
        my_xlog(OOPS_LOG_DBG|OOPS_LOG_HTTP, "build_parent_request(): %s", fav);
	xfree(fav);fav = NULL;
    }
    if ( insert_via && !via_inserted ) {
	char *buf;

	buf = malloc(4+1+strlen(host_name)+7+10+strlen(version)+2+1);
	if ( !buf ) goto fail;
	sprintf(buf,"Via: %s:%d (Oops %s)\r\n", host_name, http_port, version);
	if ( attach_data(buf, strlen(buf), tmpbuff) ) {
	    xfree(buf);
	    goto fail;
	}
        my_xlog(OOPS_LOG_DBG|OOPS_LOG_HTTP, "build_parent_request(): %s", buf);
	xfree(buf);
	xfree(fav);fav = NULL;
    }
    /* CRLF  */
    if ( attach_data("\r\n", 2, tmpbuff) )
	goto fail;
    if ( attach_data("", 1, tmpbuff) )
	goto fail;
    IF_FREE(answer);
    IF_FREE(lp);
    answer = tmpbuff->data;
    tmpbuff->data = NULL;
    free_chain(tmpbuff);
    return answer;
fail:
    IF_FREE(fav);
    IF_FREE(lp);
    if (tmpbuff) free_chain(tmpbuff);
    IF_FREE(answer);
    return NULL;
}

static int
content_chunked(struct mem_obj *obj)
{
char	*transfer_encoding = NULL;

    if ( obj->headers )
	transfer_encoding = attr_value(obj->headers, "Transfer-Encoding");
    if ( transfer_encoding && !strncasecmp("chunked", transfer_encoding, 7)) {
	    return(TRUE);
    }
    return(FALSE);
}

static int
downgrade(struct request *rq, struct mem_obj *obj)
{
int	res = 0;
char	*transfer_encoding = NULL;
#if	defined(HAVE_ZLIB)
char	*content_encoding = NULL;
#endif	/* HAVE_ZLIB */
    if ( (rq->http_major  < obj->httpv_major) ||
	 (rq->http_minor  < obj->httpv_minor) ) {

	res |= DOWNGRADE_ANSWER;
	if ( obj->headers )
	    transfer_encoding = attr_value(obj->headers, "Transfer-Encoding");
	if ( transfer_encoding && !strncasecmp("chunked", transfer_encoding, 7)) {
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "downgrade(): Turn on Chunked Gateway.\n");
	    res |= UNCHUNK_ANSWER;
	}
    }
#if	defined(HAVE_ZLIB)
    content_encoding = attr_value(obj->headers, "Content-Encoding");
    if ( content_encoding && !strncasecmp(content_encoding, "gzip", 4) ) {
	/* we ungzip if useragent won't accept gzip	*/
	char	*ua_accept = attr_value(rq->av_pairs, "accept-encoding");

	if ( !ua_accept || !(strstr(ua_accept, "gzip")) )
	    res |= UNGZIP_ANSWER;
    }
#endif
    return(res);
}

void
process_vary_headers(struct mem_obj *obj, struct request *rq)
{
    if ( !rq || !obj ) return;
    if ( obj->headers && rq->av_pairs ) {
	/* save Vary: headers */
	char	*p, *t, *tok_ptr, *value;
	char	*vary = attr_value(obj->headers, "Vary:" ), *temp_vary;

	if ( vary && (temp_vary = strdup(vary)) ) {
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "process_vary_headers(): Vary = `%s'\n", vary);
	    /* 1. skip spaces */
	    p = temp_vary;
	    while ( *p && IS_SPACE(*p) ) p++;
		t = p;
		/* split on ',' */
		while ( (p = (char*)strtok_r(t, " ,", &tok_ptr)) != 0 ) {
		    int	a_len;
		    char	a_buf[128], pref[] ="X-oops-internal-rq-", *fav;

		    t = NULL;
		    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "process_vary_headers(): Chk hdr: %s\n", p);
		    value = attr_value(rq->av_pairs, p);
		    if ( value ) {
			/* format and attach */
			a_len = sizeof(pref)+strlen(p)+1;
			if ( a_len <= sizeof(a_buf) ) {
			    fav = a_buf;
			} else {
			    fav = xmalloc(a_len, "process_vary_headers(): fav");
			}
			if ( fav ) {
			    sprintf(fav, "%s%s:", pref, p);
			    insert_header(fav, value, obj);
			    if ( fav != a_buf ) xfree(fav);
			} /* if fav */
		    } /* value */
		} /* while tokens */
	    IF_FREE(temp_vary);
	    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "process_vary_headers(): Vary = `%s'\n", vary);
	 }
    }
}

static void
check_new_object_expiration(struct request *rq, struct mem_obj *obj)
{
	if ( !rq || !obj ) return;
	if ( rq->refresh_pattern.valid ) {
	    int	min,max,lmt, tmpexpires, expires_altered = FALSE;

	    min = rq->refresh_pattern.min;
	    max = rq->refresh_pattern.max;
	    lmt = rq->refresh_pattern.lmt;
	    /* if there was Expires - use it 		*/
	    if ( TEST(obj->flags, ANSW_HAS_EXPIRES) ) {
		if ( obj->times.expires < obj->times.date + min ) {
			obj->times.expires = obj->times.date + min;
			expires_altered = TRUE;
		} else
		if ( obj->times.expires > obj->times.date + max ) {
			obj->times.expires = obj->times.date + max;
			expires_altered = TRUE;
		}  /* else Expires is OK */
	    } else {
		/* we don't received Expires - try to use Last-Modified */
		if ( obj->times.last_modified ) {
		    int	LM_AGE;

		    LM_AGE = obj->times.date - obj->times.last_modified;
		    if ( LM_AGE > 0 ) {
			tmpexpires = (lmt*LM_AGE)/100;
			if ( (tmpexpires>min) && (tmpexpires<max) ) {
			    obj->times.expires = obj->times.date+tmpexpires;
			    expires_altered = TRUE;
			} else {
			    obj->times.expires = obj->times.date+min;
			    expires_altered = TRUE;
			}
		    } else { /* no LM_AGE > 0 */
			obj->times.expires = obj->times.date+min;
			expires_altered = TRUE;
		    }
		} else { /* no last-modified */
		    obj->times.expires = obj->times.date+min;
		    expires_altered = TRUE;
		}
		SET(obj->flags, ANSW_HAS_EXPIRES);
	    }
	    if ( expires_altered == TRUE )
		SET(obj->flags, ANSW_EXPIRES_ALTERED);
	    if ( obj->times.expires < obj->times.date ) {
		obj->flags |= ANSW_NO_STORE;
	    }
	}
	else if ( obj->flags & ANSW_HAS_EXPIRES ) {
	    if ( obj->times.expires < obj->times.date ) {
		obj->flags |= ANSW_NO_STORE;
	    }
	}
}

static char*
check_rewrite_charset(char *s, struct request *rq, struct av *header, int* convert_charset)
{
char	*p, *t, *d=NULL, *delim, text = FALSE;
int	dsize = 0;
    t = s;
    while ( (p = (char*)strtok_r(t, ";", &delim)) != 0 ) {
	/* if it is text/...	*/
	if ( !text ) {
	    if (!strncasecmp(p, "text/", 5) ) {
		text = TRUE;
		t = NULL;
		/* save this token */
		dsize = strlen(header->attr)  + 1
			+ strlen(header->val) + 1
			+ strlen(rq->src_charset) + 1;
		d = malloc(dsize);
		if ( !d )
		    goto not_text;
		sprintf(d, "Content-Type: %s", p);
		continue;
	    } else
		goto not_text;
	}
	t = NULL;
	my_xlog(OOPS_LOG_DBG, "check_rewrite_charset(): Token: `%s'.\n", p);
	while ( *p && IS_SPACE(*p) ) p++;
	if ( !strncasecmp(p, "charset=", 8) ) {
	    my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "check_rewrite_charset(): Alter charset from `%s' to `%s'.\n",
	    	   p+8, rq->src_charset);
	    strncat(d, "; charset=", dsize-strlen(d)-1);
	    strncat(d, rq->src_charset, dsize-strlen(d)-1);
	    if ( convert_charset ) *convert_charset = TRUE;
	    continue;
	} else {
	    /* just attach */
	    strncat(d, p, dsize-strlen(d)-1);
	}
    }
not_text:
    return(d);
}

static int
can_recode_rq_content(struct request *rq)
{
int	res = FALSE;
char	*cont_type;
    if ( rq && rq->av_pairs ) {
	cont_type = attr_value(rq->av_pairs, "Content-Type:");
	if ( cont_type ) {
	    my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "can_recode_rq_content(): rq->content_type = %s\n", cont_type);
	    res = TRUE;
	} else {
	    my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "can_recode_rq_content(): No cont type in rq.\n");
	    res = TRUE;
	}
    }
    return(res);
}

static void
pump_data(struct mem_obj *obj, struct request *rq, int so, int server_so)
{
int		r, pass = 0;
struct	pollarg pollarg[2];

    forever() {

    sel_again:
	pollarg[0].fd = server_so;
	pollarg[1].fd = so;
	pollarg[0].request = FD_POLL_RD;
	pollarg[1].request = FD_POLL_RD;
	r = poll_descriptors(2, &pollarg[0], READ_ANSW_TIMEOUT*1000);
	if ( r <= 0) {
	    goto done;
	}
	if ( IS_HUPED(&pollarg[0]) || IS_HUPED(&pollarg[1]) )
	    goto done;
	if ( IS_READABLE(&pollarg[0]) ) {
	    char b[1024];
	    /* read from server */
	    r = read(server_so, b, sizeof(b));
	    if ( (r < 0) && (ERRNO == EAGAIN) )
		goto sel_again;
	    if ( r <= 0 )
		goto done;
	    if ( rq ) rq->received += r;
	    if ( rq ) rq->doc_received += r;
	    if ( rq->cs_to_client_table
			&& rq->cs_to_client_table->list
			&& rq->cs_to_client_table->list->string)
		r = writet_cv_cs(so, b, r, READ_ANSW_TIMEOUT,
			rq->cs_to_client_table->list->string, TRUE);
	    else
		r = writet(so, b, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 ) goto done;
	    if ( rq ) rq->doc_sent += r;
	    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) )
		update_transfer_rate(rq, r);
	    if ( rq->sess_bw )
		update_sess_transfer_rate(rq, r);
	    if ( (++pass)%2 ) {SLOWDOWN;SLOWDOWN_SESS} ;
	}
	if ( IS_READABLE(&pollarg[1]) ) {
	    char b[1024];
	    /* read from client */
	    r = read(so, b, sizeof(b));
	    if ( (r < 0) && (ERRNO == EAGAIN) )
		goto sel_again;
	    if ( r <= 0 )
		goto done;
	    if ( rq->cs_to_server_table
		&& rq->cs_to_server_table->list
		&& rq->cs_to_server_table->list->string)
	    r = writet_cv_cs(server_so, b, r, READ_ANSW_TIMEOUT,
				rq->cs_to_server_table->list->string, TRUE);
		else
	    r = writet(server_so, b, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 ) goto done;
	}
    }
done:
    return;
}

/* form out Via: value and check if it is already in request via */
static int
loop_detected(char *rq_via)
{
char	*buf;

    if ( !rq_via ) return(FALSE);
    buf = malloc(strlen(host_name) + 10 + strlen(version) +8 + 1);
    if ( !buf )
	return(FALSE);
    sprintf(buf, " %s:%d (Oops %s)" , host_name, http_port, version);
    if ( strstr(rq_via, buf) ) {
	xfree(buf);
	return(TRUE);
    }
    sprintf(buf, ",%s:%d (Oops %s)" , host_name, http_port, version);
    if ( strstr(rq_via, buf) ) {
	xfree(buf);
	return(TRUE);
    }
    xfree(buf);
    return(FALSE);
}

inline
static void
analyze_header(char *p, struct server_answ *a)
{
char	*t;

    my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "analyze_header(): ---> `%s'.\n", p);
    if ( !a->status_code ) {
	/* check HTTP/X.X XXX */
	if ( !strncasecmp(p, "HTTP/", 5) ) {
	    int	httpv_major, httpv_minor;
	    if ( sscanf(p+5, "%d.%d", &httpv_major, &httpv_minor) == 2 ) {
		a->httpv_major = httpv_major;
		a->httpv_minor = httpv_minor;
	    }
	    t = strchr(p, ' ');
	    if ( !t ) {
		my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "analyze_header(): Wrong_header: %s\n", p);
		return;
	    }
	    a->status_code = atoi(t);
	    my_xlog(OOPS_LOG_DBG, "analyze_header(): Status code: %d\n", a->status_code);
	}
	return;
    }
    if ( !strncasecmp(p, "X-oops-internal-request-time: ", 30) ) {
	char        *x;

	x=p + 30;
	while( *x && IS_SPACE(*x) ) x++;
	a->request_time = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "X-oops-internal-response-time: ", 31) ) {
	char        *x;

	x=p + 31;
	while( *x && IS_SPACE(*x) ) x++;
	a->response_time = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "X-oops-internal-content-length: ", 32) ) {
	char        *x;

	x=p + 31;
	while( *x && IS_SPACE(*x) ) x++;
	a->x_content_length = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "X-oops-internal-alt-expires: ", 29) ) {
	char        *x;

	x=p + 29;
	while( *x && IS_SPACE(*x) ) x++;
	a->times.expires = atoi(x);
	SET(a->flags, ANSW_EXPIRES_ALTERED | ANSW_HAS_EXPIRES);
	return;
    }
    if ( !strncasecmp(p, "Content-length: ", 16) ) {
	char        *x;
	/* length */
	x=p + 16; /* strlen("content-length: ") */
	while( *x && IS_SPACE(*x) ) x++;
	a->content_len = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "Date: ", 6) ) {
	char        *x;
	/* length */
	x=p + 6; /* strlen("date: ") */
	while( *x && IS_SPACE(*x) ) x++;
	a->times.date  = global_sec_timer;
	if (http_date(x, &a->times.date) ) my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "analyze_header(): Can't parse date: %s\n", x);
	return;
    }
    if ( !strncasecmp(p, "Last-Modified: ", 15) ) {
	char        *x;
	/* length */
	x=p + 15; /* strlen("date: ") */
	while( *x && IS_SPACE(*x) ) x++;
	if (http_date(x, &a->times.last_modified) ) my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "analyze_header(): Can't parse date: %s\n", x);
	    else
		a->flags |= ANSW_LAST_MODIFIED;
	return;
    }
    if ( !strncasecmp(p, "Pragma: ", 8) ) {
	char        *x;
	/* length */
	x=p + 8; /* strlen("Pragma: ") */
	if ( strstr(x, "no-cache") ) a->flags |= ANSW_NO_STORE;
	return;
    }
    if ( !strncasecmp(p, "Age: ", 5) ) {
	char        *x;
	/* length */
	x=p + 5; /* strlen("Age: ") */
	a->times.age = atoi(x);
	return;
    }
    if ( !strncasecmp(p, "Cache-Control: ", 15) ) {
	char        *x;
	/* length */
	x=p + 15; /* strlen("Cache-Control: ") */
	while( *x && IS_SPACE(*x) ) x++;
	if ( strstr(x, "no-store") )
		a->flags |= ANSW_NO_STORE;
	if ( strstr(x, "no-cache") )
		a->flags |= ANSW_NO_STORE;
	if ( strstr(x, "private") )
		a->flags |= ANSW_NO_STORE;
	if ( strstr(x, "must-revalidate") )
		a->flags |= ANSW_MUST_REVALIDATE;
	if ( !strncasecmp(x, "proxy-revalidate", 15) )
		a->flags |= ANSW_PROXY_REVALIDATE;
	if ( sscanf(x, "max-age = %d", (int*)&a->times.max_age) == 1 )
		a->flags |= ANSW_HAS_MAX_AGE;
    }
    if ( !strncasecmp(p, "Connection: ", 12) ) {
	char        *x;
	/* length */
	x = p + 12; /* strlen("Connection: ") */
	while( *x && IS_SPACE(*x) ) x++;
	if ( !strncasecmp(x, "keep-alive", 10) )
		a->flags |= ANSW_KEEP_ALIVE;
	if ( !strncasecmp(x, "close", 5) )
		a->flags &= ~ANSW_KEEP_ALIVE;
    }
    if (    !TEST(a->flags, ANSW_HAS_EXPIRES) 
         && !strncasecmp(p, "Expires: ", 9) ) {
	char        *x;
	/* length */
	x = p + 9; /* strlen("Expires: ") */
	while( *x && IS_SPACE(*x) ) x++;
	a->times.expires  = time(NULL);
	if (http_date(x, &a->times.expires)) {
		my_xlog(OOPS_LOG_DBG|OOPS_LOG_INFORM, "analyze_header(): Can't parse date: %s\n", x);
		return;
	}
	a->flags |= ANSW_HAS_EXPIRES;
	return;
    }
}

inline
static int
add_header_av(char* avtext, struct mem_obj *obj)
{
struct	av	*new = NULL, *next;
char		*attr = avtext, *sp = avtext, *val, holder;
char		*new_attr = NULL, *new_val = NULL;
char		nullstr[1];

    if ( *sp == 0 ) return(-1);
    while( *sp && IS_SPACE(*sp) ) sp++;
    while( *sp && !IS_SPACE(*sp) && (*sp != ':') ) sp++;
    if ( !*sp ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "add_header_av(): Invalid header string: '%s'\n", avtext);
	nullstr[0] = 0;
	sp = nullstr;
    }
    if ( *sp == ':' ) sp++;
    holder = *sp;
    *sp = 0;
    if ( !strlen(attr) ) return(-1);
    new = xmalloc(sizeof(*new), "add_header_av(): for av pair");
    if ( !new ) goto failed;
    new_attr = xmalloc( strlen(attr)+1, "add_header_av(): for new_attr" );
    if ( !new_attr ) goto failed;
    strcpy(new_attr, attr);
    *sp = holder;
    val = sp; while( *val && IS_SPACE(*val) ) val++;
    /*if ( !*val ) goto failed;*/
    new_val = xmalloc( strlen(val) + 1, "add_header_av(): for new_val");
    if ( !new_val ) goto failed;
    strcpy(new_val, val);
    new->attr = new_attr;
    new->val  = new_val;
    new->next = NULL;
    if ( !obj->headers ) {
	obj->headers = new;
    } else {
	next = obj->headers;
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

int
check_server_headers(struct server_answ *a, struct mem_obj *obj, struct buff *b, struct request *rq)
{
char	*start, *beg, *end, *p;
char	holder, its_here = 0, off = 2;
char	*p1 = NULL;

    if ( !b || !b->data ) return(0);
    beg = b->data;
    end = b->data + b->used;

    if ( end - beg > MAX_DOC_HDR_SIZE ) {
        /* Header is too large */
        return(1);
    }
go:
    if ( a->state & GOT_HDR ) return(0);
    start = beg + a->checked;
    if ( !a->checked ) {
	p = memchr(beg, '\n', end-beg);
	holder = '\n';
	if ( !p ) {
	    p = memchr(beg, '\r', end-beg);
	    holder = '\r';
	}
	if ( !p ) return(0);
	if ( *p == '\n' ) {
	    if ( *(p-1) == '\r' ) {
		p1 = p-1;
		*p1 = 0;
	    }
	}
	*p = 0;
	a->checked = strlen(start);
	/* this is HTTP XXX yyy "header", which we will never rewrite */
	analyze_header(start, a);
	if ( add_header_av(start, obj) ) {
	    *p = holder;
	    if ( p1 ) {*p1 = '\r'; p1=NULL;}
	    return(-1);
	}
	*p = holder;
	if ( p1 ) {*p1 = '\r'; p1=NULL;}
	goto go;
    }
    if ( (end - start >= 2) && !memcmp(start, "\n\n", 2) ) {
	its_here = 1;
	off = 2;
    }
    if ( (end - start >= 3) && !memcmp(start, "\r\n\n", 3) ) {
	its_here = 1;
	off = 3;
    }
    if ( (end - start >= 3) && !memcmp(start, "\n\r\n", 3) ) {
	its_here = 1;
	off = 3;
    }
    if ( (end - start >= 4) && !memcmp(start, "\r\n\r\n", 4) ) {
	its_here = 1;
	off = 4;
    }
    if ( its_here ) {
	struct buff	*body;
	int		all_siz;

	obj->insertion_point = start-beg;
	obj->tail_length = off;
	a->state |= GOT_HDR ;
	obj->httpv_major = a->httpv_major;
	obj->httpv_minor = a->httpv_minor;
	obj->content_length = a->content_len;
	b->used = ( start + off ) - beg;	/* trunc first buf to header siz	*/
	/* if requested don't cache documents without "Last-Modified" */
	if ( dont_cache_without_last_modified
		&& !TEST(a->flags, ANSW_LAST_MODIFIED) ) {
	    SET(obj->flags, ANSW_NO_STORE|ANSW_NO_CACHE);
	}
	/* allocate data storage */
	if ( a->content_len ) {
	    if ( a->content_len > maxresident ) {
		/*
		 -  This object will not be stored, we will receive it in
		 -  small parts, in syncronous mode
		 -  allocate as much as we need now...
		*/
		all_siz = ROUND_CHUNKS(end-start-off);
		/*
		 - mark object as 'not for store' and 'don't expand container'
		*/
		a->flags |= (ANSW_NO_STORE | ANSW_SHORT_CONTAINER);
	    } else {/* obj is not too large */
		all_siz = MIN(a->content_len, 8192);
            }
	} else { /* no Content-Len: */
            char        *transfer_encoding = NULL;
	    all_siz = ROUND_CHUNKS(end-start-off);
	    transfer_encoding = attr_value(obj->headers, "Transfer-Encoding");
	    if ( !(transfer_encoding && !strncasecmp("chunked", transfer_encoding, 7)) ) {
                a->flags |= (ANSW_NO_STORE | ANSW_SHORT_CONTAINER);
            }            
        }
	body = alloc_buff(all_siz);
	if ( !body ) {
	    return(-1);
	}
	b->next = body;
	obj->hot_buff = body;
	attach_data(start+off, end-start-off, obj->hot_buff);
	return(0);
    }
    p = start;
    while( (p < end) && ( *p == '\r' || *p == '\n' ) ) p++;
    if ( p < end && *p ) {
	char *t = memchr(p, '\n', end-p);
	char *tmp, *saved_tmp;

	holder = '\n';
	if ( !t ) {
	    t = memchr(p, '\r', end-p);
	    holder = '\r';
	}
	if ( !t ) return(0);
	if ( *t == '\n' ) {
	    if ( *(t-1) == '\r' ) {
		p1 = t-1;
		*p1 = 0;
	    }
	}
	*t = 0;
	saved_tmp = tmp = strdup(p);
	if ( !tmp )
	    return(-1);
	do_redir_rewrite_header(&tmp, rq, NULL);
	analyze_header(tmp, a);
	if ( add_header_av(tmp, obj) ) {
	    free(tmp);
	    return(-1);
	}
	if ( saved_tmp != tmp ) {
	    /* header was changed */
	    if ( obj ) SET(obj->flags, ANSW_HDR_CHANGED);
	}
	free(tmp);
	*t = holder;
	if ( p1 ) { *p1 = '\r'; t=p1; p1 = NULL;}
	a->checked = t - beg;
	goto go;
    }
    return(0);
}
