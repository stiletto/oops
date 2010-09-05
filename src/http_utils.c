#include        <stdio.h>
#include        <stdlib.h>
#include        <fcntl.h>
#include        <errno.h>
#include        <stdarg.h>
#include        <string.h>
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

int		no_direct_connections	= FALSE;

int		insert_via = TRUE;
int		insert_x_forwarded_for = TRUE;

int		writen(int, char*, int);
int		str_to_sa(char*, struct sockaddr*);
void		analyze_header(char*, struct server_answ *);
int		attach_data(char* src, int size, struct buff *buff);
struct	buff*	alloc_buff(int size);
int		send_data_from_buff(int, struct buff **, int *, int *);
int		send_data_from_buff_no_wait(int, struct buff **, int *, int *, int*, int);
void		send_data_from_obj(struct request*, int, struct mem_obj *, int);
void		unlock_obj(struct mem_obj *);
void		lock_obj(struct mem_obj *);
void		unlock_obj_state(struct mem_obj *);
void		lock_obj_state(struct mem_obj *);
void		unlock_decision(struct mem_obj *);
void		lock_decision(struct mem_obj *);
void		change_state(struct mem_obj*, int);
void		change_state_notify(struct mem_obj *obj);
void		free_chain(struct buff *);
void		destroy_obj(struct mem_obj *);
int		continue_load(struct request*, int, int, struct mem_obj *);
int		parent_connect(int, char *, int , struct request *);
int		peer_connect(int, struct sockaddr_in*, struct request *);
int		srv_connect(int, struct url *url, struct request*);
int		fill_server_request(struct request *, struct buff *);
struct	mem_obj	*check_validity(int, struct request*, char *, struct mem_obj*);
char*		build_direct_request(char *meth, struct url *url, char *headers, struct request *rq);
char*		build_parent_request(char *meth, struct url *url, char *headers, struct request *rq);

void
send_not_cached(int so, struct request *rq, char *headers)
{
int			server_so = -1, r, received = 0, pass=0, to_write;
char			*answer = NULL, *p, *origin;
struct	url		*url = &rq->url;
char			*meth, *source;
struct timeval		start_tv, stop_tv;
int			delta_tv;
int			have_code = 0, sent = 0;

    if ( rq->meth == METH_GET ) meth="GET";
    else if ( rq->meth == METH_PUT ) meth="PUT";
    else if ( rq->meth == METH_POST ) meth="POST";
    else if ( rq->meth == METH_TRACE ) meth="TRACE";
    else if ( rq->meth == METH_HEAD ) meth="HEAD";
    else
	return;
    gettimeofday(&start_tv, NULL);
    server_so = parent_port?parent_connect(so, parent_host, parent_port, rq):
			    srv_connect(so, url, rq);

    if ( server_so == -1 )
	goto done;

    set_socket_options(server_so);
    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));
    if ( fcntl(server_so, F_SETFL, fcntl(server_so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));

    answer = parent_port?build_parent_request(meth, &rq->url, headers, rq):
		         build_direct_request(meth, &rq->url, headers, rq);
    if ( !answer )
	goto done;

    /* push whole request to server */
    r = writet(server_so, answer, strlen(answer), READ_ANSW_TIMEOUT);
    free(answer); answer = NULL;
    if ( r < 0 ) {
	say_bad_request(so, "Can't send", strerror(errno), ERR_TRANSFER, rq);
	goto done;
    }
    answer=xmalloc(ANSW_SIZE+1, "send_not_cached");
    if ( !answer ) goto done;
    if ( rq->meth == METH_POST && rq->data ) {
	char	*cp = rq->data->data;
	int	rest= rq->data->used;
	/* send whole content to server				*/
	
	while ( rest > 0 ) {
	    int to_send;
	    to_send = MIN(2048, rest);
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
	    r = writet(server_so, answer, r, READ_ANSW_TIMEOUT);
	    if ( r <= 0 )
		goto done;
	}
    }
    while(1) {
	r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
	if ( r < 0 ) {
	    if ( !sent ) say_bad_request(so, "Can't read", strerror(errno), ERR_TRANSFER,rq);
	    goto done;
	}
        if ( r == 0 ) /*done*/
	    goto done;
	received += r;
	if ( !have_code ) {
	    /* try to find it */
	    int http_maj, http_min,code ;
	    answer[r] = 0;
	    if ( sscanf(answer, "HTTP/%d.%d %d", &http_maj, &http_min, &code) == 3 ) {
		have_code = code;
	    }
	}
	to_write = r;
	p = answer;
    w_l:
	while( to_write ) {
	    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH) ) {
		if ( (++pass)%2 ) SLOWDOWN ;
		r = MIN(to_write, 512);
	    }
	    /* if client close connection we'll note here */
	    r = writet(so, p, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 )
		goto done;
	    sent += r;
	    to_write -= r;
	    p += r;
	    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH) ) update_transfer_rate(rq, r);
	}
    }
done:
    if ( server_so != -1 ) close(server_so);
    if ( answer ) free(answer);
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( !have_code ) have_code = 555;
    source = parent_port?(TEST(rq->flags, RQ_GO_DIRECT)?"DIRECT":"PARENT"):"DIRECT";
    if ( parent_port ) origin = parent_host;
	else	       origin = url->host;
    log_access(delta_tv, &rq->client_sa,
    	"TCP_MISS", have_code, received,
	meth, &rq->url, source, "-", origin);
    my_log("not_cached done\n");
    return;
}

void
send_from_mem(int so, struct request *rq, char *headers, struct mem_obj *obj, int flags)
{
int			server_so = -1;
struct	mem_obj		*new_obj = NULL;
struct	timeval		start_tv, stop_tv;
time_t			now;
int			delta_tv, received;
int			have_code = 0;
char			*tcp_tag = "TCP_HIT", *meth;
#define			ROLE_READER	1
#define			ROLE_WRITER	2
#define			ROLE_VALIDATOR	3
int			role;
char			*content_type, ctbuf[40], *origin;

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
	my_log("Document not expired, send from mem\n");
	goto prepare_send_mem;
    }
    goto revalidate;

prepare_send_mem:
    role = ROLE_READER;
    INCR_READERS(obj);
    send_data_from_obj(rq,so,obj,flags);
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
	    send_data_from_obj(rq,so, obj, flags);
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
	/* now make decision - object is valid or not		*/
	server_so = parent_port?parent_connect(so, parent_host, parent_port, rq):
				srv_connect(so, &obj->url, rq);
	if ( server_so == -1 ) {
	    /* send old content, but mark obj dead		*/
	    SET(obj->flags, FLAG_DEAD);
	    SWITCH_TO_READER_ON(obj);
	    DECR_READERS(obj);
	    obj->decision_done = TRUE ;
	    unlock_decision(obj);
	    pthread_cond_broadcast(&obj->decision_cond);
	    goto done;
	}
	new_obj = check_validity(server_so, rq, meth, obj);
	obj->child_obj = new_obj;
	obj->decision_done = TRUE ;
	unlock_decision(obj);
	pthread_cond_broadcast(&obj->decision_cond);
	if ( new_obj ) {
	    /* increment references to new_obs, as obj refers	*/
	    /* to it						*/
	    INCREMENT_REFS(new_obj);
	    /* old object is invalid anymore 			*/
	    SET(obj->flags, FLAG_DEAD);
	    /* continue load to new_obj */
	    continue_load(rq, so, server_so, new_obj);
	    DECR_WRITERS(new_obj);
	    new_obj->response_time	= time(NULL);
	    tcp_tag = "TCP_REFRESH_MISS";
	    goto done;
	} else {
	    /*--------------------------------------------------*/
	    /* old object is valid				*/
	    /* switch to READER role, because we will use	*/
	    /* old content					*/
	    /*--------------------------------------------------*/
	    SWITCH_TO_READER_ON(obj);
	    send_data_from_obj(rq,so, obj, flags);
	    DECR_READERS(obj);
	    tcp_tag = "TCP_REFRESH_HIT";
	    goto done;
	}
    }

done:
    my_log("from mem sended\n");
    if ( new_obj ) leave_obj(new_obj);
    if ( server_so != -1 ) close(server_so);
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( obj->status_code ) have_code = obj->status_code;
	else		    have_code = 555;
    if ( new_obj ) received = new_obj->size;
         else	   received =     obj->size;
    if ( content_type = attr_value(obj->headers, "Content-Type") ) {
	char *p;
	strncpy(ctbuf, content_type, sizeof(ctbuf)-1);
        p = &ctbuf[0];
	ctbuf[sizeof(ctbuf)-1] = 0;
	while (*p) {
	    if ( isspace(*p) || *p==';' ) {
		*p = 0;
		break;
	    }
	    p++;
	}
	content_type = ctbuf;
    } else {
	content_type = "text/html";
    }
    if ( parent_port ) origin = parent_host;
	else	       origin = obj->url.host;
    log_access(delta_tv, &rq->client_sa,
    	tcp_tag, have_code, received,
	meth, &rq->url, "NONE", content_type, origin);
    LOCK_STATISTICS(oops_stat);
	oops_stat.hits0++;
	oops_stat.hits++;
    UNLOCK_STATISTICS(oops_stat);
    return;
}

void
send_data_from_obj(struct request *rq, int so, struct mem_obj *obj, int flags)
{
int 		r, sended, received, state, send_hot_pos, pass=0, sf=0, ssended;
struct	buff	*send_hot_buff;
fd_set		wset;
struct	timeval	tv;
char		*content_type, *transfer_encoding;
char		convert_from_chunked = FALSE, downgrade_minor = FALSE;
int		rest_in_chunk = 0;

    if (   ((rq->http_major <= 1) && (rq->http_minor < 1)) &&
	   (obj->headers && !strcmp(obj->headers->attr,"HTTP/1.1")) ) {

	downgrade_minor = TRUE;
	transfer_encoding = attr_value(obj->headers, "Transfer-Encoding");
	if ( transfer_encoding && !strncasecmp("chunked", transfer_encoding, 7)) {
	    my_log("Turn on Chunked Gateway\n");
	    convert_from_chunked = TRUE;
	}
    }
    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));
    sended = 0;
    received = obj->size;
    send_hot_buff = NULL;
    send_hot_pos = 0;
go_again:
    lock_obj_state(obj);
    while(1) {
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
    	struct av	*header = obj->headers;

	if ( !header ) goto done ;
	/* first must be "HTTP/1.x 200 ..." */
	if ( downgrade_minor ) {
	    send_av_pair(so, "HTTP/1.0", header->val);
	    header = header->next;
	}
	while(header) {
	    /*my_log("Sending ready header '%s'->'%s'\n", header->attr, header->val);*/
	    if (   !is_attr(header, "Age:") &&

			/* we must not send Tr.-Enc. and Cont.-Len. if we convert
			 * from chunked							*/

	    	   !(convert_from_chunked && is_attr(header, "Transfer-Encoding")) &&
	    	   !(convert_from_chunked && is_attr(header, "Content-Length")) ){

		send_av_pair(so, header->attr, header->val);
	    }
	    header = header->next;
	}
	/* send header from memory */
	if ( flags & MEM_OBJ_WARNING_110 ) {
	    my_log("Send Warning: 110 oops Stale document\n");
	    send_av_pair(so, "Warning:", "110 oops Stale document");
	}
	if ( flags & MEM_OBJ_WARNING_113 ) {
	    my_log("Send Warning: 113 oops Heuristic expiration used\n");
	    send_av_pair(so, "Warning:", "113 oops Heuristic expiration used");
	}
	{
	    char agebuf[32];
	    sprintf(agebuf, "%d", (int)current_obj_age(obj));
	    send_av_pair(so, "Age:", agebuf);
	}
	/* end of headers */
	send_av_pair(so,"","");

	if ( !obj->container ) goto done;
	send_hot_buff = obj->container->next;
	send_hot_pos = 0;
	sended = obj->container->used;
    }
    if ( (state == OBJ_READY) && (sended >= obj->size) ) {
	my_log("obj is ready\n");
	goto done;
    }
    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH) && (++pass)%2 )
	SLOWDOWN ;
    FD_ZERO(&wset);
    FD_SET(so, &wset);
    tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
    r = select(so+1, NULL, &wset, NULL, &tv);
    if ( r <= 0 ) goto done;
    ssended = sended;
    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH) )
	sf |= RQ_HAS_BANDWIDTH;
    if ( convert_from_chunked )
	sf |= RQ_CONVERT_FROM_CHUNKED;
    if ((r=send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, &rest_in_chunk, sf)) ) {
	my_log("send_data_from_mem: send error: %s\n", strerror(errno));
	goto done;
    }
    if ( !r && convert_from_chunked && !rest_in_chunk ) {
	/* we sent nothing... this can be because we convert from chunked
	 * ans we have only part of chunk size value stored in buff. like this:
	 * | ..... 2f| - e.g currently available buff contain
	 * only begin of chunk size, without ending CRLF
	 * If object is ready, this means something wrong, just return.
	 * If object is in progress, we have to wait some time.			*/
	if ( obj->state==OBJ_READY )
	    goto done;
	/* else object in progress, sleep a little */
	my_sleep(1);
	goto go_again;
    }
    if ( TEST(rq->flags, RQ_HAS_BANDWIDTH)) update_transfer_rate(rq, sended-ssended);
    goto go_again;
done:
    return;
}
/* return new object if old is invalid	*/
/* otherwise returns NULL		*/
struct mem_obj *
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
int			r, maxfd;
fd_set			rset;
struct	timeval		tv;
struct	buff		*to_server_request = NULL;

    /* send If-modified-Since request	*/
    /* prepare faked header		*/
    if (!mk1123time(obj->times.date, mk1123buff, sizeof(mk1123buff)) ) {
	my_log("Can't mk1123time\n");
	return NULL;
    }
    fake_header = xmalloc(19 + strlen(mk1123buff) + 3, "for fake header");
    if ( !fake_header ) {
	my_log("Can't create fake header\n");
	return NULL;
    }
    sprintf(fake_header, "If-Modified-Since: %s\r\n", mk1123buff);

    answer = parent_port?build_parent_request(meth, &rq->url, fake_header, rq):
		         build_direct_request(meth, &rq->url, fake_header, rq);
    if ( !answer )
	goto validate_err;
    to_server_request = alloc_buff(2*CHUNK_SIZE);
    if ( !to_server_request ) {
	my_log("No mem in check_validity\n");
	goto validate_err;
    }
    r = attach_data(answer, strlen(answer), to_server_request);
    if ( r )
	goto validate_err;
    if ( insert_x_forwarded_for ) {
	char	*ip_addr = my_inet_ntoa(&rq->client_sa);
	if ( ip_addr ) {
	    r = attach_data("X-Forwarded-For: ", strlen("X-Forwarded-For: "),
			to_server_request);
	    if ( !r )
	        r = attach_data(ip_addr, strlen(ip_addr), to_server_request);
	    if ( !r )
		r = attach_data("\r\n", 2, to_server_request);
	    xfree(ip_addr);
	}
    }
    if ( r )
	goto validate_err;
    if ( insert_via ) {
	r = attach_data("Via: Oops 0.0alpha1\r\n",
	    strlen("Via: Oops 0.0alpha1\r\n"), to_server_request);
    }
    if ( r || attach_data("\r\n", 2, to_server_request) )
	goto validate_err;
    r = writet(server_so, to_server_request->data, to_server_request->used,
    		READ_ANSW_TIMEOUT);
    free(answer); answer = NULL;
    free(fake_header); fake_header = NULL;
    free_container(to_server_request); to_server_request = NULL;

    new_obj = locate_in_mem(&rq->url, AND_PUT|AND_USE|PUT_NEW_ANYWAY|NO_DISK_LOOKUP);
    if ( !new_obj ) {
	my_log("Can't create new_obj\n");
	goto validate_err;
    }

    new_obj->request_time = time(NULL);
    bzero(&answer_stat, sizeof(answer_stat));
    answer=xmalloc(ANSW_SIZE, "send_from_mem3");
    if ( !answer ) {
	goto validate_err;
    }

    if ( fcntl(server_so, F_SETFL, fcntl(server_so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));
    while(1) {
	FD_ZERO(&rset);
	FD_SET(server_so, &rset);
	maxfd = server_so;
	tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
        r = select(maxfd+1, &rset, NULL, NULL, &tv);
	if ( r < 0  ) {
	    my_log("select: error on new_obj\n");
	    goto validate_err;
	}
	if ( r == 0 ) {
	    my_log("select: timed out on new_obj\n");
	    goto validate_err;
	}
	if ( !FD_ISSET(server_so, &rset) )
	    continue;
	r = read(server_so, answer, ANSW_SIZE);
	if ( r <  0 ) {
	    if ( errno == EAGAIN ) {
		my_log("Hmm, again select say ready, but read fails\n");
		continue;
	    }
	    my_log("fill_new_obj: select error: %s\n", strerror(errno));
	    goto validate_err;
	}
	if ( r == 0 ) {
	    my_log("fill_new_obj: server closed connection too early\n");
	    goto validate_err;
	}
	if ( !new_obj->container ) {
		struct	buff *new;
		new = alloc_buff(CHUNK_SIZE);
		if ( !new ) {
		    my_log("Cant create container\n");
		    goto validate_err;
		}
		new_obj->container = new;
	}
	if ( !(answer_stat.state & GOT_HDR) ) {
	    new_obj->size += r;
	    if ( attach_data(answer, r, new_obj->container) ) {
		my_log("attach_data error\n");
		goto validate_err;
	    }
	    if ( check_server_headers(&answer_stat, new_obj, new_obj->container) ) {
		my_log("check_server_headers\n");
		goto validate_err;
	    }
	    if ( answer_stat.state & GOT_HDR ) {
		new_obj->times		= answer_stat.times;
		new_obj->status_code 	= answer_stat.status_code;
		new_obj->flags	       |= answer_stat.flags;

		if ( new_obj->status_code == STATUS_NOT_MODIFIED ) {
		    SET(new_obj->flags, FLAG_DEAD);
		    leave_obj(new_obj);
		    new_obj = NULL;
		    goto validate_done;
		}
		new_obj->flags|= answer_stat.flags;
		new_obj->times = answer_stat.times;
		if ( !new_obj->times.date ) new_obj->times.date = time(NULL);
		if ( answer_stat.flags & ANSW_HAS_EXPIRES ) {
		    if ( new_obj->times.expires < new_obj->times.date )
			new_obj->flags |= ANSW_NO_STORE;
		}
		if ( new_obj->status_code == STATUS_OK ) {
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
fill_mem_obj(int so, struct request *rq, char * headers, struct mem_obj *obj)
{
int			server_so = -1, r;
char			*answer = NULL;
struct	url		*url = &rq->url;
char			*meth, *source;
struct	server_answ	answ_state;
int			received=0, sended=0, maxfd, resident_size;
struct	buff		*send_hot_buff=NULL;
int			send_hot_pos=0;
fd_set			rset, wset;
struct	timeval		tv, start_tv, stop_tv;
int			delta_tv;
int			have_code = 0, pass = 0;
struct	buff		*to_server_request = NULL;
char			*content_type, ctbuf[40], origin[MAXHOSTNAMELEN];
struct	sockaddr_in	peer_sa;
int			source_type;

    if ( rq->meth == METH_GET ) meth="GET";
    else if ( rq->meth == METH_PUT ) meth="PUT";
    else if ( rq->meth == METH_POST ) meth="POST";
    else if ( rq->meth == METH_HEAD ) meth="HEAD";
    else {
	DECR_WRITERS(obj);
	return;
    }
    gettimeofday(&start_tv, NULL);
    if ( !parent_port && peers && (icp_so != -1) && (rq->meth == METH_GET) && !is_local_dom(rq->url.host) ) {
	struct icp_queue_elem *new;
	struct timeval   tv;

	bzero((void*)&peer_sa, sizeof(peer_sa));
	my_log("sending icp_requests\n");
	new = (struct icp_queue_elem*)xmalloc(sizeof(*new),"icp_q_e");
	if ( !new ) goto icp_failed;
	bzero(new, sizeof(*new));
	pthread_cond_init(&new->icpr_cond, NULL);
	pthread_mutex_init(&new->icpr_mutex, NULL);
	gettimeofday(&tv, NULL);
	new->waitors = 1;
	/* XXX make rq_n generation more random */
	new->rq_n    = tv.tv_sec+tv.tv_usec;
	pthread_mutex_lock(&new->icpr_mutex);
	if ( !send_icp_requests(rq, new) ) {
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
	    if ( pthread_cond_timedwait(&new->icpr_cond,&new->icpr_mutex,&ts) ) {
		/* failed */
		my_log("icp timedout\n");
	    } else {
		/* success */
		my_log("icp_success\n");
	    }
	    pthread_mutex_unlock(&new->icpr_mutex);
	    if ( new->status ) {
		my_log("Fetch from neighbour\n");
		peer_sa = new->peer_sa;
		source_type = new->type;
		server_so = peer_connect(so, &new->peer_sa, rq);
		icp_request_destroy(new);
		goto server_connect_done;
	    } else {
		if ( no_direct_connections ) {
		    /* check if there was misses from parent	*/
		    if ( new->peer_sa.sin_port ) {
			peer_sa = new->peer_sa;
			source_type = new->type;
			server_so = peer_connect(so, &new->peer_sa, rq);
			icp_request_destroy(new);
			goto server_connect_done;
		    }
		}
		my_log("Direct\n");
	    }
	    icp_request_destroy(new);
	} else {
	    new->waitors = 0;
	    pthread_mutex_unlock(&new->icpr_mutex);
	    pthread_mutex_destroy(&new->icpr_mutex);
	    pthread_cond_destroy(&new->icpr_cond);
	    xfree(new);
	}

 icp_failed:;
    } /* all icp things */

    source_type = (parent_port && !is_local_dom(rq->url.host))?PEER_PARENT:SOURCE_DIRECT;
    server_so = (source_type==PEER_PARENT)?parent_connect(so, parent_host, parent_port, rq):
			    srv_connect(so, url, rq);

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
	strncpy(origin, obj->url.host, sizeof(origin));
	break;
    case PEER_PARENT:
	source="PARENT";
	if ( parent_port ) strncpy(origin, parent_host, sizeof(origin));
	  else {
	    RDLOCK_CONFIG ;
	    peer = peer_by_http_addr(&peer_sa);
	    if ( peer && peer->name )
		strncpy(origin, peer->name, sizeof(origin));
	     else
		strncpy(origin, "unknown_peer", sizeof(origin));
	    UNLOCK_CONFIG ;
	}
	break;
    case PEER_SIBLING:
	source="SIBLING";
	RDLOCK_CONFIG ;
	peer = peer_by_http_addr(&peer_sa);
	if ( peer && peer->name )
		strncpy(origin, peer->name, sizeof(origin));
	    else
		strncpy(origin, "unknown_peer", sizeof(origin));
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

    answer = (source_type==SOURCE_DIRECT)?build_direct_request(meth, &rq->url, headers, rq):
    			 build_parent_request(meth, &rq->url, headers, rq);

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
    free(answer); answer = NULL;

    r = writet(server_so, to_server_request->data, to_server_request->used, READ_ANSW_TIMEOUT);
    free_container(to_server_request);

    if ( r < 0 ) {
	say_bad_request(so, "Can't send", strerror(errno), ERR_TRANSFER, rq);
	change_state(obj, OBJ_READY);
	obj->flags |= FLAG_DEAD;
	goto error;
    }

    obj->request_time = time(NULL);
    answer=xmalloc(ANSW_SIZE+1, "fill_mem_obj2");
    if ( !answer )
	goto error;

    bzero(&answ_state, sizeof(answ_state));

    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));
    if ( fcntl(server_so, F_SETFL, fcntl(server_so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));
    while(1) {
	FD_ZERO(&rset); FD_ZERO(&wset);
	FD_SET(server_so, &rset);
	if ( server_so > so ) maxfd = server_so;
	    else	      maxfd = so;
	if ( (obj->state == OBJ_INPROGR) && (received > sended) && (so != -1) ) {
	    if ( (++pass)%2 && TEST(rq->flags, RQ_HAS_BANDWIDTH) ) {
		r = group_traffic_load(inet_to_group(&rq->client_sa.sin_addr));
		tv.tv_sec = 0;tv.tv_usec = 0;
		if ( r < 75 ) /* low load */
		    goto ignore_bw_overload;
		else if ( r < 95 ) /* start to slow down */
		    tv.tv_usec = 250;
		else if ( r < 100 )
		    tv.tv_usec = 500;
		else
		    tv.tv_sec = MIN(2, r/100);
		r = select(maxfd+1, &rset, NULL, NULL, &tv);
		if ( r < 0 ) goto error;
		if ( r== 0 ) continue;
		goto read_s;
	    }
	ignore_bw_overload:
	    FD_SET(so, &wset);
	}
	tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
        r = select(maxfd+1, &rset, &wset, NULL, &tv);
	if ( r < 0 ) {
	    my_log("select: %s\n", strerror(errno));
	    change_state(obj, OBJ_READY);
	    obj->flags |= FLAG_DEAD;
	    goto error;
	}
	if ( r == 0 ) {
	    my_log("select: timed out\n");
	    change_state(obj, OBJ_READY);
	    obj->flags |= FLAG_DEAD;
	    goto error;
	}
	if ( (so != -1) && FD_ISSET(so, &wset) ) {
	   int	sf, ssended = sended;
	   r--;
	   sf = (rq->flags & RQ_HAS_BANDWIDTH);
	   if ( send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, NULL, sf) )
		so = -1;
	   if ( rq->flags & RQ_HAS_BANDWIDTH) update_transfer_rate(rq, sended-ssended);
	}
	if ( so == -1 ) {
	    lock_obj(obj);
	    if ( obj->refs <= 1 ) /* we are only who refers to this obj */ {
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
	if ( !FD_ISSET(server_so, &rset) ) {
	    if ( r ) {
		/* this is solaris 2.6 select bug(?) workaround */
		my_log("select bug(?)\n");
		obj->state =  OBJ_READY;
		obj->flags |= FLAG_DEAD;
		change_state_notify(obj);
		goto error;
	    }
	    continue;
	}
	r = read(server_so, answer, ANSW_SIZE);
	if ( r < 0  ) {
	    /* Error reading from server */
	    if ( errno == EAGAIN ) {
		my_log("Hmm, server_so was ready, but read failed\n");
		continue;
	    }
	    my_log("fill_mem_obj: read failed: %s\n", strerror(errno));
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
	    while( (so != -1) && send_hot_buff && (received > sended) ) {
		int	ssended, sf;
		if ( (++pass)%2 && TEST(rq->flags, RQ_HAS_BANDWIDTH) )
		    SLOWDOWN ;
		FD_ZERO(&wset);
		FD_SET(so, &wset);
		tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
		r = select(so+1, NULL, &wset, NULL, &tv);
		if ( r <= 0 ) break;
		ssended = sended;
		sf = (rq->flags & RQ_HAS_BANDWIDTH);
		if (send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, NULL, sf) )
		    so = -1;
		if ( rq->flags & RQ_HAS_BANDWIDTH) update_transfer_rate(rq, sended-ssended);
	    }
	    goto done;
	}
	/* there is something to read */
	if ( !obj->container ) {
	    struct	buff *new;
	    new = alloc_buff(CHUNK_SIZE);
	    if ( !new ) {
		my_log("Cant create container\n");
		change_state(obj, OBJ_READY);
		obj->flags |= FLAG_DEAD;
		goto error;
	    }
	    obj->container = new;
	}
	if ( !(answ_state.state & GOT_HDR) ) {
	    received+=r;
	    obj->size += r;
	    if ( attach_data(answer, r, obj->container) ) {
		my_log("attach_data\n");
		obj->flags |= FLAG_DEAD;
		change_state(obj, OBJ_READY);
		goto error;
	    }
	    if ( check_server_headers(&answ_state, obj, obj->container) ) {
		my_log("check_server_headers\n");
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
		continue;
	    }
	    if ( answ_state.state & GOT_HDR ) {
		send_hot_buff = obj->container;
		send_hot_pos  = 0;
		sended = 0;
		obj->flags|= answ_state.flags;
		obj->times = answ_state.times;
		if ( !obj->times.date ) obj->times.date = time(NULL);
		if ( answ_state.flags & ANSW_HAS_EXPIRES ) {
		    if ( obj->times.expires < obj->times.date ) {
			obj->flags |= ANSW_NO_STORE;
		    }
		}
		obj->status_code = answ_state.status_code;
		if ( obj->status_code != STATUS_OK )
			obj->flags |= FLAG_DEAD;
		if (!(obj->flags & ANSW_NO_STORE) )
			obj->flags &= ~ANSW_NO_CACHE;
		change_state(obj, OBJ_INPROGR);
		if ( TEST(obj->flags, ANSW_SHORT_CONTAINER) ) {
		    struct buff *last_buff;
		    while ( send_hot_buff ) {
			last_buff = send_hot_buff;
			if ( !send_hot_buff->data ) goto error;
			if ( writet(so, send_hot_buff->data, send_hot_buff->used, READ_ANSW_TIMEOUT) < 0)
			    goto error;
			sended += send_hot_buff->used;
			send_hot_buff->used = 0;
			send_hot_buff = send_hot_buff->next;
		    }
		    send_hot_buff = last_buff;
		} /* we flushed all what we read */
	    }
	} else {
	    if ( TEST(obj->flags, ANSW_SHORT_CONTAINER) ) {
		if ( TEST(rq->flags, RQ_HAS_BANDWIDTH) && (++pass)%2 )
		    SLOWDOWN ;
		if ( writet(so, answer, r, READ_ANSW_TIMEOUT) < 0 )
		    goto error;
		    received += r;
		    sended   += r;
		if ( TEST(rq->flags, RQ_HAS_BANDWIDTH))
			update_transfer_rate(rq, r);
		goto rcv_d;
	    }
	    /* store data in hot_buff */
	    if ( store_in_chain(answer, r, obj) ) {
		my_log("Can't store\n");
		obj->flags |= FLAG_DEAD;
		change_state(obj, OBJ_READY);
		goto error;
	    }
	    received += r;
	    obj->size += r;
	    change_state_notify(obj);
        rcv_d:;
	}
    }
error:
    my_log("fill_mem_obj: load error\n");
    if ( server_so != -1 ) close(server_so);
    if ( answer ) free(answer);
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( obj->status_code ) have_code = obj->status_code;
	else		    have_code = 555;

    if ( content_type = attr_value(obj->headers, "Content-Type") ) {
	char *p;
	strncpy(ctbuf, content_type, sizeof(ctbuf)-1);
        p = &ctbuf[0];
	ctbuf[sizeof(ctbuf)-1] = 0;
	while (*p) {
	    if ( isspace(*p) || *p==';' ) {
		*p = 0;
		break;
	    }
	    p++;
	}
	content_type = ctbuf;
    } else {
	content_type = "text/html";
    }

    log_access(delta_tv, &rq->client_sa,
    	"TCP_ERROR", have_code, received,
	meth, &rq->url, source, content_type,origin);
    DECR_WRITERS(obj);
    return;
done:
    obj->response_time = time(NULL);
    resident_size = calculate_resident_size(obj);
    my_log("loaded successfully: received: %d\n", received);

    /* if object too large remove it right now */
    if ( resident_size > maxresident ) {
	my_log("Obj is too large - remove it\n");
	obj->flags |= FLAG_DEAD;
    } else {
	obj->resident_size = resident_size;
	increase_hash_size(obj->hash_back, obj->resident_size);
    }
    if ( server_so != -1 ) close(server_so);
    if ( answer ) free(answer);
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    if ( obj->status_code ) have_code = obj->status_code;
	else		    have_code = 555;
    if ( content_type = attr_value(obj->headers, "Content-Type") ) {
	char *p;
	strncpy(ctbuf, content_type, sizeof(ctbuf)-1);
        p = &ctbuf[0];
	ctbuf[sizeof(ctbuf)-1] = 0;
	while (*p) {
	    if ( isspace(*p) || *p==';' ) {
		*p = 0;
		break;
	    }
	    p++;
	}
	content_type = ctbuf;
    } else {
	content_type = "text/html";
    }
    log_access(delta_tv, &rq->client_sa,
    	"TCP_MISS", have_code, received,
	meth, &rq->url, source, content_type,origin);
    DECR_WRITERS(obj);
    return;
}

int
continue_load(struct request *rq, int so, int server_so, struct mem_obj *obj)
{
int			received=0, sended=0, maxfd, pass=0, ssended, sf=0;
struct	buff		*send_hot_buff;
int			send_hot_pos;
fd_set			rset, wset;
struct	timeval		tv;
int			r;
char			*answer=NULL;

    received = obj->size;
    send_hot_buff = obj->container;
    send_hot_pos = 0;
    if ( !(obj->flags & ANSW_NO_STORE) )
	obj->flags &= ~ANSW_NO_CACHE;
    answer = xmalloc(ANSW_SIZE+1, "continue_load1");
    if ( ! answer )  {
	my_log("continue_load: no mem\n");
	change_state(obj, OBJ_READY);
	obj->flags |= FLAG_DEAD;
	goto error;
    }
    if ( fcntl(so, F_SETFL, fcntl(so, F_GETFL, 0)|O_NONBLOCK) )
	my_log("fcntl: %s\n", strerror(errno));
    while(1) {
	FD_ZERO(&rset); FD_ZERO(&wset);
	FD_SET(server_so, &rset);
	if ( server_so > so ) maxfd = server_so;
	    else	      maxfd = so;
	if ( (obj->state == OBJ_INPROGR) && (received > sended) && (so != -1) ) {
	    if ( (++pass)%2 && TEST(rq->flags, RQ_HAS_BANDWIDTH) ) {
		r = group_traffic_load(inet_to_group(&rq->client_sa.sin_addr));
		tv.tv_sec = 0;tv.tv_usec = 0;
		if ( r < 75 ) /* low load */
		    goto ignore_bw_overload;
		else if ( r < 95 ) /* start to slow down */
		    tv.tv_usec = 250;
		else if ( r < 100 )
		    tv.tv_usec = 500;
		else
		    tv.tv_sec = MIN(2, r/100);
		r = select(maxfd+1, &rset, NULL, NULL, &tv);
		if ( r < 0 ) goto error;
		if ( r== 0 ) continue;
		goto read_s;
	    }
	ignore_bw_overload:
	    FD_SET(so, &wset);
	}
	tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
        r = select(maxfd+1, &rset, &wset, NULL, &tv);
	if ( r < 0 ) {
	    my_log("select: %s\n", strerror(errno));
	    obj->flags |= FLAG_DEAD;
	    change_state(obj, OBJ_READY);
	    goto error;
	}
	if ( r == 0 ) {
	    my_log("select: timed out\n");
	    obj->flags |= FLAG_DEAD;
	    change_state(obj, OBJ_READY);
	    goto error;
	}
	if ( (so != -1) && FD_ISSET(so, &wset) ) {
	   r--;
	   if ( send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, NULL, 0) ) {
		so = -1;
	   }
	}
	if ( so == -1 ) {
	    lock_obj(obj);
	    if ( obj->refs <= 1 ) /* we are only who refers to this obj */ {
		my_log("we alone: %d\n", obj->refs);
		obj->state = OBJ_READY;
		obj->flags |= FLAG_DEAD;
	    }
	    unlock_obj(obj);
	    my_log("fill_mem_obj: Send failed: %s\n", strerror(errno));
	    if ( obj->state == OBJ_READY ) {
		change_state_notify(obj);
		goto error;	/* no one heard */
	    }
	    my_log("Continue to load - we are not alone\n");
	}
    read_s:;
	if ( !FD_ISSET(server_so, &rset) ) {
	    if ( r ) {
		/* this is solaris 2.6 select bug(?) workaround */
		my_log("select bug(?)\n");
		obj->state =  OBJ_READY;
		obj->flags |= FLAG_DEAD;
		change_state_notify(obj);
		goto error;
	    }
	    continue;
	}
	r = read(server_so, answer, ANSW_SIZE);
	if ( r < 0  ) {
	    if ( errno == EAGAIN)  {
		my_log("Hmm in continue load\n");
		continue;
	    }
	    my_log("fill_mem_obj: Read failed: %s\n", strerror(errno));
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
		if ( TEST(rq->flags, RQ_HAS_BANDWIDTH) && (++pass)%2 )
		    SLOWDOWN ;
		FD_ZERO(&wset);
		FD_SET(so, &wset);
		tv.tv_sec = READ_ANSW_TIMEOUT;tv.tv_usec = 0;
        	r = select(so+1, NULL, &wset, NULL, &tv);
		if ( r <= 0 ) break;
		ssended = sended;
		if (TEST(rq->flags, RQ_HAS_BANDWIDTH)) sf = RQ_HAS_BANDWIDTH;
		if (send_data_from_buff_no_wait(so, &send_hot_buff, &send_hot_pos, &sended, NULL, sf) )
		    so = -1;
		if ( TEST(rq->flags, RQ_HAS_BANDWIDTH)) update_transfer_rate(rq, sended-ssended);
	    }
	    goto done;
	}
	/* store data in hot_buff */
	if ( store_in_chain(answer, r, obj) ) {
	    my_log("Can't store\n");
	    obj->flags |= FLAG_DEAD;
	    change_state(obj, OBJ_READY);
	    goto error;
	   }
	received += r;
	obj->size += r;
	change_state_notify(obj);
    }
done:
    obj->resident_size = calculate_resident_size(obj);
	/*received + sizeof(*obj)+(obj->container?obj->container->used:0);*/
    increase_hash_size(obj->hash_back, obj->resident_size);
error:
    if (answer) free(answer);
    return(0);
}

int
send_data_from_buff(int so, struct buff **hot, int *pos, int *sended)
{
int		r, to_send;
struct	buff	*b = *hot;
fd_set		wset;
struct	timeval tv;

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
	my_log("What the fuck? to_send = %d\n", to_send);
	return(-1);
    }
    FD_ZERO(&wset);
    FD_SET(so, &wset);
    tv.tv_sec = READ_ANSW_TIMEOUT; tv.tv_usec = 0 ;

    r = select(so+1, NULL, &wset, NULL, &tv);
    if ( r <= 0 )
	return(r);
    r = write(so, b->data+*pos, to_send);
    if ((r < 0) && (errno == EWOULDBLOCK) ) return(0);
    if ( r < 0 )
	return(r);
    *pos += r; *sended += r;
    goto do_it;
}

int
send_data_from_buff_no_wait(int so, struct buff **hot, int *pos, int *sended, int *rest_in_chunk, int flags)
{
int		r, to_send, cz_here, faked_sent, chunk_size;
struct	buff	*b = *hot;
char		*cb, *ce, *cd;
char		ch_sz[16];	/* buffer to collect chunk size	*/

    if ( !*hot )
	return(0);
    if ( TEST(flags, RQ_CONVERT_FROM_CHUNKED) && !rest_in_chunk ) {
	my_log("Check yourself: sending chunked in send_data_from_buff\n");
	return(-1);
    }
    if ( TEST(flags, RQ_CONVERT_FROM_CHUNKED ) )
	goto send_chunked;

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
	my_log("What the fuck? to_send = %d\n", to_send);
	return(-1);
    }
    /** send no more than 512 bytes at once if we control bandwith
     *	 because bandwidth control will be difficult if we will send by large
     *	 chunks
     *  send no more than 2048 bytes anyway. large writes apply high load on system
     **/
    if ( TEST(flags, RQ_HAS_BANDWIDTH) ) to_send = MIN(to_send, 512);
	else				 to_send = MIN(to_send, 2048);

    r = write(so, b->data+*pos, to_send);
    if ((r < 0) && (errno == EWOULDBLOCK) ) return(0);
    if ( TEST(flags, RQ_HAS_BANDWIDTH) && (r>0) ) {
	*pos += r; *sended += r;
	return(0);
    }
    if ( r < 0 )
	return(r);
    *pos += r; *sended += r;
    goto do_it;

send_chunked:
    faked_sent = 0;
do_it_chunked:
    if ( !*rest_in_chunk ) {
	/* we stay on a new chunk,extract current chunk size */
	cz_here = FALSE;
	cd = ch_sz;
	*cd = 0;
    find_chunk_size:
	cb = b->data + *pos;
	ce = b->data + b->used;
    find_chunk_size_again:
	while( cb < ce ) {
	    if ( cd - ch_sz >= sizeof(ch_sz) ) {
		/* ch_sz must not be overflowed */
		return(-1);
	    }
	    if ( strstr(ch_sz, "\r\n") ) {
		/* the end of chunk size */
		cz_here = TRUE;
		break;
	    }
	    *cd++ = *cb++;
	    *cd=0;
	    faked_sent++;
	}
	if ( cz_here ) {
	    my_log("Got chunk size: %s\n", ch_sz);
	    *hot = b;
	    *pos = cb - b->data;
	    *sended += faked_sent;
	    cd = ch_sz;
	    r = sscanf(ch_sz, "%x", &chunk_size);
	    if ( r != 1)
		return(-1);
	    if ( !chunk_size ) {
		/* it is last */
		*rest_in_chunk = 0;
		return(0);
	    }
	    *rest_in_chunk = chunk_size;
	    return(0);
	} else {
	    if ( !b->next )
		return(0);
	    b = b->next;
	    cb = b->data;
	    ce = b->data + b->used;
	    goto find_chunk_size_again;
	}
    } else {
	/* send from current position till the minimum(chunksize,b->used) */
	to_send = MIN(b->used - *pos, *rest_in_chunk);
	if ( !to_send ) {
	    /* this canbe only end of buffer */
	    if ( !b->next ) return(0);
	    *hot = b->next;
	    b = b->next;
	    *pos = 0;
	    goto do_it_chunked;
 	}
   	if ( to_send < 0 ) {
	    my_log("What the fuck? to_send = %d\n", to_send);
	    return(-1);
	}
	if ( TEST(flags, RQ_HAS_BANDWIDTH) ) to_send = MIN(to_send, 512);
	   else				     to_send = MIN(to_send, 2048);
	r = write(so, b->data+*pos, to_send);
	if ((r < 0) && (errno == EWOULDBLOCK) ) return(0);
	if ( TEST(flags, RQ_HAS_BANDWIDTH) && (r>0) ) {
	    *pos += r; *sended += r; *rest_in_chunk -= r;
	    return(0);
	}
	if ( r < 0 )
	    return(r);
        *pos += r; *sended += r; *rest_in_chunk -= r;
	if ( !*rest_in_chunk ) {
	    /* we stay on the end of chunk */
	    /* skip CRLF, which can be in  */
	    /* this or in next buff	   */
	    if ( *pos+2 <= b->used ) {
		/* it is in this buff	*/
		*pos+=2;
		faked_sent+=2;
	    } else {
		/* This can happens in only  case: CR|LF */
		if ( !b->next ) /* this is fatal... */
		    return(0);
		faked_sent+=2;
		*pos = *pos+2-b->used;
		b = b->next;
		if ( *pos > b->used ) {
		    /* this is fatal */
		    return (-1);
		}
		goto do_it_chunked;
	    }
	}
	goto do_it_chunked;
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

void
lock_obj_state(struct mem_obj *obj)
{
    pthread_mutex_lock(&obj->state_lock);
}

void
unlock_obj_state(struct mem_obj *obj)
{
    pthread_mutex_unlock(&obj->state_lock);
}

void
lock_decision(struct mem_obj *obj)
{
    pthread_mutex_lock(&obj->decision_lock);
}

void
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

void
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
	free(buff->data);
	free(buff);
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
    free(hdr);
    return;
}

int
is_attr(struct av *av, char *attr)
{
    return(!strncmp(av->attr, attr, strlen(attr)));
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
    buf = xmalloc(strlen(attr) + 1 + strlen(val) + 3,"send_av_pair");
    if ( !buf ) {
	my_log("No mem at send_av_pair\n");
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
	buf = xmalloc(strlen(attr) + 1 + strlen(val) + 3,"send_av_pair");
    else
	buf = xmalloc(3,"send_av_pair");
    if ( !buf ) {
	my_log("No mem at send_av_pair\n");
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
/*    my_log("apparent_age: %d\n", apparent_age);
    my_log("corrected_received_age: %d\n", corrected_received_age);
    my_log("responce_delay: %d\n", response_delay);
    my_log("corrected_initial_age: %d\n", corrected_initial_age);
    my_log("resident_time: %d\n", resident_time);
    my_log("current_age: %d\n", current_age);*/
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
srv_connect(int client_so, struct url *url, struct request *rq)
{
int 			server_so = -1, r;
struct	sockaddr_in 	server_sa;

    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(client_so, "Can't create socket", strerror(errno), ERR_INTERNAL, rq);
	return(-1);
    }
    bind_server_so(server_so);
    if ( str_to_sa(url->host, (struct sockaddr*)&server_sa) ) {
	say_bad_request(client_so, "Can't translate name to address", url->host, ERR_DNS_ERR, rq);
	close(server_so);
	return(-1);
    }
    server_sa.sin_port = htons(url->port);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	say_bad_request(client_so, "Can't connect to host.", strerror(errno), ERR_TRANSFER, rq);
	close(server_so);
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
    server_sa.sin_port = htons(parent_port);
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(client_so, "Can't create socket", strerror(errno), ERR_INTERNAL, rq);
	return(-1);
    }
    bind_server_so(server_so);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	say_bad_request(client_so, "Can't connect to parent", strerror(errno), ERR_TRANSFER, rq);
	close(server_so);
	return(-1);
    }
    return(server_so);
}

int
peer_connect(int client_so, struct sockaddr_in *peer_sa, struct request *rq)
{
int 			server_so = -1, r;
struct	sockaddr_in 	server_sa;
struct	sockaddr_in	dst_sa;

    my_log("Connecting to peer\n");
    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(client_so, "Can't create socket", strerror(errno), ERR_INTERNAL, rq);
	return(-1);
    }
    bind_server_so(server_so);
    r = connect(server_so, (struct sockaddr*)peer_sa, sizeof(*peer_sa));
    if ( r == -1 ) {
	say_bad_request(client_so, "Can't connect to parent", strerror(errno), ERR_TRANSFER, rq);
	close(server_so);
	return(-1);
    }
    return(server_so);
}


int
fill_server_request(struct request *rq, struct buff * to_server_request)
{
struct	av	*av;
int		r;

    av = rq->av_pairs;
    r = 0;
    while( av && !r ) {
	r = attach_data(av->attr, strlen(av->attr), to_server_request);
	if ( !r )
	    r = attach_data(" ", 1, to_server_request);
	if ( !r )
	    r = attach_data(av->val, strlen(av->val), to_server_request);
	if ( !r )
	    r = attach_data("\r\n", 2, to_server_request);
	av = av->next;
    }

    if ( !r && insert_x_forwarded_for ) {
	char	*ip_addr = my_inet_ntoa(&rq->client_sa);
	if ( ip_addr ) {
	    r = attach_data("X-Forwarded-For: ", strlen("X-Forwarded-For: "),
			to_server_request);
	    if ( !r )
	        r = attach_data(ip_addr, strlen(ip_addr), to_server_request);
	    if ( !r )
		r = attach_data("\r\n", 2, to_server_request);
	    xfree(ip_addr);
	}
    }
    if ( !r && insert_via )
	r = attach_data("Via: Oops 0.0alpha1\r\n",
	    strlen("Via: Oops 0.0alpha1\r\n"), to_server_request);

    if ( !r )
	r = attach_data("\r\n", 2, to_server_request);
    return(r);
}

char*
build_direct_request(char *meth, struct url *url, char *headers, struct request *rq)
{
int	rlen, authorization_done = FALSE;
char	*answer = NULL, *fav=NULL;
struct	buff 	*tmpbuff;
struct	av	*av;

    tmpbuff = alloc_buff(CHUNK_SIZE);
    if ( !tmpbuff ) return(NULL);
    rlen = strlen(meth) + 1/*sp*/ + strlen(url->path) + 1/*sp*/ +
           strlen(url->httpv) + 2/* \r\n */;
    answer = xmalloc(ROUND(rlen+1,CHUNK_SIZE), "send_not_cached"); /* here answer is actually *request* buffer */
    if ( !answer )
	goto fail;
    sprintf(answer, "%s %s %s\r\n", meth, url->path, url->httpv);
    if ( attach_data(answer, strlen(answer), tmpbuff) )
	goto fail;
    av = rq->av_pairs;
    while ( av ) {
	if ( is_attr(av, "Proxy-Connection:") )
	    goto do_not_insert;
	if ( is_attr(av, "Connection:") )
	    goto do_not_insert;
	if ( (fav=format_av_pair(av->attr, av->val)) ) {
	    if ( is_attr(av, "Authorization:") ) {
		/* we prefer "in-header"-supplied Authorization: */
		authorization_done = TRUE;
	    }
	    if ( attach_data(fav, strlen(fav), tmpbuff) )
		goto fail;
	    free(fav);fav = NULL;
	}
  do_not_insert:
	av = av->next;
    }
    if ( rq->url.login && !authorization_done ) {
	char	log_pass[1024], *b64e;
	strncpy(log_pass, rq->url.login, sizeof(log_pass)-1);
	strncat(log_pass, ":", sizeof(log_pass) - strlen(log_pass) - 1);
	if ( rq->url.password )
	    strncat(log_pass, rq->url.password, sizeof(log_pass) - strlen(log_pass) - 1);
	b64e = base64_encode(log_pass);
	if ( b64e ) {
	    strncpy(log_pass, "Basic ", sizeof(log_pass));
	    strncat(log_pass, b64e, sizeof(log_pass) - strlen(log_pass) -1 );
	    xfree(b64e);
	    fav = format_av_pair("Authorization:", log_pass);
	    if ( fav ) {
		if ( attach_data(fav, strlen(fav), tmpbuff) )
		    goto fail;
		xfree(fav); fav = NULL;
	    }
	}
    }
    if ( (fav=format_av_pair("Connection:", "close")) ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
	free(fav);fav = NULL;
    }
    if ( insert_via && (fav = format_av_pair("Via:","Oops 0.1")) ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
	free(fav);fav = NULL;
    }
    /* CRLF  */
    if ( attach_data("\r\n", 2, tmpbuff) )
	goto fail;
    if ( attach_data("", 1, tmpbuff) )
	goto fail;
    if (answer) free(answer);
    answer = tmpbuff->data;
    tmpbuff->data = NULL;
    free_chain(tmpbuff);
    return answer;
fail:
    if (fav) free(fav);
    if (tmpbuff) free_chain(tmpbuff);
    if (answer) free(answer);
    return NULL;
}

char*
build_parent_request(char *meth, struct url *url, char *headers, struct request *rq)
{
int	rlen;
char	*answer, *fav=NULL;
struct	buff 	*tmpbuff;
struct	av	*av;

    if ( TEST(rq->flags, RQ_GO_DIRECT) ) {
	return(build_direct_request(meth, url, headers, rq));
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
	strlen(url->httpv) + 2/* \r\n */;

    answer = xmalloc(ROUND(rlen+1, CHUNK_SIZE), "send_not_cached"); /* here answer is actually *request* buffer */
    if ( !answer )
	return NULL;

    if ( !strcasecmp(url->proto, "http" ) ) {
	sprintf(answer, "%s %s://%s:%d%s %s\r\n", meth, url->proto, url->host,
    	    url->port, url->path, url->httpv);
    } else {
	sprintf(answer, "%s %s://%s%s %s\r\n", meth, url->proto, url->host,
    	    url->path, url->httpv);
    }
    if ( attach_data(answer, strlen(answer), tmpbuff) )
	goto fail;
    av = rq->av_pairs;
    while ( av ) {
	if ( is_attr(av, "Connection:") )
	    goto do_not_insert;
	if ( is_attr(av, "Proxy-Connection:") )
	    goto do_not_insert;
	if ( (fav=format_av_pair(av->attr, av->val)) ) {
	    if ( attach_data(fav, strlen(fav), tmpbuff) )
		goto fail;
	    free(fav);fav = NULL;
	}
  do_not_insert:
	av = av->next;
    }
    if ( (fav=format_av_pair("Connection:", "close")) ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
	free(fav);fav = NULL;
    }
    if ( insert_via && (fav = format_av_pair("Via:","Oops 0.1")) ) {
	if ( attach_data(fav, strlen(fav), tmpbuff) )
	    goto fail;
	free(fav);fav = NULL;
    }
    /* CRLF  */
    if ( attach_data("\r\n", 2, tmpbuff) )
	goto fail;
    if ( attach_data("", 1, tmpbuff) )
	goto fail;
    if ( answer ) free(answer);
    answer = tmpbuff->data;
    tmpbuff->data = NULL;
    free_chain(tmpbuff);
    return answer;
fail:
    if (fav) free(fav);
    if (tmpbuff) free_chain(tmpbuff);
    if (answer) free(answer);
    return NULL;
}

