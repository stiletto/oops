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

extern	char	icons_host[MAXPATHLEN];
extern	char	icons_path[MAXPATHLEN];
extern	char	icons_port[64];
extern	int	no_direct_connections;

static	int	add_nlst_entry(char *, void *);
static	void	ftp_put(int, struct request *, char*, struct ftp_r *);
static	int	get_server_greeting(struct ftp_r *);
static	char	*in_nlst(char *, struct string_list *);
static	int	list_parser(char *, void *);
static	int	parse_answ(struct buff*, int*, int (*f)(char *, void*), void *);
static	int	parse_ftp_srv_answ(struct buff *, int *, struct ftp_r *);
static	int	recv_ftp_data(struct ftp_r *);
static	int	recv_ftp_list(struct ftp_r *);
static	int	recv_ftp_nlst(struct ftp_r *req);
static	int	request_list(struct ftp_r *ftp_r);
static	void	send_401_answer(int, struct request *);
static	void	send_ftp_err(struct ftp_r *);
static	int	send_http_header(int, char *, int, struct mem_obj *, struct ftp_r *);
static	int	send_user_pass_type(struct ftp_r *);
static	int	server_connect(struct ftp_r *);
static	int	try_cwd(struct ftp_r *);
static	int	try_passive(struct ftp_r *);
static	int	try_port(struct ftp_r *);
static	int	try_rest(struct ftp_r *);
static	int	try_retr(struct ftp_r *);
static	int	try_size(struct ftp_r *);


void
ftp_fill_mem_obj(int so, struct request *rq,
		 char *headers, struct mem_obj *obj)
{
int			server_so = -1;
int			r, source_type, rc;
struct	url		*url = &rq->url;
struct	ftp_r		ftp_request;
struct  sockaddr_in     dst_sa, peer_sa;
struct timeval		start_tv, stop_tv;
int			delta_tv, pathlen = 0;
hash_entry_t            *he = NULL;

    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "ftp_fill_mem_obj(): Ftp...\n");
    bzero(&ftp_request, sizeof(ftp_request));
    ftp_request.type	= "text/html";
    gettimeofday(&start_tv, NULL);
    ftp_request.client	= so;
    ftp_request.obj	= obj;
    ftp_request.request = rq;
    ftp_request.control = -1;
    ftp_request.data    = -1;
    if ( rq->url.login && !rq->url.password ) {
	char *authorization, *data;
	/* there must be Authorization header */
	authorization = attr_value(rq->av_pairs, "Authorization");
	if ( !authorization ) {
	create_aur:;
	    /* create 401 answer */
	    send_401_answer(so, rq);
	    goto done;
	}
        if ( !strncasecmp(authorization, "Basic", 5 ) ) {
	    char  *up=NULL, *u, *p;

	    data = authorization + 5;
	    while ( *data && IS_SPACE(*data) ) data++;
            if ( *data ) up = base64_decode(data);
	    if ( up ) {
                /* up = username:password */
                u = up;
                p = strchr(up, ':');
                if ( p ) {
		    *p=0; p++;
		} else {
		    free(up);
		    goto create_aur;
		}
		if ( strcmp(rq->url.login,up) ) {
		    free(up);
		    goto create_aur;
		}
		rq->url.password = strdup(p);
                free(up);
		goto have_p;
            } /* up != NULL */
	    goto create_aur;
        }
	/* not Basic */
        /* we do not support any schemes except Basic */
	goto create_aur;
    }
have_p:
    if ( parent_port ) {
        bzero(&dst_sa, sizeof(dst_sa));
	if ( local_networks_sorted && local_networks_sorted_counter ) {
	    if (str_to_sa(rq->url.host, (struct sockaddr*)&dst_sa) )
		bzero(&dst_sa, sizeof(dst_sa));
	}
	if ( !is_local_dom(rq->url.host) && !is_local_net(&dst_sa) ) {
	    if ( rq->meth != METH_GET )
		send_not_cached(so, rq, headers);
	      else
		fill_mem_obj(so, rq, headers, obj, 0, 0, NULL);
	    return;
	}
    }

    if ( peers && (icp_so != -1) && (rq->meth == METH_GET) && !is_local_dom(rq->url.host) ) {
	struct icp_queue_elem *new_qe;
	struct timeval tv = start_tv;

	bzero((void*)&peer_sa, sizeof(peer_sa));
	my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "ftp_fill_mem_obj(): sending icp_requests\n");
	new_qe = (struct icp_queue_elem*)xmalloc(sizeof(*new_qe),"ftp_fill_mem_obj(): icp_q_e");
	if ( !new_qe ) goto icp_failed;
	bzero(new_qe, sizeof(*new_qe));
	pthread_cond_init(&new_qe->icpr_cond, NULL);
	pthread_mutex_init(&new_qe->icpr_mutex, NULL);
	new_qe->waitors = 1;
	/* XXX make rq_n generation more random */
	new_qe->rq_n    = tv.tv_sec+tv.tv_usec;
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
	    if ( pthread_cond_timedwait(&new_qe->icpr_cond,&new_qe->icpr_mutex,&ts) ) {
		/* failed */
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "ftp_fill_mem_obj(): icp timedout\n");
	    } else {
		/* success */
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "ftp_fill_mem_obj(): icp_success\n");
	    }
            if ( he ) {
                rc = delete_hash_entry(icp_requests_hash, he, NULL);
                if ( rc != 0 )
                        abort();
            }
	    new_qe->rq_n = 0;
	    pthread_mutex_unlock(&new_qe->icpr_mutex);
	    if ( new_qe->status ) {
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "ftp_fill_mem_obj(): Fetch from neighbour\n");
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
		my_xlog(OOPS_LOG_HTTP|OOPS_LOG_DBG, "ftp_fill_mem_obj(): Direct\n");
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
	goto icp_failed;
 server_connect_done:;
	if ( server_so < 0 )
	    goto error;
	/* fetch from parent */
	fill_mem_obj(so, rq, headers, obj, server_so, source_type, &peer_sa);
	return;

 icp_failed:;
        SET(rq->flags, RQ_SERVED_DIRECT);
    } /* all icp things */
    if ( *(url->path+1) == '~' )
	ftp_request.dehtml_path = dehtmlize(url->path+1);
      else {
	if ( !strncasecmp(url->path+1, "%7e", 3) ) {
	    ftp_request.dehtml_path = dehtmlize(url->path+1);
	}
	  else
	    ftp_request.dehtml_path = dehtmlize(url->path);
    }
    ftp_request.server_log  = alloc_buff(CHUNK_SIZE);
    ftp_request.container = alloc_buff(CHUNK_SIZE);
    if ( ! ftp_request.container )
	   goto error;
    server_so = server_connect(&ftp_request);
    if ( server_so == -1 ) goto error1;
    ftp_request.control = server_so;

    r = get_server_greeting(&ftp_request);	if ( r == -1 ) goto error;

    r = send_user_pass_type(&ftp_request);	if ( r == -1 ) goto error;

    r = try_passive(&ftp_request);		if ( r == -1 ) {
	r = try_port(&ftp_request);		if ( r == -1 ) goto error;
	ftp_request.mode = MODE_PORT;
    }

    if ( rq->meth == METH_PUT ) {
	ftp_put(so, rq, headers, &ftp_request);
	goto done;
    }

    /* if last char is '/', then we can go directly to cwd */
    if ( ftp_request.dehtml_path ) pathlen = strlen(ftp_request.dehtml_path);
    if ( pathlen > 0 && ftp_request.dehtml_path[pathlen-1] == '/' )
	goto cwdtopath;

    r = try_size(&ftp_request);
    if ( TEST(rq->flags, RQ_HAVE_RANGE)
	 && ( rq->range_from >= 0 )
	 && ( rq->range_to == -1 ) ) {
	/* we can try REST */
	r = try_rest(&ftp_request);
	if ( r >= 0 ) {
	    r = try_retr(&ftp_request);
	    if ( r == -1 ) goto error;
	    r = recv_ftp_data(&ftp_request);
	    if ( r ) goto error;
	    goto error1;	/* because we never save part of document */
	}
    }
    r = try_retr(&ftp_request);
    if ( r == -1 ) {
cwdtopath:
	r = try_cwd(&ftp_request);
	if ( r == -1 ) {
	    goto error;
	} else {
	    ftp_request.size = 0 ;
	    r = recv_ftp_nlst(&ftp_request);
	    if ( r == -1 )
		goto error;
	    /* now we must build data connection again */
	    ftp_request.mode = MODE_PASV;
    	    r = try_passive(&ftp_request);	if ( r == -1 ) {
		r = try_port(&ftp_request);	if ( r == -1 ) goto error;
		ftp_request.mode = MODE_PORT;
	    }
	    r = request_list(&ftp_request);
	    if ( r ) goto error;
	    r = recv_ftp_list(&ftp_request);
	    if ( r ) goto error;
	}
    } else {
	r = recv_ftp_data(&ftp_request);
	if ( r ) goto error;
    }

    goto done;
error:
    send_ftp_err(&ftp_request);
error1:
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    IF_STRDUP(rq->tag, "TCP_MISS");
    IF_STRDUP(rq->hierarchy, "DIRECT");
    IF_STRDUP(rq->c_type, ftp_request.type);
    IF_STRDUP(rq->source, rq->url.host);
    rq->code = 555;
    rq->received = ftp_request.received;
    log_access(delta_tv, rq, obj);
    obj->flags |= FLAG_DEAD;
    goto free_ftp_resources;
done:
    gettimeofday(&stop_tv, NULL);
    delta_tv = (stop_tv.tv_sec-start_tv.tv_sec)*1000 +
	(stop_tv.tv_usec-start_tv.tv_usec)/1000;
    IF_STRDUP(rq->tag, "TCP_MISS");
    rq->code = 200;
    rq->received = ftp_request.received;
    rq->hierarchy = strdup("DIRECT");
    rq->c_type = strdup(ftp_request.type);
    rq->source = strdup(rq->url.host);
    obj->httpv_major = 1;
    obj->httpv_minor = 0; /* this is 1.0 doc */
    log_access(delta_tv, rq, obj);
    /* when we shall not cache ftp answer */
    if ( rq->url.login ) obj->flags |= FLAG_DEAD;
    if ( ftp_request.file_dir==FTP_TYPE_FILE &&
       (!ftp_request.size ||				/* unknown SIZE		*/
	 (ftp_request.received < ftp_request.size)))	/* received incomplete	*/
		obj->flags |= FLAG_DEAD;

free_ftp_resources:
    if ( server_so != -1 ) CLOSE(server_so);
    if ( ftp_request.data != -1 ) close(ftp_request.data);
    if ( ftp_request.control != -1 ) close(ftp_request.control);
    if ( ftp_request.dehtml_path ) free(ftp_request.dehtml_path);
    if ( ftp_request.server_path ) free(ftp_request.server_path);
    if ( ftp_request.server_log ) free_chain(ftp_request.server_log);
    if ( ftp_request.nlst ) free_string_list(ftp_request.nlst);
    if ( ftp_request.container ) free_container(ftp_request.container);
    obj->readers = obj->writers = 0;
    obj->state = OBJ_READY;
    obj->times.date = obj->request_time = obj->response_time = global_sec_timer;
    obj->times.expires = obj->times.date + ftp_expire_value ;
    obj->flags |= ANSW_HAS_EXPIRES;
    obj->doc_type = FTP_DOC;
    obj->size = calculate_container_datalen(obj->container);
    obj->resident_size = calculate_resident_size(obj);
    increase_hash_size(obj->hash_back, obj->resident_size);
    obj->flags &= ~ANSW_NO_CACHE;	/* it can be cached if it is good (not dead */
}

static int
recv_ftp_data(struct ftp_r *ftp_r)
{
int		client = ftp_r->client;
int		data = ftp_r->data;
struct		mem_obj *obj=ftp_r->obj;
char		buf[1024];
int		r, read_size, pass = 0;
socklen_t	sa_len;
struct		sockaddr_in sa;
struct		request	*rq = ftp_r->request;
char		*mime_type;

    if ( TEST(ftp_r->ftp_r_flags, PARTIAL_ANSWER) )
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_data(): receiving partial data.\n");
    else
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_data(): receiving data.\n");

    ftp_r->file_dir = FTP_TYPE_FILE;
    if ( !ftp_r->size || (ftp_r->size >= maxresident) || (ftp_r->size < minresident) )
    		SET(obj->flags, FLAG_DEAD);
    if ( ftp_r->mode == MODE_PORT ) {
	sa_len = sizeof(sa);
	r = -1;
	if ( wait_for_read(data, 10*1000) )
	    r = accept(data, (struct sockaddr*)&sa, &sa_len);
	close(data); ftp_r->data = -1;
	if ( r < 0 ) return(r);
	data = ftp_r->data = r;
    }
    mime_type = lookup_mime_type(ftp_r->obj->url.path);
    obj->content_length = ftp_r->size;
    ftp_r->type = mime_type;
    if ( !obj->container ) {
	obj->container = alloc_buff(CHUNK_SIZE);
        if ( ! obj->container )
	   return(-1);
	obj->hot_buff = obj->container;
    } else {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_data(): Something wrong rcv_ftp_list: container already allocated.\n");
	return(-1);
    }
    r = send_http_header(client, mime_type, ftp_r->size, ftp_r->obj, ftp_r);
    if ( r < 0 ) return(r);
    ftp_r->received = 0;
    read_size = (TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW))?
    		(MIN(512,(sizeof(buf)-1))):
		(sizeof(buf)-1);
    if (TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW)) 
    	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_data(): Slow down request.\n");
    while((r = readt(data, buf, read_size, READ_ANSW_TIMEOUT)) > 0) {
	ftp_r->received += r;
	ftp_r->request->doc_received += r;
	buf[r] = 0;
	if (TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW) && ((++pass)%2) )
			SLOWDOWN ;
	if ( rq->sess_bw )
			SLOWDOWN_SESS ;
	if ( (writet(client, buf, r, READ_ANSW_TIMEOUT) < 0) &&
	      !FORCE_COMPLETION(obj) ) {
	    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_data(): Ftp aborted.\n");
	    return(-1);
	}
	ftp_r->request->doc_sent += r;
	if (TEST(rq->flags, RQ_HAS_BANDWIDTH|RQ_HAVE_PER_IP_BW)) update_transfer_rate(rq, r);
	if (rq->sess_bw) update_sess_transfer_rate(rq, r);
	if ( obj && !TEST(obj->flags, FLAG_DEAD) ) {
		store_in_chain(buf, r, obj);
		obj->size += r;
	}
    }
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_data(): Data connection closed.\n");
    return(0);
}


static int
recv_ftp_nlst(struct ftp_r *req)
{
char			buf[160];
int			r, received = 0, checked, r_code;
socklen_t		sa_len;
int			data = req->data;
char			*tmpbuf = NULL;
struct  sockaddr_in 	sa;
struct	buff		*nlst_buff = NULL;
struct	buff		*resp_buff = NULL;
int			server_so = req->control;
char			answer[ANSW_SIZE+1];
time_t			started;

    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_nlst(): receiving nlst.\n");

    if ( req->mode == MODE_PORT ) {
	sa_len = sizeof(sa);
	r = -1;
	if ( wait_for_read(data, 10*1000) )
	    r = accept(data, (struct sockaddr*)&sa, &sa_len);
        close(data); req->data = -1;
	if ( r < 0 ) return(r);
	data = req->data = r;
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG,"recv_ftp_nlst(): recv_nlst: Accepted.\n");
    }
    nlst_buff = alloc_buff(CHUNK_SIZE);
    if ( !nlst_buff ) {
	close(data);req->data = -1;
	return(-1);
    }
    req->received = 0;
    while((r = readt(data, buf, sizeof(buf)-1, READ_ANSW_TIMEOUT)) > 0) {
	req->received += r;
	buf[r] = 0;
	attach_data(buf, r, nlst_buff);
	parse_answ(nlst_buff, &received, &add_nlst_entry, (void*)req);
    }
    if ( r < 0 ) my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_nlst(): Read list: %m\n");
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_nlst(): Data connection closed.\n");
    resp_buff = alloc_buff(CHUNK_SIZE);
    checked = 0;
    r = -1;
    started = time(NULL);
    r=0;
    goto done;
read_srv:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( !r ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_nlst(): Server closed connection too early in ftp_fill_mem.\n");
	goto wait_code;
    }
    if ( r == -2 ) {
	/* read timed put */
        if ( time(NULL) - started >= 10*60 ) {
	    /* it is completely timed out */
	    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_nlst(): Timeout reading from server in ftp_fill_mem.\n");
	    goto error;
        }
	goto read_srv;
    }
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_nlst(): Error reading from server in ftp_fill_mem.\n");
	goto error;
    }
    /* wait for for '2xx '	*/
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "recv_ftp_nlst(): No space at ftp_fill_mem.\n");
	goto error;
    }
wait_code:
    if ( resp_buff ) while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, req)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "recv_ftp_nlst(): Some fatal error at nlst.\n");
	    r = -1;
	    goto error;
	}
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_nlst(): Server code: %d\n", r_code);
	r_code = r_code/100;
	if ( r_code == 2 )
	    {r = 0;  goto done;}
	if ( r_code == 3 )
	    {r = 0;  goto done;}
	if ( r_code >= 4 )
	    {r = -1; goto done;}
    }
    goto read_srv;
error:;
done:;
    if ( tmpbuf ) free(tmpbuf);
    if ( nlst_buff ) free_container(nlst_buff);
    if ( resp_buff ) free_chain(resp_buff);
    close(data);req->data = -1;
    return(r);
}


static int
recv_ftp_list(struct ftp_r *req)
{
char		buf[160];
int		r, received = 0, rc = 0, len;
socklen_t	sa_len;
int		client = req->client;
int		data = req->data;
struct		mem_obj *obj = req->obj;
char		*tmpbuf = NULL, *pTmp;
struct		sockaddr_in sa;
struct		url url = req->request->url;

    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_list(): Receiving list.\n");

    req->file_dir = FTP_TYPE_DIR ;
    if ( req->mode == MODE_PORT ) {
	sa_len = sizeof(sa);
	r = -1;
	if ( wait_for_read(data, 10*1000) )
	    r = accept(data, (struct sockaddr*)&sa, &sa_len);
        close(data); req->data = -1;
	if ( r < 0 ) return(r);
	data = req->data = r;
    }
    if ( !obj->container ) {
	obj->container = alloc_buff(CHUNK_SIZE);
        if ( ! obj->container )
	    return(-1);
	obj->hot_buff = obj->container;
    } else {
	my_xlog(OOPS_LOG_SEVERE, "recv_ftp_list(): Something wrong rcv_ftp_list: container already allocated.\n");
	return(-1);
    }
    r = send_http_header(client, "text/html", 0, req->obj, req);
    if ( r < 0 ) return(r);
    sendstr(client, "<html><head><title>ftp LIST</title>\n");
    store_in_chain("<html><head><title>ftp LIST</title>\n",
	    strlen("<html><head><title>ftp LIST</title>\n"), req->obj);
    tmpbuf = xmalloc(strlen((req->obj->url).proto)+
		strlen((req->obj->url).host)+
		strlen((req->obj->url).path)+ 256, "recv_ftp_list(): 1");
    if ( tmpbuf ) {
	sprintf(tmpbuf, "<base href=\"%s://%s%s\">", req->obj->url.proto,
		req->obj->url.host,
		req->obj->url.path);
	sendstr(client, tmpbuf);
	store_in_chain(tmpbuf, strlen(tmpbuf), req->obj);
	free(tmpbuf); tmpbuf = NULL;
    }

    sendstr(client, "</head><body>\n");
    store_in_chain("</head><body>\n", sizeof("</head><body>\n")-1, req->obj);

    /* Go to up level directory. Patch from doka@kiev.sovam.com */
    if ( req->server_path && ((len = strlen(req->server_path)) > 1) ) {
	char	*ls;

	pTmp = malloc(len+1);
	if ( pTmp ) {
	    strncpy(pTmp, req->server_path, len+1);
	    while ( ( len>0 ) && (pTmp[len-1] == '/') ) {
		len--;
		pTmp[len] = 0;
	    }
	    if ( (ls = strrchr(pTmp, '/')) != 0 ) *(ls+1) = 0;
	    len += 80 + strlen(url.proto) + strlen(url.host);
	    if ( url.login )
		len += strlen(url.login);
	    tmpbuf = malloc(len);
	    if ( tmpbuf ) {
		sprintf (tmpbuf, "<h2><a href=\"%s://", url.proto);
		if (url.login) sprintf (tmpbuf+strlen(tmpbuf), "%s@", url.login);
		sprintf(tmpbuf+strlen(tmpbuf), "%s", url.host);
		if (url.port != 21) sprintf (tmpbuf+strlen(tmpbuf), ":%d", url.port);
		sprintf (tmpbuf+strlen(tmpbuf), "/%s\">Go to parent directory</a></h2><p>", pTmp+1);

		sendstr(client, tmpbuf);
		store_in_chain(tmpbuf, strlen(tmpbuf), req->obj);
		free(tmpbuf); tmpbuf = NULL;
	    }
	    free(pTmp);
	}
    }
    tmpbuf = malloc(strlen(url.path)+80);  /* </head><body>... */
    if (tmpbuf) {
	sprintf(tmpbuf, "<h2>Directory listing for &lt;%s&gt; follows:</h2>", url.path);
	sendstr(client, tmpbuf);
	store_in_chain(tmpbuf, strlen(tmpbuf), req->obj);
    }
    sendstr(client, "<p><pre>\n");
    store_in_chain("<p><pre>\n", strlen("<p><pre>\n"), req->obj);

    req->received = 0;
    while((r = readt(data, buf, sizeof(buf)-1, READ_ANSW_TIMEOUT)) > 0) {
	req->received += r;
	buf[r] = 0;
	attach_data(buf, r, req->container);
	parse_answ(req->container, &received, &list_parser, (void*)req);
    }
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_list(): Read list: %m\n");
	rc = -1;
    }
    if ( writet(client, "</body>", strlen("</body>"), READ_ANSW_TIMEOUT) < 0 )
	rc = -1;
    store_in_chain("</body>", strlen("</body>"), req->obj);
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "recv_ftp_list(): Data connection closed.\n");
    if ( tmpbuf ) free(tmpbuf);
    return(rc);
}

static int
parse_answ(struct buff *b, int *checked, int (*f)(char *, void*), void *arg)
{
char	*start, *beg, *end, *p;
char	holder;

    if ( !b || !b->data )
	return(-1);
    beg = b->data;
    end = b->data + b->used;
go:
    start = beg+*checked;
    if ( !*checked ) {
	p = memchr(beg, '\r', end-beg);
	holder = '\r';
	if ( !p ) {
	    p = memchr(beg, '\n', end-beg);
	    holder = '\n';
	}
	if ( !p ) return(0);
	*p = 0;
	*checked = strlen(start);
	/* start point to beg of server line */
	my_xlog(OOPS_LOG_DBG, "parse_answ(): Answer: <--- `%s'.\n", start);
	(*f)(start, arg);
        *p = holder;
	goto go;
    }
    p = start;
    while( (p < end) && ( *p == '\r' || *p == '\n' ) ) p++;
    if ( (p < end) && *p ) {
	char *t = memchr(p, '\r', end-p);
	holder = '\r';
	if ( !t ) {
	    t = memchr(p, '\n', end-p);
	    holder = '\n';
	}
	if ( !t ) return(0);
	*t = 0;
	my_xlog(OOPS_LOG_DBG, "parse_answ(): Answer: <--- `%s'.\n", p);
	(*f)(p, arg);
	*t = holder;
	*checked = t - beg;
	goto go;
    }
    return(0);
}

/* buld http_header in mem (so it can be saved on disk)
   and send it to user */
static int
send_http_header(int so, char* type, int size, struct mem_obj *obj, struct ftp_r *ftp_r)
{
int	r;
char	b[128];
char	*fmt;
struct	buff	*nextb;

    if ( ftp_r && TEST(ftp_r->ftp_r_flags, PARTIAL_ANSWER) ) {
	r = writet(so, "HTTP/1.0 206 Partial Content\r\n",
		strlen("HTTP/1.0 206 Partial Content\r\n"), READ_ANSW_TIMEOUT);
	if ( obj ) {
	    put_av_pair(&obj->headers, "HTTP/1.0","206 Partial Content");
	    fmt = format_av_pair("HTTP/1.0","206 Partial Content");
	    attach_data(fmt, strlen(fmt), obj->container);
	    xfree(fmt);
        }
	if ( size ) {
	    sprintf(b, "Content-Range: bytes %d-%d/%d\r\n",
		ftp_r->request->range_from,
		size, size);
	} else
	    sprintf(b, "Content-Range: bytes %d-\r\n", ftp_r->request->range_from);
	r = writet(so, b, strlen(b), READ_ANSW_TIMEOUT);
    } else {
	r = writet(so, "HTTP/1.0 200 Ftp Gateway\r\n", strlen("HTTP/1.0 200 Ftp Gateway\r\n"), READ_ANSW_TIMEOUT);
	if ( obj ) {
	    put_av_pair(&obj->headers, "HTTP/1.0","200 Ftp Gateway");
	    fmt = format_av_pair("HTTP/1.0","200 Ftp Gateway");
	    attach_data(fmt, strlen(fmt), obj->container);
	    xfree(fmt);
        }
    }
    if ( r >= 0 )
    r = writet(so, "Content-Type: ", strlen("Content-Type: "), READ_ANSW_TIMEOUT);
    if ( r >= 0 )
    r = writet(so, type, strlen(type), READ_ANSW_TIMEOUT);
    if ( r >= 0 ) r=writet(so, CRLF, 2, READ_ANSW_TIMEOUT);
    if ( obj ) {
	put_av_pair(&obj->headers, "Content-Type:", type);
	fmt = format_av_pair("Content-Type:", type);
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
    }
    if ( (r >= 0) && size ) {
	if ( ftp_r && TEST(ftp_r->ftp_r_flags, PARTIAL_ANSWER) ) {
	    sprintf(b, "Content-Length: %d", size-ftp_r->request->range_from);
	    r = writet(so, b, strlen(b), READ_ANSW_TIMEOUT);
	    r = writet(so, CRLF, 2, READ_ANSW_TIMEOUT);
	} else {
	    sprintf(b, "Content-Length: %d", size);
	    r = writet(so, b, strlen(b), READ_ANSW_TIMEOUT);
	    r = writet(so, CRLF, 2, READ_ANSW_TIMEOUT);
	    if ( obj ) {
		put_av_pair(&obj->headers, b, "");
		attach_data(b, strlen(b), obj->container);
	    }
	}
    }
    mk1123time(global_sec_timer + ftp_expire_value, b, sizeof(b));
    if ( r >= 0 )
    r = writet(so, "Expires: ", strlen("Expires: "), READ_ANSW_TIMEOUT);
    if ( r >= 0 )
    r = writet(so, b, strlen(b), READ_ANSW_TIMEOUT);
    if ( r >= 0 )
    r = writet(so, CRLF, 2, READ_ANSW_TIMEOUT);
    if ( obj ) {
	put_av_pair(&obj->headers, "Expires:", b);
	fmt = format_av_pair("Expires:", b);
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
	mk1123time(global_sec_timer, b, sizeof(b));
	put_av_pair(&obj->headers, "Date:", b);
	fmt = format_av_pair("Date:", b);
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
    }
    if ( r >= 0 )
    r = writet(so, "Via: oops\r\n", strlen("Via: oops\r\n"), READ_ANSW_TIMEOUT);
    if ( obj ) {
	put_av_pair(&obj->headers, "Via:", "oops");
	fmt = format_av_pair("Via:", "oops");
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
    }
    if ( r >= 0 )
    r = writet(so, CRLF, 2, READ_ANSW_TIMEOUT);
    if ( obj ) {
	fmt = format_av_pair("", NULL);
	attach_data(fmt, strlen(fmt), obj->container);
	xfree(fmt);
	if ( obj->hot_buff->used > 4 ) {
	    obj->insertion_point = obj->hot_buff->used - 4;
	    obj->tail_length = 4;
	}
    }
    nextb = alloc_buff(CHUNK_SIZE);
    if ( nextb ) {
	obj->container->next = nextb;
	obj->hot_buff = nextb;
    }
    return(r);
}

static int
add_nlst_entry(char* line, void* arg)
{
struct	ftp_r	*req = (struct ftp_r*) arg;

    add_to_string_list(&req->nlst, line);
    return(0);
}

static int
list_parser(char* line, void *arg)
{
struct	ftp_r	*req = (struct ftp_r*) arg;
int		so;
struct	mem_obj *obj;
struct	url	*url;
enum	{
	PLAIN,
	DIR,
	LINK,
	UNKNOWN
} type;
char	*icons[] = {
	"binary.gif",
	"dir.gif",
	"link.gif",
	"unknown.gif"
};
char	*alts[] = {
	"[File] ",
	"[Dir ] ",
	"[Link] ",
	"[Unkn] "
};
char	*p = line, *tok_ptr, *t;
int	tok_cnt = 0, dovesok, htmlplen=0;
char	*tempbuf = NULL;
char	*htmlized_path = NULL;
char	*htmlized_file = NULL;
char	*htmlized_something = NULL;
char	myhostname[MAXHOSTNAMELEN];
char	portb[20];

/* if not in nlst, then assumed line is something like that:
drwxr-xr-x   2 ms    ms          512 Jul 28 09:52 usr
-rw-r--r--   1 ms    ms        19739 Jan 17  1997 www.FAQ.alt
lrwxrwxrwx   1 root  wheel         7 May  2  1997 www.FAQ.koi8 -> www.FAQ
*/

    if ( !req ) {
	my_xlog(OOPS_LOG_SEVERE, "list_parser(): Fatal: req==NULL in list parser.\n");
	return(-1);
    }
    so = req->client;
    if ( !(obj = req->obj) ) {
	my_xlog(OOPS_LOG_SEVERE, "list_parser(): Fatal: obj==NULL in list parser.\n");
	return(-1);
    }
    url= &obj->url;
    if ( !strlen(url->path) ) {
	my_xlog(OOPS_LOG_SEVERE, "list_parser(): Fatal: path=="" in list parser.\n");
	return(-1);
    }
    /* move to first non-space	*/
    while( *p && IS_SPACE(*p) ) p++;
    /* well, now we can find is it dir, link or plain file	*/
    if ( !*p ) return(0);

    if ( req->request->url.port != 21 ) {
	sprintf(portb, ":%d", req->request->url.port);
    } else
	portb[0] = 0;
    myhostname[0] = 0;
    gethostname(myhostname, sizeof(myhostname)-1);
    /* allocate space to hold all components */
    dovesok = 128;
    if ( req->request->url.login ) {
	dovesok += strlen(req->request->url.login);
    }
    if ( req->request->url.password &&
	 !TEST(req->request->flags,RQ_HAS_AUTHORIZATION ) ) {
	dovesok += strlen(req->request->url.password);
    }
    dovesok += icons_host[0]?strlen(icons_host):strlen(myhostname);
    dovesok += icons_path[0]?strlen(icons_path):(sizeof("icons")+1);
    tempbuf = xmalloc(strlen(line)*6 + strlen(myhostname) + dovesok , "list_parser(): 1");
    if ( !tempbuf ) {
	my_xlog(OOPS_LOG_SEVERE, "list_parser(): No space for tembuf\n");
	return(0);
    }
    switch (tolower(*p)) {
	case '-':	type = PLAIN; 	break;
	case 'd':	type = DIR; 	break;
	case 'l':	type = LINK; 	break;
	default:	type = UNKNOWN; break;
    }
    if ( (t = in_nlst(p, req->nlst)) !=0 ) {
	if ( (t > p) && ( t<=p+strlen(p) ) ) *(t-1)=0;
	htmlized_something = html_escaping(p);
	sprintf(tempbuf, "<img src=\"http://%s:%s/%s/%s\" alt=\"%s\">%s ",
	    		      icons_host[0]?icons_host:myhostname,
	    		      icons_port[0]?icons_port:"80",
			      icons_path[0]?icons_path:"icons",
	    		      icons[type],
	    		      alts[type],
	    		      htmlized_something);
	writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	store_in_chain(tempbuf, strlen(tempbuf), obj);
	htmlized_path = htmlize(req->dehtml_path);
	htmlized_file = htmlize(t);
        if ( htmlized_file ) {
	    /* place '/' at the end of the ref if this is DIR	*/
	    htmlplen = strlen(htmlized_file);
	    if ( htmlplen > 0 ) {
		if (  (htmlized_file[htmlplen-1] != '/')
		    &&(type==DIR) ) {
		    char *newhtmlized_file = malloc(htmlplen+2);
		    if ( newhtmlized_file ) {
			sprintf(newhtmlized_file,"%s/", htmlized_file);
			free(htmlized_file);
			htmlized_file = newhtmlized_file;
		    }
		}
	    }
	}
	if ( req->request->url.login ) {
	    if (req->request->url.password &&
	       !TEST(req->request->flags,RQ_HAS_AUTHORIZATION)) {
		sprintf(tempbuf, "<a href=\"%s://%s:%s@%s%s%s%s%s%s\">%s</a> ",
			url->proto,
			req->request->url.login,req->request->url.password,
			url->host,portb,
			*htmlized_path=='/'?"":"/",
			htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, t);
	    }
	    if (req->request->url.password &&
	       TEST(req->request->flags,RQ_HAS_AUTHORIZATION)) {
		sprintf(tempbuf, "<a href=\"%s://%s@%s%s%s%s%s%s\">%s</a> ",
			url->proto,
			req->request->url.login,
			url->host,portb,
			*htmlized_path=='/'?"":"/",
			htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, t);
	    }
	} else {
	    sprintf(tempbuf, "<a href=\"%s://%s%s%s%s%s%s\">%s</a> ",
			url->proto,url->host,portb,
			*htmlized_path=='/'?"":"/",
			htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, t);
	}
	writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	store_in_chain(tempbuf, strlen(tempbuf), obj);
	
	goto fin_line;
    }
    t = p;
    while( (p = (char*)strtok_r(t, " \t", &tok_ptr)) != 0 ) {
	t = NULL;
	switch (tok_cnt) {
	case 0:
	    /* type */
	    sprintf(tempbuf, "<img src=\"http://%s:%s/%s/%s\" alt=\"%s\">%s ",
	    		      icons_host[0]?icons_host:myhostname,
	    		      icons_port[0]?icons_port:"80",
			      icons_path[0]?icons_path:"icons",
	    		      icons[type],
	    		      alts[type],
	    		      p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 1:
	case 2:
	case 3:
	    sprintf(tempbuf, "%4s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 4:
	    /* this happens if ls give no links number in output */
	    if ( strlen(p) == 3 ) {
		if (!strcasecmp(p,"jan") || !strcasecmp(p,"feb") ||
		    !strcasecmp(p,"mar") || !strcasecmp(p,"apr") ||
		    !strcasecmp(p,"may") || !strcasecmp(p,"jun") ||
		    !strcasecmp(p,"jul") || !strcasecmp(p,"aug") ||
		    !strcasecmp(p,"sep") || !strcasecmp(p,"oct") ||
		    !strcasecmp(p,"nov") || !strcasecmp(p,"dec")
		) tok_cnt++;
	    }
	case 7:
	    sprintf(tempbuf, "%5s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 5:
	case 6:
	    sprintf(tempbuf, "%3.3s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 8:	/* file name */
	    htmlized_path = htmlize(req->dehtml_path);
	    htmlized_file = htmlize(p);
	    if ( req->request->url.login ) {
		if ( req->request->url.password &&
		    !TEST(req->request->flags,RQ_HAS_AUTHORIZATION)) {
		    sprintf(tempbuf, "<a href=\"%s://%s:%s@%s%s%s%s%s%s\">%s</a> ",
			url->proto,
			req->request->url.login,req->request->url.password,
			url->host,portb,
			*htmlized_path=='/'?"":"/",
			htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, p);
		}
		if ( req->request->url.password &&
		    TEST(req->request->flags,RQ_HAS_AUTHORIZATION)) {
		    sprintf(tempbuf, "<a href=\"%s://%s@%s%s%s%s%s%s\">%s</a> ",
			url->proto,
			req->request->url.login,
			url->host,portb,
			*htmlized_path=='/'?"":"/",
			htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, p);
		}
	    } else {
	        sprintf(tempbuf, "<a href=\"%s://%s%s%s%s%s%s\">%s</a> ",
			url->proto,url->host,portb,
			*htmlized_path=='/'?"":"/",
			htmlized_path,
			url->path[strlen(url->path)-1]=='/'?"":"/",
			htmlized_file, p);
	    }
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	case 9:
	    sprintf(tempbuf, "%s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	default:
	    sprintf(tempbuf, "%s ",p);
	    writet(so, tempbuf, strlen(tempbuf), READ_ANSW_TIMEOUT);
	    store_in_chain(tempbuf, strlen(tempbuf), obj);
	    tok_cnt++;
	    continue;
	}
    }
fin_line:;
    writet(so, "\n", 1, READ_ANSW_TIMEOUT);
    store_in_chain("\n", 1, obj);
    if ( tempbuf ) free(tempbuf);
    if ( htmlized_path ) free(htmlized_path);
    if ( htmlized_file ) free(htmlized_file);
    if ( htmlized_something ) free(htmlized_something);
    return(0);
}


static int
server_connect(struct ftp_r *rq)
{
int			server_so = -1, so = rq->client, r;
struct	url		*url = &rq->obj->url;
struct	sockaddr_in	server_sa;
ERRBUF ;

    server_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	say_bad_request(so, "Can't create socket", STRERROR_R(ERRNO, ERRBUFS),
			ERR_INTERNAL, rq->request);
	goto error;
    }
    if ( rq && rq->request )
	bind_server_so(server_so, rq->request);
    if ( str_to_sa(url->host, (struct sockaddr*)&server_sa) ) {
	say_bad_request(so, "Can't translate name to address", url->host, ERR_DNS_ERR, rq->request);
	goto error;
    }
    server_sa.sin_port = htons(url->port);
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "server_connect(): Connecting `%s' for `%s'.\n", url->host, url->path);
    r = connect(server_so, (struct sockaddr*)&server_sa, sizeof(server_sa));
    if ( r == -1 ) {
	say_bad_request(so, "Can't connect", STRERROR_R(ERRNO, ERRBUFS),
			ERR_TRANSFER, rq->request);
	goto error;
    }

    return(server_so);
error:
    if ( server_so != -1) CLOSE(server_so);
    return(-1);
}

static int
get_server_greeting(struct ftp_r *ftp_r)
{
int		r, checked, r_code;
int		server_so = ftp_r->control;
char		answer[ANSW_SIZE+1];
time_t		started = time(NULL);
struct	buff	*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

read_srv:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( !r ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "get_server_greeting(): Server closed connection too early in ftp_fill_mem.\n");
	goto error;
    }
    if ( r == -2 ) {
	/* read timed put */
        if ( time(NULL) - started >= 10*60 ) {
	    /* it is completely timed out */
	    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "get_server_greeting(): Timeout reading from server in ftp_fill_mem.\n");
	    goto error;
        }
	goto read_srv;
    }
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "get_server_greeting(): Error reading from server in ftp_fill_mem.\n");
	goto error;
    }
    /* wait for for '220 '	*/
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "get_server_greeting(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "get_server_greeting(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
    	if ( r_code >= 4 ) {
	    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "get_server_greeting(): Server refused connection at ftp_fill_mem.\n");
	    goto error;
	}
	if ( r_code == 2 )
	    goto done;
    }
    goto read_srv;
done:
    if ( resp_buff ) free_chain(resp_buff);
    return(r);
error:
    if ( resp_buff ) free_chain(resp_buff);
    return(-1);
}

static int
send_user_pass_type(struct ftp_r *ftp_r)
{
int		r, checked, r_code;
int		server_so = ftp_r->control;
char		answer[ANSW_SIZE+1];
time_t		started = time(NULL);
struct	buff	*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    if ( ftp_r->request->url.login ) {
	r = writet(server_so, "USER ", 5, READ_ANSW_TIMEOUT);
	r = writet(server_so, ftp_r->request->url.login, strlen(ftp_r->request->url.login), READ_ANSW_TIMEOUT);
	r = writet(server_so, "\r\n", 2, READ_ANSW_TIMEOUT);
    } else {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "send_user_pass_type(): ftp_srv ---> `%s'\n", "USER anonymous");
	r = writet(server_so, "USER anonymous\r\n", 16, READ_ANSW_TIMEOUT);
    }
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "send_user_pass_type(): Error at 'USER anonymous' in ftp_fill_mem.\n");
	goto error;
    }
wait_user_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_user_pass_type(): No server answer after USER in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "send_user_pass_type(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "send_user_pass_type(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "send_user_pass_type(): Server code: %d\n", r_code);
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto send_type;
	if ( r_code == 3 )
	    goto send_pass;
	if ( r_code >= 4 )
	    goto error;
    }
    goto wait_user_ok;
send_pass:
    /* can clear prev. results */
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
    if ( ftp_r->request->url.password ) {
	r = writet(server_so, "PASS ", 5, READ_ANSW_TIMEOUT);
	r = writet(server_so, ftp_r->request->url.password, strlen(ftp_r->request->url.password), READ_ANSW_TIMEOUT);
	r = writet(server_so, "\r\n", 2, READ_ANSW_TIMEOUT);
    } else {
	char	*pass = NULL;
        if (ftp_passw) {
            pass = malloc(5 + strlen(ftp_passw) + 3);
            sprintf(pass, "PASS %s\r\n", ftp_passw);
        } else if ( host_name[0] && strchr(host_name, '.') ) {
	    pass = malloc(5 + 5 + strlen(host_name) + 3);
	    sprintf(pass, "PASS oops@%s\r\n", host_name);
	} else {
	    pass = strdup("PASS oops@\r\n");
	}
	if ( pass ) {
	    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "send_user_pass_type(): ftp_srv ---> `%s'", pass);
	    r = writet(server_so, pass, strlen(pass), READ_ANSW_TIMEOUT);
	}
	IF_FREE(pass);
    }
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "send_user_pass_type(): Error at 'USER anonymous' in ftp_fill_mem: %m\n");
	goto error;
    }
wait_pass_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "send_user_pass_type(): No server answer after PASS in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "send_user_pass_type(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "send_user_pass_type(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto send_type;
	if ( r_code >= 3 )
	    goto error;
    }
    goto wait_pass_ok;
    
send_type:
    /* can clear prev. results */
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "send_user_pass_type(): ftp_srv: ---> TYPE I\n");
    r = writet(server_so, "TYPE I\r\n", 8, READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_user_pass_type(): Error at 'TYPE I' in ftp_fill_mem.\n");
	goto error;
    }
wait_type_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "send_user_pass_type(): No server answer after PASS in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "send_user_pass_type(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "send_user_pass_type(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto done;
	if ( r_code >= 3 )
	    goto error;
    }
    goto wait_type_ok;

done:
    if ( resp_buff ) free_chain(resp_buff);
    return(r);
error:
    if ( TEST(ftp_r->request->flags, RQ_HAS_AUTHORIZATION) ) send_401_answer(ftp_r->client,
		ftp_r->request);
    if ( resp_buff ) free_chain(resp_buff);
    return(-1);
}

static int
try_passive(struct ftp_r *ftp_r)
{
int		r, checked, r_code, data_so = -1;
int		server_so = ftp_r->control;
char		answer[ANSW_SIZE+1], *p;
time_t		started = time(NULL);
struct	buff	*resp_buff=NULL;
u_int		i[6], j;
u_int		pasv_addr;
u_short		pasv_port = 0;
struct	sockaddr_in	pasv_sa;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

		/* <<<	TRYING PASSIVE MODE  >>> */
		/* _____________________________ */

    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_passive(): ftp_srv: ---> PASV.\n");
    r = writet(server_so, "PASV\r\n", 6, READ_ANSW_TIMEOUT);
    if ( r < 0) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_passive(): Error sending PASV.\n");
	goto error;
    }

wpasv:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_passive(): No server answer after PASS in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "try_passive(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "try_passive(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	if ( r_code == 226 ) {
	    goto wpasv;
	}
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto use_pasv;
	if ( r_code >= 3 )
	    goto error;
    }
    goto wpasv;
use_pasv:
    /* retrive info about server pasive port */
    p = (resp_buff->data)+checked;
    while ( p > resp_buff->data ) {
	if ( *p == '(' ) break;
	p--;
    }
    if ( p == resp_buff->data ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_passive(): Unrecognized format of PASV answer.\n");
	goto error;
    }
    p++;
    for(j=0;j<6;j++) {
	i[j] = atoi(p);
	while(*p && IS_DIGIT(*p) ) p++;
	if ( j < 5 )
	if ( (*p != ',') || !*++p ) {
	    my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_passive(): Unrecognized format of PASV answer.\n");
	    goto error;
        }
    }
    pasv_addr = (i[0]<<24) | (i[1]<<16) | (i[2]<<8) | i[3];
    pasv_port = (i[4]<<8)  |  i[5];
    data_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "try_passive(): Can't create socket: %m\n");
	goto error;
    }
    if ( ftp_r && ftp_r->request )
	bind_server_so(data_so, ftp_r->request);
    pasv_sa.sin_family = AF_INET;
    pasv_sa.sin_addr.s_addr = htonl(pasv_addr);
    pasv_sa.sin_port        = htons(pasv_port);
    r = connect(data_so, (struct sockaddr*)&pasv_sa, sizeof(pasv_sa));
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_passive(): PASV connect: %m\n");
	goto error;
    }
    ftp_r->data = data_so;
    if ( resp_buff ) free_chain(resp_buff);
    return(r);
error:
    if ( data_so != -1 ) CLOSE(data_so);
    if ( resp_buff ) free_chain(resp_buff);
    return(-1);
}

static int
try_port(struct ftp_r *ftp_r)
{
int			r, checked, r_code, data_so = -1;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1], *p;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;
struct	sockaddr_in	my_data_sa;
socklen_t		my_data_sa_len;
 
    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;
		/* <<<  TRYING PORT MODE  >>> */
		/* __________________________ */
    data_so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_so == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "try_port(): Can't create socket: %m\n");
	goto error;
    }
    my_data_sa_len = sizeof(my_data_sa);
    r = getsockname(server_so, (struct sockaddr*)&my_data_sa, &my_data_sa_len);
    if ( r == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "try_port(): Can't getsockname: %m\n");
	goto error;
    }
    my_data_sa.sin_port = 0;
    r = bind(data_so, (struct sockaddr*)&my_data_sa, sizeof(my_data_sa));
    if ( r == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "try_port(): Can't bind for PORT: %m\n");
	goto error;
    }
    r = getsockname(data_so, (struct sockaddr*)&my_data_sa, &my_data_sa_len);
    if ( r == -1 ) {
	my_xlog(OOPS_LOG_SEVERE, "try_port(): Can't do 2-nd getsockname: %m\n");
	goto error;
    }
    /* this is dangerous, but solaris has no snprintf */
    sprintf(answer, "PORT %d,%d,%d,%d,%d,%d\r\n",
    	(unsigned)(ntohl(my_data_sa.sin_addr.s_addr) & 0xff000000) >> 24,
    	(unsigned)(ntohl(my_data_sa.sin_addr.s_addr) & 0x00ff0000) >> 16,
    	(unsigned)(ntohl(my_data_sa.sin_addr.s_addr) & 0x0000ff00) >> 8,
    	(unsigned)(ntohl(my_data_sa.sin_addr.s_addr) & 0x000000ff) ,
    	(unsigned)(ntohs(my_data_sa.sin_port) & 0xff00) >> 8 ,
    	(unsigned)(ntohs(my_data_sa.sin_port) & 0x00ff));
    r = writet(server_so, answer, strlen(answer), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_port(): Error sending PORT: %m\n");
	goto error;
    }
    p = strchr(answer, '\n'); *p = 0; my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_port(): ftp_srv: ---> `%s'\n", answer);
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
w_port_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_port(): No server answer after PORT in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "try_port(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "try_port(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 2 )
	    goto prep_data_so;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_port_ok;
prep_data_so:
    r = listen(data_so, 5);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_SEVERE, "try_port(): Can't accept: %m\n");
	goto error;
    }

    ftp_r->data = data_so;
    if ( resp_buff ) free_chain(resp_buff);
    return(0);
error:
    if ( data_so != -1 ) CLOSE(data_so);
    if ( resp_buff ) free_chain(resp_buff);
    return(-1);
}

static int
try_size(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL, *c, *sn;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;
struct	mem_obj		*obj = ftp_r->obj;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    rq_buff=xmalloc(strlen(ftp_r->dehtml_path)+strlen("SIZE \r\n")+1, "try_size(): rq_buff");
    if ( !rq_buff ) {
	SET(obj->flags, FLAG_DEAD);
	my_xlog(OOPS_LOG_SEVERE, "try_size(): Can't alloc mem.\n");
	goto error;
    }
    sprintf(rq_buff, "SIZE %s\r\n", ftp_r->dehtml_path);
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_size(): ftp_srv: %s", rq_buff);

    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	SET(obj->flags, FLAG_DEAD);
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_size(): Error sending SIZE in ftp_fill_mem.\n");
	goto error;
    }
w_retr_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	SET(obj->flags, FLAG_DEAD);
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_size(): No server answer after SIZE in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	SET(obj->flags, FLAG_DEAD);
	my_xlog(OOPS_LOG_SEVERE, "try_size(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "try_size(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto retrieve_size;
	if ( r_code == 2 )
	    goto retrieve_size;
	if ( r_code >= 3 ) {
	    goto error;
	}
    }
    goto w_retr_ok;
retrieve_size:
    /* stand at the end of answer */
    c = resp_buff->data ;
    sn = memchr(c, '\n', resp_buff->used);
    if ( !sn ) sn = memchr(c, '\r', resp_buff->used);
    if ( (sn > resp_buff->data) && (sn < resp_buff->data + resp_buff->used) )
	*sn = 0;
    else
	goto error;

    c+=3;while(*c && IS_SPACE(*c) ) c++;
    ftp_r->size = atoi(c);
    ftp_r->request->doc_size = ftp_r->size;
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_size(): SIZE: %d\n", ftp_r->size);
    /* we will not store large files */
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}

static int
try_retr(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    rq_buff=xmalloc(strlen(ftp_r->dehtml_path)+strlen("RETR \r\n")+1, "try_retr(): rq_buff");
    if ( !rq_buff ) {
	my_xlog(OOPS_LOG_SEVERE, "try_retr(): Can't alloc mem.\n");
	goto error;
    }
    sprintf(rq_buff, "RETR %s\r\n", ftp_r->dehtml_path);
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_retr(): ftp_srv: %s", rq_buff);
    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_retr(): Error sending RETR in ftp_fill_mem.\n");
	goto error;
    }
w_retr_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_retr(): No server answer after PORT in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "try_retr(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "try_retr(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto receive_data;
	if ( r_code == 2 )
	    goto receive_data;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_retr_ok;
receive_data:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(0);
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}

static int
try_rest(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;
struct	request		*rq = ftp_r->request;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    rq_buff=xmalloc(20+strlen("REST \r\n")+1, "try_rest(): rq_buff");
    if ( !rq_buff ) {
	my_xlog(OOPS_LOG_SEVERE, "try_rest(): Can't alloc mem.\n");
	goto error;
    }
    sprintf(rq_buff, "REST %d\r\n", rq->range_from);
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_rest(): ftp_srv: %s", rq_buff);
    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_rest(): Error sending RETR in ftp_fill_mem.\n");
	goto error;
    }
w_retr_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_rest(): No server answer after PORT in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "try_rest(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "try_rest(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto receive_data;
	if ( r_code == 2 )
	    goto receive_data;
	if ( r_code == 3 )
	    goto receive_data;
	if ( r_code >= 4 )
	    goto error;
    }
    goto w_retr_ok;
receive_data:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    SET(ftp_r->ftp_r_flags, PARTIAL_ANSWER);
    return(0);
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}

static int
try_cwd(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;
char			*cwd_path = ftp_r->dehtml_path;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    rq_buff = xmalloc(strlen(cwd_path)+strlen("CWD \r\n")+1, "try_cwd(): rq_buff");
    if ( !rq_buff ) {
	my_xlog(OOPS_LOG_SEVERE, "try_cwd(): Can't alloc mem.\n");
	goto error;
    }

    sprintf(rq_buff, "CWD %s\r\n", cwd_path);
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_cwd(): ftp_srv: %s", rq_buff);
    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_cwd(): Error sending RETR in ftp_fill_mem.\n");
	goto error;
    }
w_cwd_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_cwd(): No server answer after CWD in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "try_cwd(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "try_cwd(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto request_list;
	if ( r_code == 2 )
	    goto request_list;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_cwd_ok;

request_list:

    r = writet(server_so, "PWD\r\n", 5, READ_ANSW_TIMEOUT);
    if ( r >= 0 ) {
	r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
	if ( r > 0 ) {   /* Success */
	    answer[r]='\0';
	    /*---- Malloc or realloc memory for server_path */
	    if ( ftp_r->server_path ) {
		if ( ftp_r->server_path ) {
			free(ftp_r->server_path);
			ftp_r->server_path = NULL;
		}
		cwd_path = malloc(r);
	    } else
		cwd_path = malloc(r);
	    /*---- Check if it was successfull */
	    if ( !cwd_path ) {
		my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_cwd(): Can't allocate server_path in try_cwd.\n");
	    } else {
		int	n;
		n = sscanf(answer, "%d %s", &r_code, cwd_path);
		if ( (n == 2) && 
		     (r_code == 257) && 
		     (*(cwd_path) == '"') && 
		     ((r = strlen(cwd_path)) > 2 ) ) {
		    strncpy (cwd_path, cwd_path+1, r-2);
		    cwd_path[r-2] = '\0';
		    ftp_r->server_path = cwd_path;
		    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "try_cwd(): Directory is `%s'\n", ftp_r->server_path);
		} else
		    free(cwd_path);
	    }
	} /* PWD's read */
    } /* PWD's write */

    r = writet(server_so, "NLST -a\r\n", 9, READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_cwd(): ftp_srv: error sending NLST: %m\n");
	goto error;
    }
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
w_list_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "try_cwd(): No server answer after PORT in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "try_cwd(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "try_cwd(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto receive_data;
	if ( r_code == 2 )
	    goto receive_data;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_list_ok;
receive_data:
    if ( resp_buff ) free_chain(resp_buff); if ( rq_buff ) free(rq_buff);
    return(0);
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}

static int
request_list(struct ftp_r *ftp_r)
{
int			r, checked, r_code;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    r = writet(server_so, "LIST\r\n", 6, READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "request_list(): ftp_srv: error sending LIST: %m\n");
	goto error;
    }
    resp_buff->used = 0;
    started = time(NULL);
    checked = 0;
w_list_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "request_list(): No server answer after LIST in ftp_fill_mem.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "request_list(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "request_list(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto receive_data;
	if ( r_code == 2 )
	    goto receive_data;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_list_ok;
receive_data:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(0);
error:
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    return(-1);
}

static int
parse_ftp_srv_answ(struct buff *b, int *checked, struct ftp_r *ftp_r)
{
char	*start, *beg, *end, *p;
char	holder;
int	res=0;

    if ( !b || !b->data )
	return(-1);
    beg = b->data;
    end = b->data + b->used;
go:
    start = beg+*checked;
    if ( !*checked ) {
	if ( (beg < end) && IS_SPACE(*beg) ) {
	    (*checked)++;
	    goto go;
	}
	p = memchr(beg, '\r', end-beg);
	holder = '\r';
	if ( !p ) {
	    p = memchr(beg, '\n', end-beg);
	    holder = '\n';
	}
	if ( !p ) return(0);
	if ( ftp_r->server_log )
		if ( attach_data(start, p-start+1, ftp_r->server_log) )
		    return(-1);
	*p = 0;
	*checked = strlen(start);
	if ( !*checked ) {
	    return(-1);
	}
	/* start point to beg of server line */
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "parse_ftp_srv_answ(): ftp_srv1 <--- `%s'\n", start);
        if ( (strlen(start) > 3) && (start[3] == ' ') ) {
	    res = atoi(start);
	    if ( res ) {
		*p = holder;
		*checked = p - beg;
		return(res);
	    }
        }
        *p = holder;
	goto go;
    }
    p = start;
    while( (p < end) && ( *p == '\r' || *p == '\n' ) ) p++;
    if ( p<end && *p ) {
	char *t = memchr(p, '\r', end-p);
	char *tt = memchr(p, '\n', end-p);
	holder = '\r';
	if ( tt && (tt < t) ) {
	    t = tt;
	    holder = '\n';
	}
	if ( !t ) return(0);
	if ( ftp_r->server_log )
		attach_data(start, t-start+1, ftp_r->server_log);
	*t = 0;
	my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "parse_ftp_srv_answ(): ftp_srv2 <--- `%s'\n", p);
	if ( (strlen(p) > 3) &&
		IS_DIGIT(p[0]) &&
		IS_DIGIT(p[1]) &&
		IS_DIGIT(p[2]) && (p[3] == ' ') ) {
	    res = atoi(start);
	    if ( res ) {
		*t = holder;
		*checked = t - beg;
		my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "parse_ftp_srv_answ(): Returned %d\n", res);
		return(res);
	    }
	}
	*t = holder;
	*checked = t - beg;
	goto go;
    }
    return(0);
}

static void
send_ftp_err(struct ftp_r *ftp_r)
{
char	*err_header =
"HTTP/1.0 400 Got error during ftp load\r\nContent-Type: text/html\r\n\r\n<html><header>FTP error</header><body><center>Document can't be retrieved.</center><br>Server answers:<hr><p><pre>";
char	*epilog = "</body></html>";

    writet(ftp_r->client, err_header, strlen(err_header), READ_ANSW_TIMEOUT);
    ftp_r->server_log?writet(ftp_r->client,
    		ftp_r->server_log->data, ftp_r->server_log->used, READ_ANSW_TIMEOUT):
    	writet(ftp_r->client, "Undefined error\n", strlen("Undefined error\n"), READ_ANSW_TIMEOUT);
    writet(ftp_r->client, epilog, strlen(epilog), READ_ANSW_TIMEOUT);
}

static char*
in_nlst(char *line, struct string_list *list)
{
char *t, *best = NULL, *most_right;
char *longest, *wb,*we, *start;
int   len, longest_len, most_right_len=0;
struct search_list *res = NULL, *curr;

    if ( list && list->string ) {
        longest = list->string;
	longest_len = 0;
	most_right = line;
    } else
	return(NULL);

    while(list) {
	start = line;
refind:
	if ( (t = strstr(start, list->string)) != 0 ) {
	    /*while( *t && (p = strstr(t+1, list->string)) ) t = p;*/
	    len = strlen(list->string);
	    wb = t; we = t+len;
	    if ( (t == start) || !IS_SPACE(*(t-1)) || (*we && !IS_SPACE(*we))) {
		goto sss;
	    }
	    if ( t > most_right ) {
		most_right = t;
		most_right_len = len;
	    }
	    add_to_search_list(&res, t, len);
sss:;
	    start = t+1; if ( *start ) goto refind;
	}
	list = list->next;
    }
    best = NULL;
    curr = res;
    while ( curr ) {
	if ( (curr->off <= most_right) &&
	     (curr->off + curr->len >= most_right+most_right_len) ) {
	    best = curr->off;
	    longest_len = curr->len;
	}
	curr = curr->next;
    } 
    if ( best ) {
	*(best + longest_len) = 0;
    }
    free_search_list(res);
    return(best);
}

static void
send_401_answer(int so, struct request *rq)
{
struct output_object	*obj;
struct buff		*body;
int			rc;
char			std_template[] = 
"<html><body>Ftp access failed\n\n</body></html>";
char			authreqfmt[] = "Basic realm=\"ftp %s\"";
char			*authreq;

    obj = xmalloc(sizeof(*obj),"send_401_answer(): 1");
    if ( !obj )
        return;

    bzero(obj, sizeof(*obj));

    if ( rq->url.login ) {
	authreq = malloc(sizeof(authreqfmt) + strlen(rq->url.login) + 1);
        sprintf(authreq, authreqfmt, rq->url.login);
    } else {
	authreq = malloc(sizeof(authreqfmt) + sizeof("FTP") + 1);
        sprintf(authreq, authreqfmt, "FTP");
    }
    if ( !authreq ) goto done;
    put_av_pair(&obj->headers,"HTTP/1.0", "401 Authentication Required");
    put_av_pair(&obj->headers,"WWW-Authenticate:", authreq);
    put_av_pair(&obj->headers,"Content-Type:", "text/html");
    free(authreq);
    body = alloc_buff(CHUNK_SIZE);
    if ( body ) {
        obj->body = body;
	rc = attach_data(std_template, sizeof(std_template), body);
        if ( !rc )
	    process_output_object(so, obj, rq);
    }
done:
    free_output_obj(obj);
    return;

}

static int
ftpmkdir(struct ftp_r *ftp_r, char *dir)
{
int		r, server_so, checked, r_code;
struct	buff	*resp_buff=NULL;
char		*rq_buff = NULL;
char		answer[ANSW_SIZE+1];

    if ( !ftp_r || !dir ) return(1);
    resp_buff = alloc_buff(CHUNK_SIZE);
    if ( !resp_buff ) return(1);
    checked = 0;
    server_so = ftp_r->control;
    rq_buff=malloc(strlen(dir)+strlen("MKD \r\n")+1); 
    if ( !rq_buff ) goto error;
    sprintf(rq_buff, "MKD %s\r\n", dir);
    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "ftpmkdir(): Error sending MKD in ftpmkdir.\n");
	goto error;
    }
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "ftpmkdir(): No server answer after STOR in ftp_put.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "ftpmkdir(): No space at ftp_fill_mem.\n");
	goto error;
    }

    r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r);
    if ( r_code < 100 ) {
	my_xlog(OOPS_LOG_SEVERE, "ftpmkdir(): Some fatal error at ftp_fill_mem.\n");
	goto error;
    }
    if ( r_code == 550 )	/* File exists */
	goto done;

    r_code = r_code/100;
    if ( r_code == 2 )
	goto done;		/* Created	*/

    /* Smthng Failed*/
error:
    IF_FREE(rq_buff);
    if ( resp_buff ) free_chain(resp_buff);
    return(1);
done:
    IF_FREE(rq_buff);
    if ( resp_buff ) free_chain(resp_buff);
    return(0);
}

/*
 *	FTP upload
 *	We are connected and logged in
 */

static void
ftp_put(int so, struct request *rq, char *headers, struct ftp_r *ftp_r)
{
/* ftp_r->server_path contains filename */
int			r, checked, r_code, sent = 0, pass = 0;
int			server_so = ftp_r->control;
char			answer[ANSW_SIZE+1];
char			*rq_buff = NULL, *path = NULL, *dir = NULL, *t;
time_t			started = time(NULL);
struct	buff		*resp_buff=NULL;
struct	pollarg		pollarg[2];
char			*accepted_ok =
"HTTP/1.0 202 Accepted\r\nContent-Type: text/plain\r\n\r\nAccepted.\r\n";

    resp_buff = alloc_buff(CHUNK_SIZE);
    started = time(NULL);
    checked = 0;

    rq_buff = xmalloc(strlen(ftp_r->dehtml_path)+strlen("STOR \r\n")+1,"ftp_put(): rq_buff");
    if ( !rq_buff ) {
	my_xlog(OOPS_LOG_SEVERE, "ftp_put(): Can't alloc mem.\n");
	goto error;
    }
    path = ftp_r->dehtml_path;
    if ( !path ) goto error;
    if ( *path == '/' ) path++;
send_stor:;
    sprintf(rq_buff, "STOR %s\r\n", path);
    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "ftp_put(): ftp_srv: %s", rq_buff);
    r = writet(server_so, rq_buff, strlen(rq_buff), READ_ANSW_TIMEOUT);
    pass++;
    if ( r < 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "ftp_put(): Error sending STOR in ftp_fill_mem.\n");
	goto error;
    }
w_stor_ok:
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "ftp_put(): No server answer after STOR in ftp_put.\n");
	goto error;
    }
    if ( attach_data(answer, r, resp_buff) ) {
	my_xlog(OOPS_LOG_SEVERE, "ftp_put(): No space at ftp_fill_mem.\n");
	goto error;
    }
    while ( (r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r)) != 0 ) {
	if ( r_code < 100 ) {
	    my_xlog(OOPS_LOG_SEVERE, "ftp_put(): Some fatal error at ftp_fill_mem.\n");
	    goto error;
	}
	if ( r_code == 553 && pass == 1 ) goto trymkdir;
	r_code = r_code/100;
	if ( r_code == 1 )
	    goto send_data;
	if ( r_code == 2 )
	    goto send_data;
	if ( r_code >= 3 )
	    goto error;
    }
    goto w_stor_ok;
trymkdir:
    dir = strdup(path);
    if ( !dir ) goto error;
    /* traverse path and create directories	*/
    t = dir;
    while ( *t ) {
	char	*cdl;
	cdl = strchr(t, '/');
	if ( cdl ) {
	    *cdl = 0;
	    my_xlog(OOPS_LOG_FTP|OOPS_LOG_DBG, "ftp_put(): Trying to create dir `%s'\n", dir);
	    if ( ftpmkdir(ftp_r, dir) ) {
		*cdl = '/';
		goto error;
	    }
	    *cdl = '/';
	    t = cdl+1;
	} else
	    break;
    }
    checked = resp_buff->used;
    goto send_stor;

send_data:
    r = -1;
    if ( rq->data && rq->data->data )
	r = writet(ftp_r->data, rq->data->data, rq->data->used, READ_ANSW_TIMEOUT);
    if ( r < 0 )
	goto error;
    sent += rq->data->used;
    while( sent < rq->content_length ) {

	pollarg[0].fd = so;
	pollarg[0].request = FD_POLL_RD;
	r = poll_descriptors(1, &pollarg[0], READ_ANSW_TIMEOUT*1000);
	if ( r <= 0) {
	    goto done;
	}
	if ( IS_HUPED(&pollarg[0]) )
	    goto done;
	if ( IS_READABLE(&pollarg[0]) ) {
	    char b[1024];
	    /* read from client */
	    r = read(so, b, sizeof(b));
	    if ( (r < 0) && (ERRNO == EAGAIN) )
		continue;
	    if ( r <= 0 )
		goto done;
	    r = writet(ftp_r->data, b, r, READ_ANSW_TIMEOUT);
	    if ( r < 0 ) goto done;
	    sent += r;
	}
    }
done:
    ftp_r->received = sent;
    if ( ftp_r->data != -1 ) close(ftp_r->data) ;ftp_r->data = -1;
    r = readt(server_so, answer, ANSW_SIZE, READ_ANSW_TIMEOUT);
    if ( r <= 0 ) {
	my_xlog(OOPS_LOG_NOTICE|OOPS_LOG_DBG|OOPS_LOG_INFORM, "ftp_put(): No server answer after STOR in ftp_put.\n");
	goto error;
    }
    attach_data(answer, r, resp_buff);
    r_code = parse_ftp_srv_answ(resp_buff, &checked, ftp_r);
    r=writet(so, accepted_ok, strlen(accepted_ok), READ_ANSW_TIMEOUT);
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    if ( dir ) free(dir);
    /*my_sleep(1);*/
    return;
error:
    send_ftp_err(ftp_r);
    if ( resp_buff ) free_chain(resp_buff);
    if ( rq_buff ) free(rq_buff);
    if ( dir ) free(dir);
    return;
}
