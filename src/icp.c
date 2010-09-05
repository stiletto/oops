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

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<strings.h>
#include	<stdarg.h>
#include	<netdb.h>
#include	<ctype.h>

#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/socket.h>
#include	<sys/socketvar.h>
#include	<sys/resource.h>
#include	<fcntl.h>

#include	<netinet/in.h>

#include	<arpa/inet.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"

#define	ICP_OP_INVALID		0
#define	ICP_OP_QUERY		1
#define	ICP_OP_HIT		2
#define	ICP_OP_MISS		3
#define	ICP_OP_ERR		4
#define	ICP_OP_SECHO		10
#define	ICP_OP_DECHO		11
#define	ICP_OP_MISS_NOFETCH	21
#define	ICP_OP_DENIED		22
#define	ICP_OP_HIT_OBJ		23


struct icp_hdr {
	struct {
		int	opcode:8;
		int	version:8;
		short	msg_len;
	} w0;
	int	rq_n;
	int	opt;
	int	opt_data;
	int	sender;
};

struct	icp_lookup {
	struct sockaddr_in	sa;
	char			type;
	int			rq_n;
};

void	send_icp_op(int so, struct sockaddr_in *sa, int op, int rq_n, char *urlp);
void	send_icp_op_err(int so, struct sockaddr_in *sa, int rq_n);
struct	peer	*peer_by_addr(struct sockaddr_in*);
int	process_miss(void*, void*);
int	process_hit(void*, void*);


#define	icp_opcode	icp_hdr->w0.opcode
#define	icp_version	icp_hdr->w0.version
#define	icp_msg_len	icp_hdr->w0.msg_len
#define	icp_rq_n	icp_hdr->rq_n
#define	icp_opt		icp_hdr->opt
#define	icp_opt_data	icp_hdr->opt_data

/* 1) ������� ���������� ����.
	������ � ��������� DOWN �� ����������� ��� ��������.
   2) ��� ��������� ������� ���� - ����� ��������, ���� � ���� �� ���� ���
   3) ��� ��������� MISS:
	��������� ����� ��������� �������
	���� MISS �� ������� - ��������� ���.
	���� ����� ��������� ������� ����� ������� - ��������� ��������
   ���������� - ���� �� �������� ���� � ��������� �������� �������� -
   			���� ��������
	      - ���� ������ ���������� ��������� � ���� ���� �� ������� -
	        ���� � ����.
*/

int
send_icp_requests(struct request *rq, struct icp_queue_elem *qe)
{
int		len,succ=0,rr;
char		*buf;
struct	icp_hdr	*icp_hdr;
struct	peer	*peer;

    len = strlen(rq->url.proto) + strlen(rq->url.host) +
          strlen(rq->url.path) + 16 /* for port and other parts */;
    buf = xmalloc(ROUND(len+sizeof(struct icp_hdr),CHUNK_SIZE),"icp_rq");
    if ( ! buf )
	return(-1);
    if ( rq->url.port != 80 )
	sprintf(buf+sizeof(struct icp_hdr)+4, "%s://%s:%d%s",
			rq->url.proto,rq->url.host,
    			rq->url.port,rq->url.path);
      else
	sprintf(buf+sizeof(struct icp_hdr)+4, "%s://%s%s",
			rq->url.proto,rq->url.host,
    			rq->url.path);
    icp_hdr	= (struct icp_hdr*)buf;
    icp_opcode 		= ICP_OP_QUERY;
    icp_version 	= 2;
    len			= sizeof(struct icp_hdr)+4+
    			  strlen(buf+(sizeof(struct icp_hdr))+4)+1;
    icp_msg_len		= htons(len);
    icp_rq_n		= qe->rq_n;
    icp_opt		= 0;
    peer = peers;
    while ( peer ) {
	if ( rq->request_time - peer->addr_age >= ADDR_AGE ) {
	    struct	sockaddr_in	sa;

	    /* need addr update */
	    my_log("Need address update\n");
	    pthread_mutex_lock(&icp_resolver_lock);
	    bzero((void*)&sa, sizeof(sa));
	    rr = str_to_sa(peer->name,(struct sockaddr*)&sa);
	    if ( !rr ) {
		memcpy((void*)&peer->addr, (void*)&sa, sizeof(sa));
		peer->addr.sin_family = AF_INET;
		peer->addr.sin_port = htons(peer->icp_port);
		peer->addr_age  = rq->request_time;
	    } else {
		/* wipe address				*/
		/* will re-request again on 60 sec	*/
		if ( !peer->addr_age && rq->request_time )
		    /* if peer name was never resolved	*/
		    peer->addr_age = rq->request_time - ADDR_AGE + 60 ;
		  else
		    peer->addr_age += 60;
	    }
	    pthread_mutex_unlock(&icp_resolver_lock);
	}
	/* skip if we don't want to use this peers for this domain */
	if ( !is_domain_allowed(rq->url.host, peer->acls) ) {
	    peer = peer->next;
	    continue;
	}
	my_log("sending to: %s\n", peer->name);
	rr = sendto(icp_so, buf, len, 0, (struct sockaddr*)&peer->addr, sizeof(struct sockaddr_in));
	if ( rr != -1 ) {
	    if ( !TEST(peer->state, PEER_DOWN) ) 
		succ++;
	    peer->last_sent = global_sec_timer;
	} else {
	    my_log("Sendto: %s\n", strerror(errno));
	}
	/* as is just statistics, let it only approximate */
	peer->rq_sent++;
	peer = peer->next;
    }
    xfree(buf);
    if ( !succ ) {
   	return(-1);
    }
    /* requests was sent */
    qe->requests_sent = succ;
    /* put qe in list	 */
    list_add(&icp_requests_list, qe);
    return(0);
}

void
icp_request_destroy(struct icp_queue_elem *icpr)
{
    /* unlink it from list */
    list_remove(&icp_requests_list, icpr);
    pthread_cond_destroy(&icpr->icpr_cond);
    pthread_mutex_destroy(&icpr->icpr_mutex);
}

void
process_icp_msg(int so, char *buf, int len, struct sockaddr_in *sa)
{
struct	icp_hdr		*icp_hdr = (struct icp_hdr*)buf;
int			*intp;
char			*urlp;
int			r_h_a, denied;
struct	mem_obj 	*res;
struct	peer		*peer;
struct	icp_lookup	icp_lookup;
struct	request		request;

    if ( len <= 0 )
	return;
    switch(icp_opcode) {
	case ICP_OP_INVALID:
		break;
	case ICP_OP_QUERY:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    send_icp_op_err(so, sa, htonl(icp_rq_n));
		    return;
		}
		/* extract requester host addr	*/
		intp = (int*)(buf+sizeof(struct icp_hdr));
		r_h_a = *intp;
		/* extract url 			*/
		urlp =	buf + sizeof(struct icp_hdr) + 4;
		if ( !memchr(urlp, 0, len-4-sizeof(struct icp_hdr)) ) {
		    my_log("Wrong url\n");
		    send_icp_op_err(so, sa, htonl(icp_rq_n));
		    return;
		}
		LOCK_STATISTICS(oops_stat);
		    oops_stat.requests_icp++;
		    oops_stat.requests_icp0++;
		UNLOCK_STATISTICS(oops_stat);
		bzero(&request, sizeof(request));
		memcpy(&request.client_sa, sa, sizeof(*sa));
		my_log("ICP_OP_QUERY: %s\n", urlp);
		if ( parse_url(urlp, NULL, &request.url, -1) ) {
		    my_log("Wrong url\n");
		    send_icp_op_err(so, sa, htonl(icp_rq_n));
		    return;
		}
		RDLOCK_CONFIG;
		denied = deny_http_access(so, &request);
		if ( denied ) {
		    UNLOCK_CONFIG ;
		    send_icp_op(so, sa, ICP_OP_DENIED, htonl(icp_rq_n), urlp);
		    free_url(&request.url);
		    return;
		}
		peer = peer_by_addr(sa);
		if ( peer ) {
		    /* here update peer statistics			*/
		    peer->rq_recvd++;
		}
		UNLOCK_CONFIG ;
		res = locate_in_mem(&request.url, 0, NULL, NULL);
		if ( res ) {
		    my_log("ICP_MEM_HIT\n");
		    icp_opcode = ICP_OP_HIT;
		    icp_opt=0;
		    send_icp_op(so, sa, ICP_OP_HIT, htonl(icp_rq_n), urlp);
		    if ( peer )
			peer->hits_sent++;
		} else {
		    struct disk_ref	*tmp_ref;
		    int			rc;
		    /* locate on storage */
		    RDLOCK_CONFIG;
		    RDLOCK_DB;
		    rc = locate_url_on_disk(&request.url, &tmp_ref);
		    UNLOCK_DB;
		    UNLOCK_CONFIG;
		    if ( rc >= 0 )xfree(tmp_ref);
		    if ( !rc ) {
			my_log("ICP_STOR_HIT\n");
			send_icp_op(so, sa, ICP_OP_HIT, htonl(icp_rq_n), urlp);
			if ( peer )
			    peer->hits_sent++;
		    } else {
			my_log("ICP_MISS\n");
			send_icp_op(so, sa, ICP_OP_MISS, htonl(icp_rq_n), urlp);
		    }
		}
		free_url(&request.url);
		break;
	case ICP_OP_HIT:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    send_icp_op_err(so, sa, htonl(icp_rq_n));
		    return;
		}
		RDLOCK_CONFIG;
		peer = peer_by_addr(sa);
		if ( !peer ) {
		    UNLOCK_CONFIG;
		    my_log("Msg from unknown peer\n");
		    break;
		}
		/* here update peer statistics			*/
		peer->an_recvd++;
		peer->hits_recvd++;
		peer->last_recv = global_sec_timer;
		icp_lookup.sa  = *sa;
		icp_lookup.sa.sin_port = htons(peer->http_port);
		icp_lookup.type= peer->type;
		my_log("ICP_PEER_HIT from %s\n", peer->name);
		UNLOCK_CONFIG;
		icp_lookup.rq_n= icp_rq_n;
		/* looking up queue elem with the same rq_n	*/
		list_traverse(&icp_requests_list, process_hit, &icp_lookup);
		break;
	case ICP_OP_MISS:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    send_icp_op_err(so, sa, htonl(icp_rq_n));
		    return;
		}
		RDLOCK_CONFIG;
		peer = peer_by_addr(sa);
		if ( !peer ) {
		    UNLOCK_CONFIG;
		    my_log("Msg from unknown peer\n");
		    break;
		}
		/* here update peer statistics			*/
		peer->an_recvd++;
		peer->last_recv = global_sec_timer;
		icp_lookup.sa  = *sa;
		icp_lookup.sa.sin_port = htons(peer->http_port);
		icp_lookup.type= peer->type;
		my_log("ICP_PEER_MISS from %s\n", peer->name);
		UNLOCK_CONFIG;
		icp_lookup.rq_n= icp_rq_n;
		/* looking up queue elem with the same rq_n	*/
		list_traverse(&icp_requests_list, process_miss, &icp_lookup);
		break;
	case ICP_OP_ERR:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    return;
		}
		RDLOCK_CONFIG;
		peer = peer_by_addr(sa);
		if ( !peer ) {
		    UNLOCK_CONFIG;
		    my_log("Msg from unknown peer\n");
		    break;
		}
		/* here update peer statistics			*/
		peer->an_recvd++;
		UNLOCK_CONFIG;
		break;
	case ICP_OP_SECHO:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    return;
		}
		RDLOCK_CONFIG;
		peer = peer_by_addr(sa);
		if ( !peer ) {
		    UNLOCK_CONFIG;
		    my_log("Msg from unknown peer\n");
		    break;
		}
		/* here update peer statistics			*/
		UNLOCK_CONFIG;
		peer->an_recvd++;
		break;
	case ICP_OP_DECHO:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    return;
		}
		RDLOCK_CONFIG;
		peer = peer_by_addr(sa);
		if ( !peer ) {
		    UNLOCK_CONFIG;
		    my_log("Msg from unknown peer\n");
		    break;
		}
		/* here update peer statistics			*/
		peer->an_recvd++;
		UNLOCK_CONFIG;
		break;
	case ICP_OP_MISS_NOFETCH:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    return;
		}
		RDLOCK_CONFIG;
		peer = peer_by_addr(sa);
		if ( !peer ) {
		    UNLOCK_CONFIG;
		    my_log("Msg from unknown peer\n");
		    break;
		}
		/* here update peer statistics			*/
		peer->an_recvd++;
		UNLOCK_CONFIG;
		break;
	case ICP_OP_DENIED:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    return;
		}
		RDLOCK_CONFIG;
		peer = peer_by_addr(sa);
		if ( !peer ) {
		    UNLOCK_CONFIG;
		    my_log("Msg from unknown peer\n");
		    break;
		}
		/* here update peer statistics			*/
		peer->an_recvd++;
		UNLOCK_CONFIG;
		break;
	case ICP_OP_HIT_OBJ:
		if ( len != ntohs(icp_msg_len) ) {
		    my_log("Wrong len\n");
		    return;
		}
		RDLOCK_CONFIG;
		peer = peer_by_addr(sa);
		if ( !peer ) {
		    UNLOCK_CONFIG;
		    my_log("Msg from unknown peer\n");
		    break;
		}
		/* here update peer statistics			*/
		peer->an_recvd++;
		UNLOCK_CONFIG;
		break;
	default:
	     return;
    }
}

void
send_icp_op_err(int so, struct sockaddr_in *sa, int rq_n)
{
char	buf[5*4];
int	len = sizeof(buf);
struct	icp_hdr	*icp_hdr = (struct icp_hdr*)buf;

    bzero(buf, sizeof(buf));
    icp_opcode = ICP_OP_ERR;
    icp_version = 2;
    icp_msg_len = htons(len);
    icp_rq_n = htonl(rq_n);
    sendto(so, buf, len, 0, (struct sockaddr*)sa, sizeof(struct sockaddr_in));
}
void
send_icp_op(int so, struct sockaddr_in *sa, int op, int rq_n, char *urlp)
{
char	*buf;
int	len = strlen(urlp)+1 + sizeof(struct icp_hdr);
struct	icp_hdr	*icp_hdr;
int	r;

    buf = xmalloc(ROUND(len, CHUNK_SIZE), "ICP_OP");
    if ( !buf )
	return;
    icp_hdr = (struct icp_hdr *)buf;
    bzero(buf, len);
    icp_opcode = op;
    icp_version = 2;
    icp_msg_len = htons(len);
    icp_rq_n = htonl(rq_n);
    strncpy(buf+sizeof(*icp_hdr), urlp, strlen(urlp));
    r = sendto(so, buf, len, 0, (struct sockaddr*)sa, sizeof(struct sockaddr_in));
    if ( r == -1 ) {
	my_log("Failed to send OP_HIT: %s\n", strerror(errno));
    }
    xfree(buf);
}

struct peer*
peer_by_addr (struct sockaddr_in *sa)
{
struct	peer *peer = peers;

    while(peer) {
	if (    (sa->sin_addr.s_addr == peer->addr.sin_addr.s_addr) &&
		(sa->sin_port == peer->addr.sin_port)) {
	    break;
	}
	peer = peer->next;
    }
    return(peer);
}

struct peer*
peer_by_http_addr (struct sockaddr_in *sa)
{
struct	peer *peer = peers;

    while(peer) {
	if (    (sa->sin_addr.s_addr == peer->addr.sin_addr.s_addr) &&
		(ntohs(sa->sin_port) == peer->http_port)) {
	    break;
	}
	peer = peer->next;
    }
    return(peer);
}

int
process_miss(void *le, void *arg)
{
struct	icp_lookup		*icp_lookup = arg;
struct	icp_queue_elem		*qe = le;
int				rq_n;

    if ( !qe || !icp_lookup ) return(0);
    rq_n = icp_lookup->rq_n;
    my_log("miss called\n");
    pthread_mutex_lock(&qe->icpr_mutex);
    if ( rq_n == qe->rq_n ) {
	my_log("icp_req still here\n");
	if ( (icp_lookup->type == PEER_PARENT) && !qe->status) {
	    qe->type    = icp_lookup->type;
	    /* store address of first parent 	*/
	    qe->peer_sa = icp_lookup->sa;
	    qe->status = TRUE;
	}
	qe->requests_sent--;
	if ( qe->requests_sent <= 0 ) {
	    /* we will wait no answers more, so signal to start	*/
	    if ( qe->waitors) {
#if	!defined(LINUX)
		pthread_cond_signal(&qe->icpr_cond);
#endif
	    }
	}
	pthread_mutex_unlock(&qe->icpr_mutex);
	return(1);
    }
    pthread_mutex_unlock(&qe->icpr_mutex);
    return(0);
}

int
process_hit(void *le, void *arg)
{
struct	icp_lookup		*icp_lookup = arg;
struct	icp_queue_elem		*qe = le;
int				rq_n;

    if ( !qe || !icp_lookup ) return(0);
    rq_n = icp_lookup->rq_n;
    my_log("hit called\n");
    pthread_mutex_lock(&qe->icpr_mutex);
    if ( rq_n == qe->rq_n ) {
	my_log("icp_req still here\n");
	qe->requests_sent--;
	if ( qe->waitors) {
	    qe->type    = icp_lookup->type;
	    qe->peer_sa = icp_lookup->sa;
	    qe->status  = TRUE;
#if	!defined(LINUX)
	    pthread_cond_signal(&qe->icpr_cond);
#endif
	}
	pthread_mutex_unlock(&qe->icpr_mutex);
	return(1);
    }
    pthread_mutex_unlock(&qe->icpr_mutex);
    return(0);
}
