#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
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
	char			*buf;
	struct sockaddr_in	sa;
	char			type;
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

/* 1) Запросы посылаются всем.
	соседи в состоянии DOWN не учитываются для ожидания.
   2) При получении первого хита - обрыв ожидания, идем к тому от кого хит
   3) При получении MISS:
	уменьшить число ожидаемых ответов
	если MISS от парента - запомнить его.
	если число ожидаемых ответов стало нулевым - закончить ожидание
   Обработчик - если не получено хита и разрешено выходить напрямую -
   			идет напрямую
	      - если прямые соединения запрещены и есть мисс от парента -
	        идти к нему.
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
    sprintf(buf+sizeof(struct icp_hdr)+4, "%s://%s:%d%s",
			rq->url.proto,rq->url.host,
    			rq->url.port,rq->url.path);
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
	/* skip if we don't want to use this peers for this domain */
	if ( !is_domain_allowed(rq->url.host, peer->acls) ) {
	    peer = peer->next;
	    continue;
	}
	my_log("sending to: %s\n", peer->name);
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
	rr = sendto(icp_so, buf, len, 0, (struct sockaddr*)&peer->addr, sizeof(struct sockaddr_in));
	if ( rr != -1 ) {
	    if ( !TEST(peer->state, PEER_DOWN) ) succ++;
	} else {
	    my_log("Sendto: %s\n", strerror(errno));
	}
	peer = peer->next;
    }
    xfree(buf);
    if ( !succ ) return(-1);
    /* requests was sent */
    qe->requests_sent = succ;
    /* put qe in list	 */
    list_add(&icp_requests_list, &qe->ll);
    return(0);
}

void
icp_request_destroy(struct icp_queue_elem *icpr)
{
    /* unlink it from list */
    list_unlink_item(&icp_requests_list, &icpr->ll);
    pthread_cond_destroy(&icpr->icpr_cond);
    pthread_mutex_destroy(&icpr->icpr_mutex);
    xfree(icpr);
}
void
process_icp_msg(int so, char *buf, int len, struct sockaddr_in *sa)
{
struct	icp_hdr		*icp_hdr = (struct icp_hdr*)buf;
int			*intp;
char			*urlp;
int			r_h_a;
struct	url		url;
struct	mem_obj 	*res;
struct	peer		*peer;
struct	icp_lookup	icp_lookup;

    if ( len <= 0 )
	return;
/*    my_log("icp: opcode:  %d\n", icp_opcode);
    my_log("icp: version: %d\n", icp_version);
    my_log("icp: msg_len: %d\n", ntohs(icp_msg_len));
    my_log("icp: rq_n:    %d\n", ntohl(icp_rq_n));
    my_log("icp: opt:     %d\n", ntohl(icp_opt));
    my_log("icp: opt_data:%d\n", ntohl(icp_opt_data));
*/
    switch(icp_opcode) {
	case ICP_OP_INVALID:
		break;
	case ICP_OP_QUERY:
		LOCK_STATISTICS(oops_stat);
		    oops_stat.requests_icp++;
		UNLOCK_STATISTICS(oops_stat);
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
		my_log("ICP_OP_QUERY: %s\n", urlp);
		if ( parse_url(urlp, NULL, &url, -1) ) {
		    my_log("Wrong url\n");
		    send_icp_op_err(so, sa, htonl(icp_rq_n));
		    return;
		}

		res = locate_in_mem(&url, 0, NULL);
		if ( res ) {
		    my_log("ICP_MEM_HIT\n");
		    icp_opcode = ICP_OP_HIT;
		    icp_opt=0;
		    send_icp_op(so, sa, ICP_OP_HIT, htonl(icp_rq_n), urlp);
		} else {
		    struct disk_ref	*tmp_ref;
		    int			rc;
		    /* locate on storage */
		    RDLOCK_CONFIG;
		    RDLOCK_DB;
		    rc = locate_url_on_disk(&url, &tmp_ref);
		    UNLOCK_DB;
		    UNLOCK_CONFIG;
		    if ( rc >= 0 )xfree(tmp_ref);
		    if ( !rc ) {
			my_log("ICP_STOR_HIT\n");
			send_icp_op(so, sa, ICP_OP_HIT, htonl(icp_rq_n), urlp);
		    } else {
			my_log("ICP_MISS\n");
			send_icp_op(so, sa, ICP_OP_MISS, htonl(icp_rq_n), urlp);
		    }
		}
		free_url(&url);
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
		icp_lookup.sa  = *sa;
		icp_lookup.sa.sin_port = htons(peer->http_port);
		icp_lookup.type= peer->type;
		my_log("ICP_PEER_HIT from %s\n", peer->name);
		UNLOCK_CONFIG;
		/* looking up queue elem with the same rq_n	*/
		icp_lookup.buf = buf;
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
		icp_lookup.sa  = *sa;
		icp_lookup.sa.sin_port = htons(peer->http_port);
		icp_lookup.type= peer->type;
		my_log("ICP_PEER_MISS from %s\n", peer->name);
		UNLOCK_CONFIG;
		icp_lookup.buf = buf;
		/* looking up queue elem with the same rq_n	*/
		list_traverse(&icp_requests_list, process_miss, &icp_lookup);
		break;
	case ICP_OP_ERR:
		break;
	case ICP_OP_SECHO:
		break;
	case ICP_OP_DECHO:
		break;
	case ICP_OP_MISS_NOFETCH:
		break;
	case ICP_OP_DENIED:
		break;
	case ICP_OP_HIT_OBJ:
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
struct	icp_hdr			*icp_hdr = (struct icp_hdr*)icp_lookup->buf;
struct	icp_queue_elem		*qe = le;
int		rq_n;

    my_log("process_miss called\n");
    rq_n = icp_rq_n;
    if ( rq_n == qe->rq_n ) {
	my_log("ICP our request still here...\n");
	qe->requests_sent--;
	if ( !qe->requests_sent ) {
	    /* we will wait no answers more, so signal to start	*
	     * direct fetch					*
	     * that is: leave qe->status as is: clear		*/
	    pthread_mutex_lock(&qe->icpr_mutex);
	    if ( qe->waitors) {
		if ( icp_lookup->type == PEER_PARENT ) {
		    if ( !qe->peer_sa.sin_port ) {
			qe->type    = icp_lookup->type;
			/* store address of first parent 	*/
			qe->peer_sa = icp_lookup->sa;
			/* we don't change status to indicate	*
			 * this is not a hit			*/
		    }
		}
		my_log("Signalling\n");
		pthread_cond_signal(&qe->icpr_cond);
	    }
	    pthread_mutex_unlock(&qe->icpr_mutex);
	}
	return(1);
    }
    return(0);
}

int
process_hit(void *le, void *arg)
{
struct	icp_lookup		*icp_lookup = arg;
struct	icp_hdr			*icp_hdr = (struct icp_hdr*)icp_lookup->buf;
struct	icp_queue_elem		*qe = le;
int				rq_n;

    my_log("process_hit called\n");
    rq_n = icp_rq_n;
    if ( rq_n == qe->rq_n ) {
	my_log("ICP our request still here...\n");
	qe->requests_sent--;
	pthread_mutex_lock(&qe->icpr_mutex);
	if ( qe->waitors) {
	    qe->type    = icp_lookup->type;
	    qe->peer_sa = icp_lookup->sa;
	    qe->status = TRUE;
	    my_log("Signalling\n");
	    pthread_cond_signal(&qe->icpr_cond);
	}
	pthread_mutex_unlock(&qe->icpr_mutex);
	return(1);
    }
    return(0);
}
