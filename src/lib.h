#if	!defined(_LIB_H_INCLUDED_)
#define _LIB_H_INCLUDED_

inline	static	struct	buff *alloc_buff(int size);
inline	static	int	attach_av_pair_to_buff(char* attr, char *val, struct buff *buff);
inline	static	int	attach_data(char* src, int size, struct buff *buff);
inline	static	void	free_container(struct buff *buff);
inline	static	char	*my_inet_ntoa(struct sockaddr_in *sa);
inline	static	int	store_in_chain(char *src, int size, struct mem_obj *obj);

inline
static struct	buff *
alloc_buff(int size)
{
char		*t, *d;
struct buff	*b;

    if ( size <=0 ) return(NULL);
    t = xmalloc(sizeof(struct buff), "alloc_buff(): 1");
    if ( !t ) return(NULL);
    bzero(t, sizeof(struct buff));
    d = xmalloc(size, "alloc_buff(): 2");
    if ( !d ) {
	free(t);
	return(NULL);
    }
    b = (struct buff*)t;
    b->data = d;
    b->curr_size = size;
    b->used = 0;
    return(b);
}

inline
static int
attach_av_pair_to_buff(char* attr, char *val, struct buff *buff)
{
    if ( !attr || !val || !buff )return(-1);

    if ( *attr ) {
	attach_data(attr, strlen(attr), buff);
	attach_data(" ", 1, buff);
	attach_data(val, strlen(val), buff);
    }
    attach_data("\r\n", 2, buff);
    return(0);
}

/* concatenate data in continuous buffer */
inline
static int
attach_data(char* src, int size, struct buff *buff)
{
char	*t;
int	tot;

    if ( size <= 0 ) return(-1);
    if ( !buff->data ) {
	t = (char *)xmalloc(((size / CHUNK_SIZE) + 1) * CHUNK_SIZE, "attach_data(): 1");
	if (!t) return(-1);
	buff->data = t;
	memcpy(t, src, size);
	buff->curr_size = ((size / CHUNK_SIZE) + 1) * CHUNK_SIZE;
	buff->used = size;
	return(0);
    }
    if ( buff->used + size <= buff->curr_size ) {
	memcpy(buff->data+buff->used, src, size);
	buff->used += size;
    } else {
	tot = buff->used + size;
	tot = ((tot / CHUNK_SIZE) + 1) * CHUNK_SIZE;
	t = (char *)xmalloc(tot, "attach_data(): 2");
	if (!t ) {
	    my_xlog(OOPS_LOG_SEVERE, "attach_data(): No mem in attach data.\n");
	    return(-1);
	}
	memcpy(t, buff->data, buff->used);
	memcpy(t+buff->used, src, size);
	free(buff->data); buff->data = t;
	buff->used += size;
	buff->curr_size = tot;
    }
    return(0);
}

inline
static char *
attr_value(struct av *avp, char *attr)
{
char	*res = NULL;

    if ( !attr ) return(NULL);

    while( avp ) {
	if ( avp->attr && !strncasecmp(avp->attr, attr, strlen(attr)) ) {
	    res = avp->val;
	    break;
	}
	avp = avp->next;
    }
    return(res);
}

inline
static void
free_container(struct buff *buff)
{
struct buff *next;

    while(buff) {
	next = buff->next;
	/*my_xlog(OOPS_LOG_DBG, "free_container(): Free buffer: %d of %d, next: %p\n", buff->size, buff->curr_size, buff->next);*/
	if ( buff->data ) xfree(buff->data);
	xfree(buff);
	buff = next;
    }
}

inline
static char *
my_inet_ntoa(struct sockaddr_in *sa)
{
char * res = xmalloc(20, "my_inet_ntoa(): 1");
uint32_t	ia = ntohl(sa->sin_addr.s_addr);
uint32_t	a, b, c, d;

    if ( !res ) return(NULL);
    a =  ia >> 24;
    b = (ia & 0x00ff0000) >> 16;
    c = (ia & 0x0000ff00) >> 8;
    d = (ia & 0x000000ff);
    sprintf(res, "%d.%d.%d.%d",
	(unsigned)(ia >> 24),
	(unsigned)((ia & 0x00ff0000) >> 16),
	(unsigned)((ia & 0x0000ff00) >> 8),
	(unsigned)((ia & 0x000000ff)));
    return(res);
}

/* store in hot_buff, allocate buffs if need*/
inline
static int
store_in_chain(char *src, int size, struct mem_obj *obj)
{
struct buff *hot = obj->hot_buff, *new;

    if (!hot) {
	my_xlog(OOPS_LOG_SEVERE, "store_in_chain(): hot == NULL!\n");
	return(-1);
    }
    if (!obj) {
	my_xlog(OOPS_LOG_SEVERE, "store_in_chain(): obj == NULL!\n");
	return(-1);
    }
    if ( size < 0 ) {
	my_xlog(OOPS_LOG_SEVERE, "store_in_chain(): size = %d!\n", size);
	return(-1);
    }
    if ( hot->used + size <= hot->curr_size ) {
	memcpy( hot->data + hot->used, src, size);
	hot->used += size;
    } else {
	int	moved, to_move;
	/* copy part */
	memcpy(hot->data + hot->used, src, hot->curr_size - hot->used);
	moved=hot->curr_size - hot->used;
	hot->used = hot->curr_size;
	to_move = size - moved;
	/* allocate  */
	new = alloc_buff(ROUND_CHUNKS(to_move));
	if ( !new ) return(-1);
	/* copy rest */
	memcpy(new->data, src+moved, to_move);
	new->used = to_move;
	hot->next = new;
	obj->hot_buff = new;
    }
    return(0);
}

#endif	/* !_LIB_H_INCLUDED_ */
