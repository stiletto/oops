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

#define		ST_LSEEK(a,b,c)		lseek(a,storage->i_off + b,c)
#define		ST_PREAD(a,b,c,d)	pread(a,b,c,d+storage->i_off)
#define		ST_PWRITE(a,b,c,d)	pwrite(a,b,c,d+storage->i_off)

#define		ROUNDPG(x)		(((x)/STORAGE_PAGE_SIZE + ((x)%STORAGE_PAGE_SIZE?1:0))*STORAGE_PAGE_SIZE)
#define		BLKSIZE			STORAGE_PAGE_SIZE
#define		MAGIC			(0x0bdcdada)

int		buff_to_blks(struct buff *b, struct storage_st * storage, uint32_t *n, uint32_t needed);

int		skip_check;

void
set_bits(char *map, int from, int num)
{
int		cur_bit = from;
int		cur_word ;
int		bit_off, leave_to_fill = num, fill_here;
uint32_t	mask, mask2, *pvalue;

    if ( !num ) return;

    while ( leave_to_fill ) {
	cur_word = cur_bit/32;
	bit_off  = cur_bit%32;
	/*
	     |
	     V
	    mmmmmmmmmmmmmmmm.mmmmmmmmmmmmmmmm
	    0 >>>>>>>>>>>>   16             
	*/
	fill_here = MIN(leave_to_fill, 32-bit_off);
	mask = ~((1<<bit_off)-1);
	if ( bit_off+fill_here < 32 ) {
	    mask2 = ~((1<<(bit_off+fill_here))-1);
	    mask &= ~mask2;
	}

	pvalue = (uint32_t*)map + cur_word ;
	*pvalue |= (mask);

        leave_to_fill -= fill_here;
	cur_bit       += fill_here;
    }
}

void
clr_bits(char *map, int from, int num)
{
int		cur_bit = from;
int		cur_word ;
int		bit_off, leave_to_fill = num, fill_here;
uint32_t	mask, mask2, *pvalue;

    if ( !num ) return;

    while ( leave_to_fill ) {
	cur_word = cur_bit/32;
	bit_off  = cur_bit%32;
	/*
	     |
	     V
	    mmmmmmmmmmmmmmmm.mmmmmmmmmmmmmmmm
	    0 >>>>>>>>>>>>   16             
	*/
	fill_here = MIN(leave_to_fill, 32-bit_off);
	mask = ~((1<<bit_off)-1);
	if ( bit_off+fill_here < 32 ) {
	    mask2 = ~((1<<(bit_off+fill_here))-1);
	    mask &= ~mask2;
	}

	pvalue = (uint32_t*)map + cur_word ;
	*pvalue &= ~(mask);

        leave_to_fill -= fill_here;
	cur_bit       += fill_here;
    }
}

int
test_map_bit(char *map, int from)
{
int		cur_bit = from;
int		cur_word ;
int		bit_off;
uint32_t	mask, *pvalue;

    cur_word = cur_bit/32;
    bit_off  = cur_bit%32;
    mask = 1 << bit_off;
    pvalue = (uint32_t*)map + cur_word ;
    return(*pvalue & mask);
}

int
find_free_bit(char *map, int from, int to)
{
int		cur_bit = from;
int		cur_word, i ;
int		bit_off, leave_to_find, find_here;
uint32_t	mask, mask2, pvalue;

    leave_to_find = to-from;
    if ( leave_to_find <= 0 ) return(0);
    while( leave_to_find ) {
	cur_word = cur_bit/32;
	bit_off  = cur_bit%32;
	find_here = MIN(leave_to_find, 32-bit_off);
	mask = ~((1<<bit_off)-1);
	if ( bit_off+find_here < 32 ) {
	    mask2 = ~((1<<(bit_off+find_here))-1);
	    mask &= ~mask2;
	}
	/* mask now cover interesting region */

	pvalue = *((uint32_t*)map + cur_word);
	pvalue &= mask;
	pvalue |=~mask;
	/*
	   pvalue now contain real bits in region of our interest
	   and 11111...1 where we are not interested
	*/
	if ( pvalue != 0xffffffff ) {
	    pvalue = ~pvalue;
	    for(i=0;i<32;i++) {
		if ( 0x1 & pvalue ) return(cur_word*32+i);
		pvalue >>= 1;
	    }
	}
	leave_to_find -= find_here;
	cur_bit	  += find_here;
    }
    return(0);
}

int
calc_free_bits(char *map, int from, int to)
{
int		cur_bit = from;
int		cur_word, i ;
int		bit_off, leave_to_find, find_here;
uint32_t	mask, mask2, pvalue;
int		free_bits = 0;

    leave_to_find = to-from;
    if ( leave_to_find <= 0 ) return(0);
    while( leave_to_find ) {
	cur_word = cur_bit/32;
	bit_off  = cur_bit%32;
	find_here = MIN(leave_to_find, 32-bit_off);
	mask = ~((1<<bit_off)-1);
	if ( bit_off+find_here < 32 ) {
	    mask2 = ~((1<<(bit_off+find_here))-1);
	    mask &= ~mask2;
	}
	/* mask now cover interesting region */

	pvalue = *((uint32_t*)map + cur_word);
	pvalue &= mask;
	pvalue |=~mask;
	/*
	   pvalue now contain real bits in region of our interest
	   and 11111...1 where we are not interested
	*/
	if ( pvalue != 0xffffffff ) {
	    pvalue = ~pvalue;
	    for(i=0;i<32;i++) {
		if ( 0x1 & pvalue ) free_bits++;
		pvalue >>= 1;
	    }
	}
	leave_to_find -= find_here;
	cur_bit	  += find_here;
    }
    return(free_bits);
}


int
db_things_init()
{
    return 0;
}

void
init_storage(struct storage_st *storage)
{
fd_t		fd = (fd_t)-1;
int		map_words;
uint32_t	blk_num;
char		*map_ptr=NULL;


    rwl_init(&storage->storage_lock);
    if (!(storage->flags & ST_CHECKED) )
	return;
    WRLOCK_STORAGE(storage);
    if ( !storage->path ) {
	my_xlog(LOG_SEVERE, "init_storage(): No path for storage.\n");
	goto error;
    }
    fd = open_storage(storage->path, O_RDWR|O_SUPPL);
    if ( fd == (fd_t)-1 ) {
	my_xlog(LOG_SEVERE, "init_storage(): Can't open storage: %m\n");
	goto error;
    }
    storage->fd = fd;
    /* read super */
#if	defined(HAVE_PREAD) && defined(HAVE_PWRITE)
    if ( ST_PREAD(fd, &storage->super, sizeof(storage->super), 0) !=
#else
    if ( ST_LSEEK(fd, 0, SEEK_SET) == -1 ) {
	my_xlog(LOG_SEVERE, "init_storage(): seek(%s, %u): %m\n", storage->path, 0);
	goto error;
    }
    if ( read(fd, &storage->super, sizeof(storage->super)) != 
#endif	/* PREAD && PWRITE */
	sizeof(storage->super) ) {
	my_xlog(LOG_SEVERE, "init_storage(): Can't read super: %m\n");
	goto error;
    }
    if ( storage->super.magic != htonl(MAGIC) ) {
	my_xlog(LOG_SEVERE, "init_storage(): Wrong magic.\n");
	goto error;
    }
    blk_num = storage->super.blks_total;
    map_words = blk_num/32 + (blk_num%32?1:0);
    map_ptr = xmalloc(map_words*4, "init_storage(): map_ptr");
    if ( !map_ptr ) {
	goto error;
    }
#if	defined(HAVE_PREAD) && defined(HAVE_PWRITE)
    if ( ST_PREAD(fd, map_ptr, map_words*4, STORAGE_PAGE_SIZE) != map_words*4 )
#else
    ST_LSEEK(fd, STORAGE_PAGE_SIZE, SEEK_SET);
    if ( read(fd, map_ptr, map_words*4) != map_words*4 )
#endif	/* PREAD && PWRITE */
	goto error;
    storage->map = map_ptr;
    storage->size = (off_t)STORAGE_PAGE_SIZE*blk_num;
    /* ready */

    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "init_storage(): Storage %s ready.\n", storage->path);
    storage->flags = ST_READY;
    UNLOCK_STORAGE(storage);
    return;

error:
    my_xlog(LOG_SEVERE, "init_storage(): Storage %s unusable.\n", storage->path);
    if ( fd != (fd_t)-1 ) close_storage(fd);
    storage->fd = (fd_t)-1;
    if ( map_ptr ) xfree(map_ptr);
    UNLOCK_STORAGE(storage);
    return;
}

void
free_storage(struct storage_st *storage)
{

    WRLOCK_STORAGE(storage);
    if ( TEST(storage->flags, ST_READY) ) {
	flush_super(storage);
	flush_map(storage);
	if ( storage->fd != (fd_t)-1 ) {
	    close_storage(storage->fd);
	    storage->fd = (fd_t)-1;
	}
    }
    if ( storage->path ) xfree(storage->path) ;
    if ( storage->map) xfree(storage->map);
    rwl_destroy(&storage->storage_lock);
    free(storage);
}

/*
 * request n free blocks from the storage
 * if failed - return 0, nothing changed for storage
 * if succeed - return reference to start block of the allocated chain
 * Must be called for locked storage
 */
char*
request_free_blks(struct storage_st * storage, uint32_t n)
{
uint32_t	current, o = n, *p, *po, i;
char		*allocated = NULL;

    if ( !storage )
	goto error;
    if ( !(storage->flags & ST_READY) )
	goto error;
    if ( storage->super.blks_free < n )
	goto error;
    allocated =
	xmalloc(sizeof(struct disk_ref)+n*sizeof(uint32_t),"request_free_blks(): rqfb");
    if ( !allocated ) goto error;
    p = po = (uint32_t*)(allocated+sizeof(struct disk_ref));
    current = 0;
    while ( n ) {
	current = find_free_bit(storage->map, current+1, storage->super.blks_total) ;
	if ( !current ) {
	    my_xlog(LOG_SEVERE, "request_free_blks(): Severe error on block %u", n);
	    goto error;
	}
	n--;
	*p++ = current;
    }
    storage->super.blks_free -= o;
    /* mark blocks as busy */
    for (i=0;i<o;i++,po++) {
	if ( !*po ) {
	    my_xlog(LOG_SEVERE, "request_free_blks(): Try to set 0 bit.\n");
	    do_exit(1);
	}
	if ( test_map_bit(storage->map, *po) ) {
	    my_xlog(LOG_SEVERE, "request_free_blks(): Trying to set busy bit %d\n", *po);
	    do_exit(1);
	}
	set_bits(storage->map, *po, 1);
    }
    return allocated;

error:
    if ( allocated ) xfree(allocated);
    return NULL;
}

/* return chain to free list		*/
/* must be called from locked state	*/
int
release_blks(uint32_t n, struct storage_st *storage, struct disk_ref *disk_ref)
{
uint32_t *next_blk;
int	 released;

    if ( !storage )
	goto error;
    if ( !(storage->flags & ST_READY) )
	goto error;
    if ( !disk_ref ) {
	my_xlog(LOG_SEVERE, "release_blks(): Fatal: zero disk_ref.\n");
	do_exit(1);
    }

    next_blk = (uint32_t*)(disk_ref+1);
    released = disk_ref->blk ;

    if ( !released ) {
	my_xlog(LOG_SEVERE, "release_blks(): Fatal: why to release 0 blks.\n");
	do_exit(1);
    }
    storage->super.blks_free += released;
    while( released ) {
	if ( !*next_blk ) {
	    my_xlog(LOG_SEVERE, "release_blks(): Fatal: attempt to release 0 blk.\n");
	    do_exit(1);
	}
	if ( TEST(storage->flags, ST_CHECKED) && !test_map_bit(storage->map, *next_blk) ) {
	    my_xlog(LOG_SEVERE, "release_blks(): Trying to free free bit.\n");
	    do_exit(1);
	}
	clr_bits(storage->map, *next_blk, 1);
	released--;
	next_blk++;
    }
    return(0);

error:
    fprintf(stderr, "release_blks(): Failed to release blks.\n");
    return -1;
}

int
flush_super(struct storage_st *storage)
{
int	rc;

#if	defined(HAVE_PREAD) && defined(HAVE_PWRITE)
    rc = ST_PWRITE(storage->fd, &storage->super, sizeof(storage->super), 0);
#else
    rc = ST_LSEEK(storage->fd, 0, SEEK_SET);
    if ( rc == -1 )
	return(1);
    rc = write(storage->fd, &storage->super, sizeof(storage->super));
#endif	/* PREAD && PWRITE */
    return(0);
}

int
flush_map(struct storage_st *storage)
{
int		rc;
int		map_words;
uint32_t	blk_num;

    blk_num = storage->super.blks_total;
    map_words = blk_num/32 + (blk_num%32?1:0);
#if	defined(HAVE_PREAD) && defined(HAVE_PWRITE)
    rc = ST_PWRITE(storage->fd, storage->map, map_words*4, BLKSIZE);
#else
    rc = ST_LSEEK(storage->fd, BLKSIZE, SEEK_SET);
    if ( rc == -1 )
	return(1);
    rc = write(storage->fd, storage->map, map_words*4);
#endif	/* PREAD && PWRITE */
    return(0);
}

int
move_obj_to_storage(struct mem_obj *obj, struct storage_st **st,
		    struct disk_ref **chain)
{
struct	storage_st	*storage, *ostorage;
uint32_t		needed_blocks, obj_size = 0;
struct	buff		*b;
uint32_t		*blk;
struct	disk_ref	*disk_ref;

    if ( *chain ) *chain = NULL;
    if ( !obj )
	return 0;
    b = obj->container;
    if ( !b )
	return 0;

    obj_size = obj->size;

    if ( !obj_size )
	return 0;

    needed_blocks = ROUND(obj_size, BLKSIZE)/BLKSIZE;
    my_xlog(LOG_STOR|LOG_DBG, "move_obj_to_storage(): Allocate %u disk blocks for object.\n",
	    needed_blocks);

    storage = ostorage = next_alloc_storage;
    if ( !ostorage ) storage = storages;
    while( storage ) {
	WRLOCK_STORAGE(storage);
	if ( (storage->flags & ST_READY) && !(storage->flags & ST_FORCE_CLEANUP) ) {
	    if ( (disk_ref = (struct disk_ref*)request_free_blks(storage, needed_blocks)) !=0 ) {
		blk = (uint32_t*)((char*)disk_ref + sizeof(struct disk_ref));
		buff_to_blks(obj->container, storage, blk, needed_blocks);
		*st = storage;
		UNLOCK_STORAGE(storage);
		next_alloc_storage = storage->next;
		*chain = disk_ref;
		return needed_blocks;
	    }
	}
	UNLOCK_STORAGE(storage);
	storage = storage->next;
	if ( storage == ostorage ) break;
	if ( !storage ) storage = storages;
    }
    return 0;
}

int
buff_to_blks(struct buff *b, struct storage_st * storage, uint32_t *n, uint32_t needed)
{
char		*c;
int		to_move, rc, space;
#if	defined(HAVE_PWRITE)
off_t		next_position;
#endif

#if	defined(HAVE_PWRITE)
    next_position = *n*BLKSIZE;
#else
    ST_LSEEK(storage->fd, *n*BLKSIZE, SEEK_SET);
#endif	/* HAVE_PWRITE */

    space = BLKSIZE;
    while ( b && needed ) {
	c = b->data;
	to_move = b->used;
    cwb:
	if ( !to_move ) goto nextb;
	if ( to_move <= space ) {
#if	defined(HAVE_PWRITE)
	    rc = ST_PWRITE(storage->fd, c, to_move, next_position);
	    next_position += to_move;
#else
	    rc = write(storage->fd, c, to_move);
#endif	/* HAVE_PWRITE */
	    space -= to_move;
	    if ( space <= 0 ) {
		needed--;
		n++;
		space = BLKSIZE;
#if	defined(HAVE_PWRITE)
		next_position = *n*BLKSIZE;
#else
		ST_LSEEK(storage->fd, *n*BLKSIZE, SEEK_SET);
#endif	/* HAVE_PWRITE */
	    }
	    to_move = 0;
	} else {
#if	defined(HAVE_PWRITE)
	    rc = ST_PWRITE(storage->fd, c, space, next_position);
#else
	    rc = write(storage->fd, c, space);
#endif	/* HAVE_PWRITE */
	    needed--;
	    to_move -= space;
	    c += space;
	    space = BLKSIZE;
	    n++;
#if	defined(HAVE_PWRITE)
	    next_position = *n*BLKSIZE;
#else
	    ST_LSEEK(storage->fd, *n*BLKSIZE, SEEK_SET);
#endif	/* HAVE_PWRITE */
	    goto cwb;
	}

    nextb:
	b = b->next;
    }
    return(0);
}

struct storage_st *
locate_storage_by_id(uint32_t id)
{
struct storage_st *res = storages;

    while(res) {
	if ( res->super.id == id )
	    return res;
	res = res->next;
    }
    return(res);
}

/* find URL in storages.
 */
int
locate_url_on_disk(struct url *url, struct disk_ref **disk_ref)
{
char			*url_str;
int			urll, rc;
DBT			key, data;
struct storage_st	*storage;
char			http_p;

    *disk_ref = NULL;
    if ( !dbp )
	return(-1);
    urll = strlen(url->proto)+strlen(url->host)+strlen(url->path)+10;
    urll+= 3 + 1; /* :// + \0 */
    url_str = xmalloc(ROUND(urll, CHUNK_SIZE), "locate_url_on_disk(): url_str");
    if ( !url_str )
	return(-1);
    http_p = !strcmp(url->proto, "http");
    if ( http_p )
	sprintf(url_str,"%s%s:%d", url->host, url->path, url->port);
    else
	sprintf(url_str,"%s://%s%s:%d", url->proto, url->host, url->path, url->port);
    bzero(&key,  sizeof(key));
    bzero(&data, sizeof(data));
    key.data = url_str;
    key.size = strlen(url_str);
    data.flags = DB_DBT_MALLOC;
    rc = dbp->get(dbp, NULL, &key, &data, 0);
    switch ( rc ) {
	case EAGAIN:
		my_xlog(LOG_SEVERE, "locate_url_on_disk(): Deadlock in db->get(%s).\n",
			key.data);
		xfree(url_str);
		return(-1);
	case 0:
		xfree(url_str);
		*disk_ref = data.data;
		if ( !(storage = locate_storage_by_id((*disk_ref)->id)) ) {
		    *disk_ref = NULL;
		    free(data.data);
		    return(-1);
		}
		return(0);
	case DB_NOTFOUND:
		my_xlog(LOG_DBG, "locate_url_on_disk(): %s not found.\n", key.data);
		xfree(url_str);
		return(-1);
	default:
		my_xlog(LOG_SEVERE, "locate_url_on_disk(): Unknown answer from db->get(%s): %d\n",
			key.data, rc);
		xfree(url_str);
		return(-1);
    }
}

int
load_obj_from_disk(struct mem_obj *obj, struct disk_ref *disk_ref)
{
struct 	buff		*b;
size_t			to_load;
off_t			next_read;
uint32_t		*n;
int			rc;
fd_t			fd = (fd_t)-1;
struct	storage_st	*storage;
struct	server_answ	a;
char			answer[BLKSIZE+1];

    if ( !obj )
	return(-1);
    b = alloc_buff(CHUNK_SIZE);
    if ( !b )
	return(-1);
    obj->container 	= obj->hot_buff = b;
    to_load		= disk_ref->size;
    n			= (uint32_t*)(disk_ref+1);
    storage = locate_storage_by_id(disk_ref->id);
    if ( !storage )
	goto err;
    /* storage can be not locked as we use separate fd	*/
#if	defined(HAVE_PREAD) && defined(HAVE_PWRITE)
    /* If we have pread we even don't need another fd	*/
    fd = storage->fd;
#else
    fd = open_storage(storage->path, O_RDONLY|O_SUPPL);
#endif	/* PREAD && PWRITE */
    if ( fd == (fd_t)-1 )
	goto err;
    bzero(&a, sizeof(a));

s:  
#if	!defined(HAVE_PREAD)
    rc = ST_LSEEK(fd, *n*BLKSIZE, SEEK_SET);
    if ( rc == -1 )
	goto err;
#endif

r:
    next_read = MIN(BLKSIZE, to_load);
#if	defined(HAVE_PREAD)
    rc = ST_PREAD(fd, answer, next_read, *n*BLKSIZE);
#else
    rc =  read(fd, answer, next_read);
#endif	/* HAVE_PREAD */
    if ( rc != next_read )
	goto err;
    if ( !(a.state & GOT_HDR) ) {
	attach_data(answer, rc, obj->container);
	if ( check_server_headers(&a, obj, b, NULL) )
	    goto err;
        if ( a.state & GOT_HDR ) {
	    obj->times 		= a.times;
	    obj->response_time  = a.response_time;
	    obj->request_time	= a.request_time;
	    obj->status_code 	= a.status_code;
	    obj->flags	       |= a.flags;
	    obj->x_content_length = a.x_content_length;
	}
    } else {
	if ( store_in_chain(answer, rc, obj) )
	    goto err;
    }
    to_load 	-= rc;
    if ( (int)to_load > 0 ) {
	if ( *(n+1) == (*n)+1 ) {
	    n++;
	    goto r;
	} else {
	    n++;
	    goto s;
	}
    }
    obj->state = OBJ_READY;
    obj->size  = disk_ref->size;
#if	!defined(HAVE_PREAD) || !defined(HAVE_PWRITE)
    if ( fd != (fd_t)-1 ) close_storage(fd);
#endif
    return(0);

err:
    free_container(obj->container); obj->container = NULL;
#if	!defined(HAVE_PREAD) || !defined(HAVE_PWRITE)
    if ( fd != (fd_t)-1 ) close_storage(fd);
#endif
    return(-1);
}

int
erase_from_disk(char *url_str, struct disk_ref *disk_ref)
{
int			rc;
DBT			key;
struct storage_st	*storage;

    if ( !dbp || !url_str)
	return(-1);

    storage = locate_storage_by_id(disk_ref->id);
    if ( !storage ) goto done;

    my_xlog(LOG_STOR|LOG_DBG, "erase_from_disk(): Cleaning %s from storage %s\n",
	    url_str, storage->path);
    /* remove it from db */
    bzero(&key,  sizeof(key));
    key.data = url_str;
    key.size = strlen(url_str);
    rc = 0;
    rc = dbp->del(dbp, NULL, &key, 0);
    switch ( rc ) {
	case 0:
		/*dbp->sync(dbp, 0);*/
		break;
	case DB_NOTFOUND:
		my_xlog(LOG_SEVERE, "erase_from_disk(): Record `%s' not found.\n",
			url_str);
		return(-1);
	default:
		my_xlog(LOG_SEVERE, "erase_from_disk(): Error: %m\n");
		return(-1);
    }
    WRLOCK_STORAGE(storage);
    release_blks(disk_ref->blk, storage, disk_ref);
    UNLOCK_STORAGE(storage);

done:
    return(0);
}

void
check_storage(struct storage_st *storage)
{
struct	storage_st	tstorage;
char			*s, *bitmap;
int			rc, map_words, obj_n = 0;
fd_t			fd;
uint32_t		*start_blk, *n, blks, oblks, blk_num, i, in_map_free;
struct	disk_ref	*disk_ref;
DBT			key, data;
DBC			*dbcp;
struct memb {
	uint32_t        next;
	uint32_t        flags; 
	uint32_t        refs;  
};                             
struct  memb    *map = NULL;

    if ( !dbp )
	return;
    if ( !storage ) {
	return;
    }
    CLR(storage->flags, ST_CHECKED);
    tstorage = *storage;
    if ( !tstorage.path )
	return;

    tstorage.fd = open_storage(tstorage.path, O_RDWR|O_SUPPL);
    if ( tstorage.fd == (fd_t)-1 )
	return;
    fd = tstorage.fd;
#if	defined(HAVE_PREAD) && defined(HAVE_PWRITE)
    if ( ST_PREAD(fd, &tstorage.super, sizeof(tstorage.super), 0) != 
#else
    if ( ST_LSEEK(fd, 0, SEEK_SET) == -1 ) {
	my_xlog(LOG_SEVERE, "check_storage(): seek(%s, %u): %m\n", tstorage.path, 0);
	close_storage(fd);
	return;
    }
    if ( read(fd, &tstorage.super, sizeof(tstorage.super)) != 
#endif	/* PREAD && PWRITE */
	sizeof(tstorage.super) ) {
	my_xlog(LOG_SEVERE, "check_storage(): Can't read super: %m\n");
	close_storage(fd);
	return;
    }
    if ( tstorage.super.magic != htonl(MAGIC) ) {
	my_xlog(LOG_SEVERE, "check_storage(): Wrong magic.\n");
	close_storage(fd);
	return;
    }
    SET(tstorage.flags, ST_READY);
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Checking storage %s\n", tstorage.path);
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Super: %d total\n", tstorage.super.blks_total);
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage():        %d free\n", tstorage.super.blks_free );
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage():        %d blk size\n", tstorage.super.blk_siz);
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage():        %x - magic\n", ntohl(tstorage.super.magic));
    blk_num   =	tstorage.super.blks_total;
    map_words = blk_num/32 + (blk_num%32?1:0);
    tstorage.size = tstorage.super.blks_total*(off_t)STORAGE_PAGE_SIZE;
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Read map.\n");
    bitmap = calloc(map_words*4, 1);
    if ( !bitmap ) {
	my_xlog(LOG_SEVERE, "check_storage(): Can't allocate memory for map.\n");
	goto abor;
    }
#if	defined(HAVE_PREAD) && defined(HAVE_PWRITE)
    if ( ST_PREAD(fd, bitmap, map_words*4, BLKSIZE) != map_words*4 ) {
#else
    ST_LSEEK(fd, BLKSIZE, SEEK_SET);
    if ( read(fd, bitmap, map_words*4) != map_words*4 ) {
#endif	/* PREAD && PWRITE */
	my_xlog(LOG_SEVERE, "check_storage(): Can't read map.\n");
	goto abor;
    }
    tstorage.map = bitmap;
    /*in_map_free = calc_free_bits(bitmap, 0, blk_num);*/
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Done.\n");
    map = calloc(blk_num, sizeof(struct memb));
    if ( !map ) {
	my_xlog(LOG_SEVERE, "check_storage(): Can't allocate memory for map.\n");
	goto abor;
    }
    rc = dbp->cursor(dbp, NULL, &dbcp
#if     (DB_VERSION_MAJOR>2) || (DB_VERSION_MINOR>=6)
				     , 0
#endif
    					);
    if ( rc ) {
	my_xlog(LOG_SEVERE, "check_storage(): Can't create cursor for checking.\n");
	dbp->close(dbp, 0);
	dbp = NULL;
	goto abor;
    }

do_scan:
    if ( MUST_BREAK )
	goto abor;
    bzero(&key,  sizeof(key));
    bzero(&data, sizeof(data));
    key.flags = data.flags = DB_DBT_MALLOC;
    rc = dbcp->c_get(dbcp, &key, &data, DB_NEXT);
    switch ( rc ) {
	case 0:
		disk_ref = data.data;
		break;
	case DB_NOTFOUND:
		my_xlog(LOG_SEVERE, "check_storage(): Done with it.\n");
		dbcp->c_close(dbcp);
		goto fix_unrefs;
	default:
		my_xlog(LOG_SEVERE, "check_storage(): Can't find url: %d\n", rc);
		dbp->close(dbp, 0);
		dbp = NULL;
		goto abor;
    }
    if ( disk_ref->id != tstorage.super.id ) {
	free(key.data);
	free(data.data);
	goto do_scan;
    }
    obj_n++;
    start_blk = n = (uint32_t*)(disk_ref+1);
    oblks = disk_ref->blk;
    blks = 0;

s:
    map[*n].refs++;
    if ( map[*n].refs > 1 ) {
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Crossref.\n");
	/* 1. free all blocks for this obj until this */
	while ( *start_blk < blk_num) {
		clr_bits(bitmap, *start_blk, 1);
		map[*start_blk].refs--;
		tstorage.super.blks_free++;
		if ( start_blk==n) break;
		start_blk++;
		/* fix in super */
	};
	map[*n].refs = 1;
	xfree(data.data);
	xfree(key.data);
	/* remove from base */
	dbcp->c_del(dbcp, 0);
	dbp->sync(dbp, 0);
	flush_super(&tstorage);
	flush_map(&tstorage);
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Resolved.\n");
	goto do_scan;
    }
    if ( !test_map_bit(bitmap, *n) ) {
	my_xlog(LOG_SEVERE, "check_storage(): Error: Free block in object %d\n", obj_n);
	while (*start_blk < blk_num ) {
	    /* fix in mem  */
	    map[*start_blk].refs--;
	    if ( start_blk==n ) break;
	    start_blk++;
	};
	release_blks(disk_ref->blk, &tstorage, disk_ref);
	dbcp->c_del(dbcp, 0);
	dbp->sync(dbp, 0);
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Resolved.\n");
	goto do_scan;
    }
    blks++;
    if ( blks < oblks ) {
	n++;
	goto s;
    }
    s = NULL;
/*
    s = malloc(key.size+1);
    if ( !s ) {
	my_xlog(LOG_SEVERE, "check_storage(): No memory.\n");
	dbp->close(dbp, 0);
	do_exit(1);
    }
    strncpy(s, key.data, key.size);
    s[key.size] = 0;
    fprintf(stderr, "check_storage(): %s: %d blocks.\n", s, blks);
    free(s);
*/
    free(key.data);
    free(data.data);
    blks = 0;
    goto do_scan;

fix_unrefs:
    in_map_free = 0;
    for (i=0;i<blk_num;i++) {
	if ( !map[i].refs ) in_map_free++;
    }
    in_map_free--; /* super */
    in_map_free -= ROUNDPG(map_words*4)/STORAGE_PAGE_SIZE;
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Found %d free blocks in map, %d in superblock\n",
	    in_map_free, tstorage.super.blks_free);
    if ( in_map_free != tstorage.super.blks_free ) {
	int map_blks = ROUNDPG(map_words*4)/STORAGE_PAGE_SIZE;
	int busy_b = 0;
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Fixing free map.\n");
	tstorage.super.blks_free = in_map_free;
	bzero(bitmap, map_words*4);
	set_bits(bitmap, 0, 1+map_blks);
	for(i=1+map_blks;i<tstorage.super.blks_total;i++) {
	    if ( map[i].refs ) {
		set_bits(bitmap, i, 1);
		busy_b++;
	    }
	}
	tstorage.super.blks_free = blk_num - 1 - map_blks - busy_b ;
	flush_super(&tstorage);
	flush_map(&tstorage);
    } else {
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "check_storage(): Free list ok.\n");
    }
    SET(storage->flags, ST_CHECKED);

abor:
    close_storage(fd);
    if ( map ) free(map);
    if ( bitmap ) free(bitmap);
}

void
check_storages(struct storage_st *storage)
{
    pthread_mutex_lock(&st_check_in_progr_lock);
    st_check_in_progr = TRUE;
    while(storage) {
	check_storage(storage);
	if ( MUST_BREAK )
	    break;
	storage=storage->next;
    }
    st_check_in_progr = FALSE;
    pthread_mutex_unlock(&st_check_in_progr_lock);
    return;
}

void*
prep_storages(void *arg)
{
    arg=arg;
    RDLOCK_CONFIG;
    if (!skip_check) {
	check_storages(storages);
    } else {
	/* mark all as ready */
	struct storage_st *storage = storages;
	while(storage) {
	    SET(storage->flags, ST_CHECKED);
	    storage = storage->next;
	}
    }
    init_storages(storages);
    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "prep_storages(): Storages checked.\n");
    UNLOCK_CONFIG;
    return(0);
}

void
prepare_storages(void)
{
pthread_t	pid;
pthread_attr_t	attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#if	!defined(FREEBSD) && !defined(_WIN32)
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
#endif
    pthread_create(&pid, &attr, &prep_storages, NULL);
    pthread_attr_destroy(&attr);
}

void
do_format_storages()
{
struct storage_st *storage = storages;
off_t		size;
uint32_t	blk_num;
int		fd = 0;
char		c;
struct	superb	super;
struct	timeval	tv;
int		map_words, map_bits;
char		*map_ptr;

    while(storage) {
	if ( storage->size == -1 ) {
	    /* autodetect */
	    fd = open(storage->path, O_CREAT|O_RDWR|O_SUPPL, 0644);
	    if ( fd >= 0 ) {
		size = lseek(fd, 0, SEEK_END);
		size -= storage->i_off;
#if	defined(_AIX)
		if ( size <= 0) {
		    struct	devinfo	dinfo;
		    int		rc;
		    if ( (rc = ioctl(fd, IOCINFO, &dinfo)) == 0) {
			if ( dinfo.devsubtype == 'p' ) {
			    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "do_format_storages(): The %s is a physical volume\n",
				    storage->path);
			    size = (off_t)dinfo.un.scdk.numblks * (off_t)dinfo.un.scdk.blksize;
			    if ( storage->i_off < (off_t)512 ) {
				storage->i_off = (off_t)512;
#if	defined(_LARGE_FILE_API) && defined(WITH_LARGE_FILES)
				my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "do_format_storages(): Setting `offset' value to %lld for %s storage\n",
#else
				my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "do_format_storages(): Setting `offset' value to %ld for %s storage\n",
#endif
					storage->i_off, storage->path);
			    }
			    size -= storage->i_off;
			}
			if ( dinfo.devsubtype == 'l' ) {
			    struct	lv_info	lvinfo;
			    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "do_format_storages(): The %s is a logical volume\n",
				    storage->path);
			    if ( (rc = ioctl(fd, LV_INFO, &lvinfo)) == 0) {
				size = (off_t)lvinfo.num_blocks * (off_t)512;
				if ( storage->i_off < (off_t)512 ) {
				    storage->i_off = (off_t)512;
#if	defined(_LARGE_FILE_API) && defined(WITH_LARGE_FILES)
				    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "do_format_storages(): Setting `offset' value to %lld for %s storage\n",
#else
				    my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "do_format_storages(): Setting `offset' value to %ld for %s storage\n",
#endif
					    storage->i_off, storage->path);
				}
				size -= storage->i_off;
			    } else
				my_xlog(LOG_SEVERE, "do_format_storages(): Ioctl LV_INFO error for %s: %m\n",
					storage->path);
			}
		    } else
			my_xlog(LOG_SEVERE, "do_format_storages(): Ioctl IOCINFO error for %s: %m\n",
				storage->path);
		}
#elif	defined(LINUX)
		if ( size <= 0) {
		    off_t	numblks;
		    int		rc;
		    if ( (rc = ioctl(fd, BLKGETSIZE, &numblks)) == 0) {
			size = numblks * (off_t)512;
			size -= storage->i_off;
		    } else
			my_xlog(LOG_SEVERE, "do_format_storages(): Ioctl BLKGETSIZE error for %s: %m\n",
				storage->path);
		}
#elif	defined(BSDOS) || defined(FREEBSD)
		if ( size <= 0) {
		    struct	disklabel	dl;
		    struct	stat		st;
		    int		pn, rc;
		    if ( fstat( fd, &st) == -1 ) {
			my_xlog(LOG_SEVERE, "do_format_storages(): Fstat failed for %s: %m\n",
				storage->path);
			goto end_of_bsd;
		    }
		    if ( !S_ISCHR(st.st_mode) ) {
			my_xlog(LOG_SEVERE, "do_format_storages(): Not char special device for %s\n",
				storage->path);
			goto end_of_bsd;
		    }
		    if ( (rc = ioctl(fd, DIOCGDINFO, &dl)) == -1) {
			my_xlog(LOG_SEVERE, "do_format_storages(): Ioctl DIOCGDINFO error for %s: %m",
				storage->path);
			goto end_of_bsd;
		    }
		    if ( dl.d_magic != DISKMAGIC || dl.d_npartitions > MAXPARTITIONS ) {
			my_xlog(LOG_SEVERE, "do_format_storages(): Bad disklabel for %s\n",
				storage->path);
			goto end_of_bsd;
		    }
		    pn = st.st_rdev & 0x7;
		    size = (off_t)dl.d_partitions[pn].p_size * (off_t)dl.d_secsize;
		    size -= storage->i_off;
		end_of_bsd:;
		}
#endif
		close(fd);
	    } else {
		my_xlog(LOG_SEVERE, "do_format_storages(): Can't open file: %m\n");
		goto try_next;
	    }
	} else
	    size = ROUNDPG((storage->size)-(storage->i_off));
	blk_num = size/STORAGE_PAGE_SIZE;
	if ( blk_num < 2 ) {
	    my_xlog(LOG_SEVERE, "do_format_storages(): Storage size (%d bytes) is too small, skip it.\n",
		    storage->size);
	    goto try_next;
	}
#if	defined(WITH_LARGE_FILES)
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "do_format_storages(): Formatting storage %s for %lld bytes\n",
		storage->path, (long long)size);
#else
	my_xlog(LOG_NOTICE|LOG_DBG|LOG_INFORM, "do_format_storages(): Formatting storage %s for %d bytes\n",
		storage->path, size);
#endif
	gettimeofday(&tv, NULL);
	fd = open(storage->path, O_CREAT|O_RDWR|O_SUPPL, 0644);
	if ( fd == -1 ) {
	    my_xlog(LOG_SEVERE, "do_format_storages(): open(%s): %m\n",
		    storage->path);
	    goto try_next;
	}
	if ( ST_LSEEK(fd, size-1, SEEK_SET) == -1 ) {
	    my_xlog(LOG_SEVERE, "do_format_storages(): seek(%s, %u): %m\n",
		    storage->path, size-1);
	    goto try_next;
	}
	c = 0;
	write(fd, &c, 1);
	/* prepare super */
	super.magic = htonl(MAGIC);
	super.id = tv.tv_usec;
	super.blks_total = blk_num;	/* total blocks, including super */
	super.blks_free =  blk_num-1;	/* all free except super	 */
	super.blk_siz   =  BLKSIZE;
	super.free_last  = blk_num;
	map_words = blk_num/32 + (blk_num%32?1:0);
	super.blks_free -= ROUNDPG(map_words*4)/STORAGE_PAGE_SIZE;

	if ( ST_LSEEK(fd, 0, SEEK_SET) == -1 ) {
	    my_xlog(LOG_SEVERE, "do_format_storages(): seek(%s, %u): %m\n",
		    storage->path, 0);
	    goto try_next;
	}
	if ( write(fd, &super, sizeof(super)) != sizeof(super) ) {
	    my_xlog(LOG_SEVERE, "do_format_storages(): write super for %s: %m\n",
		    storage->path);
	    goto try_next;
	}
	/* how much 32-bit word we need for map? */
	map_bits  = blk_num;
	map_ptr = xmalloc(map_words*4,"do_format_storages(): map_ptr");
	if ( !map_ptr ) {
	    printf("do_format_storages(): Can't create map.\n");
	    goto try_next;
	}
	bzero(map_ptr, map_words*4);
	set_bits(map_ptr, 0, ROUNDPG(map_words*4)/STORAGE_PAGE_SIZE+1);
	ST_LSEEK(fd, STORAGE_PAGE_SIZE, SEEK_SET);
	write(fd, map_ptr, map_words*4);

try_next:
	printf("\n");
	if ( fd ) {
	    close(fd);
	    fd = 0;
	}
	storage=storage->next;
    }
}
