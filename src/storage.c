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
#include	<sys/time.h>
#include	<fcntl.h>

#include	<netinet/in.h>

#include	<arpa/inet.h>

#include	<pthread.h>

#include	<db.h>

#include	"oops.h"

#define		ST_LSEEK(a,b,c)		lseek(a,storage->i_off + b,c)
#define		ST_PREAD(a,b,c,d)	pread(a,b,c,d+storage->i_off)
#define		ST_PWRITE(a,b,c,d)	pwrite(a,b,c,d+storage->i_off)

#define		ROUNDPG(x)		(((x)/STORAGE_PAGE_SIZE + \
					 ((x)%STORAGE_PAGE_SIZE?1:0))*STORAGE_PAGE_SIZE)
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
test_bit(char *map, int from)
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
	    fd = open(storage->path, O_CREAT|O_RDWR, 0644);
	    if ( fd >= 0 ) {
		size = lseek(fd, 0, SEEK_END);
		size -= storage->i_off;
		close(fd);
	    } else {
		my_log("Can't open file: %s\n", strerror(errno));
		goto try_next;
	    }
	} else
	    size = ROUNDPG((storage->size)-(storage->i_off));
	blk_num = size/STORAGE_PAGE_SIZE;
	if ( blk_num < 2 ) {
	    my_log("Storage size(%d bytes) is too small, skip it\n", storage->size);
	    goto try_next;
	}
#if	defined(WITH_LARGE_FILES)
	my_log("Formatting storage %s for %lld bytes\n", storage->path, (long long)size);
#else
	my_log("Formatting storage %s for %d bytes\n", storage->path, size);
#endif
	gettimeofday(&tv, NULL);
	fd = open(storage->path, O_CREAT|O_RDWR, 0644);
	if ( fd == -1 ) {
	    my_log("open(%s): %s\n", storage->path, strerror(errno));
	    goto try_next;
	}
	if ( ST_LSEEK(fd, size-1, SEEK_SET) == -1 ) {
	    my_log("seek(%s, %u): %s\n", storage->path, size-1, strerror(errno));
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
	    my_log("seek(%s, %u): %s\n", storage->path, 0, strerror(errno));
	    goto try_next;
	}
	if ( write(fd, &super, sizeof(super)) != sizeof(super) ) {
	    my_log("write super for %s: %s\n", storage->path, strerror(errno));
	    goto try_next;
	}
	/* how much 32-bit word we need for map? */
	map_bits  = blk_num;
	map_ptr = xmalloc(map_words*4,"map");
	if ( !map_ptr ) {
	    printf("Can't create map\n");
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

int
db_things_init()
{
    return 0;
}

void
init_storage(struct storage_st *storage)
{
int		fd = -1;
int		map_words;
uint32_t	blk_num;
char		*map_ptr=NULL;


    rwl_init(&storage->storage_lock);
    if (!(storage->flags & ST_CHECKED) )
	return;
    WRLOCK_STORAGE(storage);
    if ( !storage->path ) {
	my_log("No path for storage\n");
	goto error;
    }
    fd = open(storage->path, O_RDWR);
    if ( fd == -1 ) {
	my_log("Can't open storage: %s\n", strerror(errno));
	goto error;
    }
    storage->fd = fd;
    /* read super */
    if ( ST_LSEEK(fd, 0, SEEK_SET) == -1 ) {
	my_log("seek(%s, %u): %s\n", storage->path, 0, strerror(errno));
	goto error;
    }
    if ( read(fd, &storage->super, sizeof(storage->super)) != 
	sizeof(storage->super) ) {
	my_log("Can't read super: %s\n", strerror(errno));
	goto error;
    }
    if ( storage->super.magic != htonl(MAGIC) ) {
	my_log("Wrong magic\n");
	goto error;
    }
    blk_num = storage->super.blks_total;
    map_words = blk_num/32 + (blk_num%32?1:0);
    map_ptr = xmalloc(map_words*4,"map");
    if ( !map_ptr ) {
	goto error;
    }
    ST_LSEEK(fd, STORAGE_PAGE_SIZE, SEEK_SET);
    if ( read(fd, map_ptr, map_words*4) != map_words*4 )
	goto error;
    storage->map = map_ptr;

    /* ready */

    my_log("Storage %s ready\n", storage->path);
    storage->flags = ST_READY;
    UNLOCK_STORAGE(storage);
    return;
error:
    my_log("Storage %s unusable\n", storage->path);
    if ( fd != -1 ) close(fd);
    storage->fd = -1;
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
	if ( storage->fd != -1 ) {
	    close(storage->fd);
	    storage->fd = -1;
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
uint32_t	current, o=n, *p, *po;
int		i;
char		*allocated = NULL;

    if ( !storage )
	goto error;
    if ( !(storage->flags & ST_READY) )
	goto error;
    if ( storage->super.blks_free < n )
	goto error;
    allocated =
	xmalloc(sizeof(struct disk_ref)+n*sizeof(uint32_t),"rqfb");
    if ( !allocated ) goto error;
    p = po = (uint32_t*)(allocated+sizeof(struct disk_ref));
    current = 0;
    while ( n ) {
	current = find_free_bit(storage->map, current+1, storage->super.blks_total) ;
	if ( !current ) {
	    my_log("Severe error on block %u", n);
	    goto error;
	}
	n--;
	*p++ = current;
    }
    storage->super.blks_free -= o;
    /* mark blocks as busy */
    for (i=0;i<o;i++,po++) {
	if ( !*po ) {
	    my_log("Try to set 0 bit\n");
	    do_exit(1);
	}
	if ( test_bit(storage->map, *po) ) {
	    my_log("Trying to set busy bit %d\n", *po);
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
	my_log("Fatal: zero disk_ref\n");
	do_exit(1);
    }

    next_blk = (uint32_t*)(disk_ref+1);
    released = disk_ref->blk ;

    if ( !released ) {
	my_log("Fatal: why to release 0 blks\n");
	do_exit(1);
    }
    storage->super.blks_free += released;
    while( released ) {
	if ( !*next_blk ) {
	    my_log("Fatal: attempt to release 0 blk\n");
	    do_exit(1);
	}
	if ( TEST(storage->flags, ST_CHECKED) && !test_bit(storage->map, *next_blk) ) {
	    my_log("Trying to free free bit\n");
	    do_exit(1);
	}
	clr_bits(storage->map, *next_blk, 1);
	released--;
	next_blk++;
    }
    return(0);
error:
    fprintf(stderr, "Failed to release blks\n");
    return -1;
}

int
flush_super(struct storage_st *storage)
{
int	rc;

    rc = ST_LSEEK(storage->fd, 0, SEEK_SET);
    if ( rc == -1 )
	return(1);
    rc = write(storage->fd, &storage->super, sizeof(storage->super) );
    return(0);
}

int
flush_map(struct storage_st *storage)
{
int		rc;
int		map_words;
uint32_t	blk_num;

    rc = ST_LSEEK(storage->fd, BLKSIZE, SEEK_SET);
    if ( rc == -1 )
	return(1);
    blk_num = storage->super.blks_total;
    map_words = blk_num/32 + (blk_num%32?1:0);
    rc = write(storage->fd, storage->map, map_words*4 );
    return(0);
}

int
move_obj_to_storage(struct mem_obj *obj, struct storage_st **st, struct disk_ref **chain)
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
    my_xlog(LOG_STOR, "Allocate %u disk blocks for object\n", needed_blocks);

    storage = ostorage = next_alloc_storage;
    if ( !ostorage ) storage = storages;
    while( storage ) {
	WRLOCK_STORAGE(storage);
	if ( (storage->flags & ST_READY) && !(storage->flags & ST_FORCE_CLEANUP) ) {
	    if ( (disk_ref = (struct disk_ref*)request_free_blks(storage, needed_blocks)) ) {
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
off_t		next_position;

#ifdef	HAVE_PWRITE
    next_position = *n*BLKSIZE;
#else
    ST_LSEEK(storage->fd, *n*BLKSIZE, SEEK_SET);
#endif

    space = BLKSIZE;
    while ( b && needed ) {
	c = b->data;
	to_move = b->used;
    cwb:
	if ( !to_move ) goto nextb;
	if ( to_move <= space ) {
#ifdef	HAVE_PWRITE
	    rc = ST_PWRITE(storage->fd, c, to_move, next_position);
	    next_position += to_move;
#else
	    rc = write(storage->fd, c, to_move);
#endif
	    space -= to_move;
	    if ( space <= 0 ) {
		needed--;
		n++;
		space = BLKSIZE;
#ifdef	HAVE_PWRITE
		next_position = *n*BLKSIZE;
#else
		ST_LSEEK(storage->fd, *n*BLKSIZE, SEEK_SET);
#endif
	    }
	    to_move = 0;
	} else {
#ifdef	HAVE_PWRITE
	    rc = ST_PWRITE(storage->fd, c, space, next_position);
#else
	    rc = write(storage->fd, c, space);
#endif
	    needed--;
	    to_move -= space;
	    c += space;
	    space = BLKSIZE;
	    n++;
#ifdef	HAVE_PWRITE
	    next_position = *n*BLKSIZE;
#else
	    ST_LSEEK(storage->fd, *n*BLKSIZE, SEEK_SET);
#endif
	    goto cwb;
	}
    nextb:
	b = b->next;
    }
    return 0;
}

struct storage_st *
locate_storage_by_id(long id)
{
struct storage_st *res=storages;

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
    url_str = xmalloc(ROUND(urll, CHUNK_SIZE), "url_str");
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
		my_log("Deadlock in db->get(%s)\n", key.data);
		xfree(url_str);
		return(-1);
	case 0:
		xfree(url_str);
		*disk_ref = data.data;
		if ( !(storage=locate_storage_by_id((*disk_ref)->id)) ) {
		    *disk_ref = NULL;
		    free(data.data);
		    return(-1);
		}
		return(0);
	case DB_NOTFOUND:
		my_log("%s not found\n", key.data);
		xfree(url_str);
		return(-1);
	default:
		my_log("Unknown answer from db->get(%s): %d\n", key.data, rc);
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
int			rc, fd=-1;
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
    /* storage can be not locked as we use separate fd */
    fd = open(storage->path, O_RDONLY);
    if ( fd == -1 )
	goto err;

    bzero(&a, sizeof(a));
s:  
#ifndef	HAVE_PREAD
    rc = ST_LSEEK(fd, *n*BLKSIZE, SEEK_SET);
    if ( rc == -1 )
	goto err;
#endif
r:  next_read = MIN(BLKSIZE, to_load);
#ifdef	HAVE_PREAD
    rc = ST_PREAD(fd, answer, next_read, *n*BLKSIZE);
#else
    rc =  read(fd, answer, next_read);
#endif
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
    if ( fd != -1 ) close(fd);
    return(0);
err:
    free_container(obj->container); obj->container = NULL;
    if ( fd != -1 ) close(fd);
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

    my_xlog(LOG_STOR, "cleaning %s from storage %s\n", url_str, storage->path);
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
		my_log("erase_obj_from_storage: record '%s' not found\n", url_str);
		return(-1);
	default:
		my_log("erase_obj_from_storage: %s\n", strerror(errno));
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
int			fd, i, in_map_free, rc, blk_num, map_words, obj_n = 0;
uint32_t		*start_blk, *n, blks, oblks;
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
    tstorage.fd = open(tstorage.path, O_RDWR);
    if ( tstorage.fd == -1 )
	return;
    fd = tstorage.fd;
    if ( ST_LSEEK(fd, 0, SEEK_SET) == -1 ) {
	my_log("seek(%s, %u): %s\n", tstorage.path, 0, strerror(errno));
	close(fd);
	return;
    }
    if ( read(fd, &tstorage.super, sizeof(tstorage.super)) != 
	sizeof(tstorage.super) ) {
	my_log("Can't read super: %s\n", strerror(errno));
	close(fd);
	return;
    }
    if ( tstorage.super.magic != htonl(MAGIC) ) {
	my_log("Wrong magic\n");
	close(fd);
	return;
    }
    SET(tstorage.flags, ST_READY);
    my_log("Checking storage %s\n", tstorage.path);
    my_log("Super: %d total\n", tstorage.super.blks_total);
    my_log("       %d free \n", tstorage.super.blks_free );
    my_log("       %d blk size\n", tstorage.super.blk_siz);
    my_log("       %x - magic\n", ntohl(tstorage.super.magic));
    blk_num   =	tstorage.super.blks_total;
    map_words = blk_num/32 + (blk_num%32?1:0);

    my_log("Read map\n");
    bitmap = calloc(map_words*4, 1);
    if ( !bitmap ) {
	my_log("Can't allocate memory for map\n");
	goto abor;
    }
    ST_LSEEK(fd, BLKSIZE, SEEK_SET);
    if ( read(fd, bitmap, map_words*4) != map_words*4 ) {
	my_log("Can't read map\n");
	goto abor;
    }
    tstorage.map = bitmap;
    /*in_map_free = calc_free_bits(bitmap, 0, blk_num);*/
    my_log("Done\n");
    map = calloc(blk_num, sizeof(struct memb));
    if ( !map ) {
	my_log("Can't allocate memory for map\n");
	goto abor;
    }
    rc = dbp->cursor(dbp, NULL, &dbcp
#if     (DB_VERSION_MAJOR>2) || (DB_VERSION_MINOR>=6)
				     , 0
#endif
    					);
    if ( rc ) {
	my_log("Cant create cursor for checking\n");
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
		my_log("Done with it\n");
		dbcp->c_close(dbcp);
		goto fix_unrefs;
	default:
		my_log("Can't find url: %d\n", rc);
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
s:  map[*n].refs++;
    if ( map[*n].refs > 1 ) {
	my_log("Crossref\n");
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
	my_log("Resolved\n");
	goto do_scan;
    }
    if ( !test_bit(bitmap, *n) ) {
	my_log("Error: Free block in object %d\n", obj_n);
	while (*start_blk < blk_num ) {
	    /* fix in mem  */
	    map[*start_blk].refs--;
	    if ( start_blk==n ) break;
	    start_blk++;
	};
	release_blks(disk_ref->blk, &tstorage, disk_ref);
	dbcp->c_del(dbcp, 0);
	dbp->sync(dbp, 0);
	my_log("Resolved\n");
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
	my_log("No memory\n");
	dbp->close(dbp, 0);
	do_exit(1);
    }
    strncpy(s, key.data, key.size);
    s[key.size] = 0;
    fprintf(stderr, "%s: %d blocks\n", s, blks);
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
    my_log("Found %d free blocks in map, %d in superblock\n", in_map_free, tstorage.super.blks_free);
    if ( in_map_free != tstorage.super.blks_free ) {
	int map_blks = ROUNDPG(map_words*4)/STORAGE_PAGE_SIZE;
	int busy_b = 0;
	my_log("Fixing free map\n");
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
	my_log("Free list ok.\n");
    }
    SET(storage->flags, ST_CHECKED);
abor:
    close(fd);
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
    my_log("Storages checked\n");
    UNLOCK_CONFIG;
    return(0);
}
void
prepare_storages()
{
pthread_t	pid;
pthread_attr_t	attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#if	!defined(FREEBSD)
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
#endif
    pthread_create(&pid, &attr, &prep_storages, NULL);
    pthread_attr_destroy(&attr);
}
