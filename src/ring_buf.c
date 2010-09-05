/*
Copyright (C) 2000 Igor Khasilev, igor@paco.net

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

/* create and initialize ring buffer	*/
ring_buf_t *
new_ring_buf(int num, int data_size)
{
ring_buf_t	*res;
ring_buf_el_t	*el;
int		i;

    if ( (num <= 0) || (data_size <= 0) )
	return(NULL);

    res = calloc(1, sizeof(*res));
    if ( !res ) return(NULL);
    if ( pthread_mutex_init(&res->lock, NULL) != 0 ) {
	free(res);
	return(NULL);
    }
    res->num = 0;
    res->r_index = 0;
    res->w_index = 0;
    res->datasize = data_size;
    res->elts = calloc(num, sizeof(ring_buf_el_t) );
    if ( res->elts == NULL ) {
	pthread_mutex_destroy(&res->lock);
	free(res);
	return(NULL);
    }
    el = res->elts;
    for (i=0;i<num;i++) {
	/* initialize each element */
	if ( pthread_mutex_init(&el->lock, NULL) != 0 ) goto error;
	el->buf = malloc(data_size);
	if ( el->buf == NULL ) {
	    pthread_mutex_destroy(&el->lock);
	    goto error;
	}
	el->size = data_size;
	el->used = 0;
	el->valid = TRUE;
	el++;
    }
    return(res);

error:
    /* destroy all valid elements */
    el = res->elts;
    for (i=0;i<num;i++) {
	if ( el->valid == TRUE ) {
	    pthread_mutex_destroy(&el->lock);
	    IF_FREE(el->buf);
	}
	el++;
    }
    free(res->elts);
    free(res);
    return(NULL);
}

/* destroy ring buffer			*/
void
destroy_ring_buf(ring_buf_t *rb)
{
ring_buf_el_t	*el;
int		i, num;

    if ( rb == NULL ) return;
    el = rb->elts;
    num = rb->total;
    for (i=0;i<num;i++) {
	if ( el->valid == TRUE ) {
	    pthread_mutex_destroy(&el->lock);
	    IF_FREE(el->buf);
	}
	el++;
    }
    free(rb->elts);
    free(rb);
    return;
}

/* place data into ring buffer 					*
 * we write into w_index buffer if it				*
 * have place. If not - move to next				*
 * buffer if next is free, and try with				*
 * it.								*/

/* Limits: each record can't be larger than single buffer.	*
 * Bugs: data must be splitted over sevaral buffers.		*/

int
put_in_ring_buff(ring_buf_t *rb, char *data, int size)
{
ring_buf_el_t   *el;

    if ( !rb || !data || (size <=0 ) )
	return(1);
    if ( size > rb->datasize )
	return(1);
    if ( pthread_mutex_lock(&rb->lock) != 0 )
	return(1);
    /* check if we have place in w_index	*/
    el = &rb->elts[rb->w_index];
    if ( pthread_mutex_lock(&rb->elts[rb->w_index].lock) != 0 ) {
	pthread_mutex_unlock(&rb->lock);
	return(1);
    }
    if ( el->used + size <= el->size ) {
	/* we can place here */
	char	*dst;

	dst = &el->buf[el->used];
	memcpy(dst, data, size);
	el->used += size;
	pthread_mutex_unlock(&rb->elts[rb->w_index].lock);
	if ( rb->num == 0 ) rb->num = 1;
	pthread_mutex_unlock(&rb->lock);
	return(0);
    }
    pthread_mutex_unlock(&rb->elts[rb->w_index].lock);
    /* we have to move to next element if we can.			*/
    if ( rb->num < rb->total ) {
	int	windex;
	char	*dst;

	rb->w_index++;
	if ( rb->w_index >= rb->total ) rb->w_index = 0;
	rb->num++;
	windex = rb->w_index;			/* fix on new w_index		*/
	el = &rb->elts[windex];			/* and new wr element		*/
	pthread_mutex_unlock(&rb->lock);	/* now can remove global lock	*/
	pthread_mutex_lock(&rb->elts[windex].lock);  /* lock buff where to write*/
	dst = &el->buf[el->used];
	memcpy(dst, data, size);
	el->used += size;
	pthread_mutex_unlock(&rb->elts[windex].lock);/* and unlock it		*/
	return(0);
    } else {
	pthread_mutex_unlock(&rb->lock);	/* just remove global lock	*/
    }
    return(1);
}

/* give reference to read element and lock it
   read pointer move to the next if possible
   return NULL if data not available

   if successful - you must call unlock later

 */

ring_buf_el_t*
read_from_ring_buff(ring_buff_t *rb)
{
ring_buf_el_t	*res;

    if ( !rb ) return(NULL);
    if ( pthread_mutex_lock(&rb->lock) != 0 )
	return(1);
    if ( rb->num == 0 ) return(NULL);
    res = &rb->elts[rb->r_index];
    if ( 
}
