#include    <stdio.h>
#include    <strings.h>
#include    "hash.h"

static unsigned int  string_hash(char *);

hash_t*
hash_init(int rows, int type)
{
hash_t      *res = NULL;
int         i;

    assert(rows > 0);
    if ( (type != HASH_KEY_INT) && (type != HASH_KEY_STRING) )
        return(NULL);
    res = (hash_t*)calloc(1, sizeof(*res));
    if ( !res )
        return(NULL);

    res->rows = rows;
    res->type = type;
    res->table = calloc(rows, sizeof(hash_row_t));
    if ( !res->table ) {
        free(res);
        return(NULL);
    }

    for(i=0; i<rows; i++) {
        pthread_mutex_init(&res->table[i].lock, NULL);
    }
    
    pthread_mutex_init(&res->lock, NULL);
    res->valid = HASH_VALID;
    return(res);    
}

int
hash_put(hash_t *hash, void *key, void *data, hash_entry_t **res)
{
unsigned int     index = 0;
hash_entry_t    *he = NULL;
hash_row_t      *row = NULL;
int             rc = 0;

    assert( hash != NULL );
    assert( hash->table != NULL );

    if ( hash->valid != HASH_VALID ) return(EINVAL);
    switch(hash->type) {
    case HASH_KEY_INT:
        index = (unsigned int)key % hash->rows;
        break;
    case HASH_KEY_STRING:
        index = string_hash((char*)key) % hash->rows;
        break;
    default:
        return(EINVAL);
    }
    assert ( index < hash->rows );
    /* lock the row */
    row = &hash->table[index];
    pthread_mutex_lock(&row->lock);
    /* check if we have this key in table   */
    he = row->first;
    while ( he ) {
        switch(hash->type) {
        case(HASH_KEY_INT):
            if ( (int)he->key == (int)key ) {
                rc = EEXIST;
                goto done;
            }
            break;
        case(HASH_KEY_STRING):
            if ( !strcmp((char*)he->key, (char*)key) ) {
                rc = EEXIST;
                goto done;
            }
            break;
        }

        he = he->next;
    }
    /* we didn't find key, can put it   */
    /* we put it on front of row list   */
    he = calloc(1, sizeof(*he));
    if ( !he ) {
        rc = ENOMEM;
        goto done;
    }

    /* fill he ======================== */
    he->ref_count = 1;
    pthread_cond_init(&he->ref_count_cv, NULL);
    he->data = data;
    switch(hash->type) {
    case(HASH_KEY_INT):
        he->key = key;
        break;
    case(HASH_KEY_STRING):
        he->key = (void*)strdup((char*)key);
        if ( !he->key ) {
            free(he);
            rc = ENOMEM;
            goto done;
        }
        break;
    }
    he->row_back_ptr = row;
    /* ================================ */
    he->next = row->first;
    if ( he->next ) he->next->prev = he;
    row->first = he;
    row->counter++;
    *res = he;
    
done:
    /* unlock row   */
    pthread_mutex_unlock(&row->lock);
    return(rc);
}

int
hash_get(hash_t *hash, void *key, hash_entry_t **he_res)
{
unsigned int    index = 0;
hash_entry_t    *he = NULL;
hash_row_t      *row = NULL;
int             rc = 0;

    assert( hash != NULL );
    assert( hash->table != NULL );
    assert( he_res != NULL );

    if ( hash->valid != HASH_VALID ) return(EINVAL);
    switch(hash->type) {
    case HASH_KEY_INT:
        index = (unsigned int)key % hash->rows;
        break;
    case HASH_KEY_STRING:
        index = string_hash((char*)key) % hash->rows;
        break;
    default:
        return(EINVAL);
    }
    assert ( index < hash->rows );
    /* lock the row */
    row = &hash->table[index];
    pthread_mutex_lock(&row->lock);
    /* check if we have this key in table   */
    he = row->first;
    while ( he ) {
        if ( he->flags & HASH_ENTRY_DELETED ) {
            he = he->next;
            continue;
        }
        switch(hash->type) {
        case(HASH_KEY_INT):
            if ( (int)he->key == (int)key ) {
                he->ref_count++;
                *he_res = he;
                goto done;
            }
            break;
        case(HASH_KEY_STRING):
            if ( !strcmp((char*)he->key, (char*)key) ) {
                he->ref_count++;
                *he_res = he;
                goto done;
            }
            break;
        }

        he = he->next;
    }
    rc = ENOENT;
done:
    /* unlock row   */
    pthread_mutex_unlock(&row->lock);
    return(rc);
    
}

int
hash_unref(hash_t *hash, hash_entry_t *he)
{
hash_row_t  *row;

    assert( he != NULL );
    assert( he->row_back_ptr != NULL );
    assert( he->ref_count > 0 );
    row = he->row_back_ptr;
    pthread_mutex_lock(&row->lock);
    he->ref_count--;
    /* singnal from inside the lock, because after row lock will be         */
    /* removed we have no warranties that he still exist (if someone called */
    /* delete_hash_entry)                                                   */
    pthread_cond_signal(&he->ref_count_cv);
    pthread_mutex_unlock(&row->lock);
    return(0);
}

/* delete referenced entry from hash */

int
delete_hash_entry(hash_t *hash, hash_entry_t *he, void (*f)(void*) )
{
hash_row_t  *row;

    assert( hash != NULL );
    assert( he != NULL );
    assert( he->row_back_ptr != NULL );
    row = he->row_back_ptr;
    pthread_mutex_lock(&row->lock);

    if ( he->flags & HASH_ENTRY_DELETED ) {
        pthread_mutex_unlock(&row->lock);
        return(EBUSY);
    }
    he->flags |= HASH_ENTRY_DELETED;

    while ( he->ref_count > 1 )
        pthread_cond_wait(&he->ref_count_cv, &row->lock);

    if ( !he->prev )
        row->first = he->next;
      else
        he->prev->next = he->next;
    if ( he->next ) {
        he->next->prev = he->prev;
    }
    row->counter--;
    pthread_mutex_unlock(&row->lock);

    /* now we are only who ref this entry                           */
    if ( f && he->data  ) (*f)(he->data);
    switch(hash->type) {
    case(HASH_KEY_STRING):
        free((char*)he->key);
        break;
    }
    pthread_cond_destroy(&he->ref_count_cv);
    free(he);
    return(0);
}


int
hash_operate(hash_t *hash, int (*f)(hash_entry_t*))
{
hash_row_t      *row;
hash_entry_t    *he, *he_next;
unsigned int    index;
int             rc=0;

    assert( hash != NULL );
    assert( f != NULL );
    if ( hash->valid != HASH_VALID ) return(EINVAL);
    if ( hash->table == NULL ) return(EINVAL);
    for(index=0;index<hash->rows;index++) {
        row = &hash->table[index];
        pthread_mutex_lock(&row->lock);
        he = row->first;
        while(he) {
            if ( he->flags & HASH_ENTRY_DELETED ) {
                he = he->next;
                continue;
            }
            he_next = he->next;
            rc = (*f)(he);
            if ( rc ) break;    /* return non 0 means - abort operation */
            if (  he->flags & HASH_ENTRY_DELETED ) {
                /* user requested to delete this entry  */
                if ( he->ref_count > 0 ) {
                    /* you can't do that    */
                    pthread_mutex_unlock(&row->lock);
                    return(EBUSY);
                }
                /* ok to delete */
                if ( !he->prev ) 
                    row->first = he->next;
                  else
                    he->prev->next = he->next;
                if ( he->next ) {
                    he->next->prev = he->prev;
                }
                row->counter--;
                switch(hash->type) {
                case(HASH_KEY_STRING):
                    free((char*)he->key);
                    break;
                }
                pthread_cond_destroy(&he->ref_count_cv);
                free(he);
            }
            he = he_next;
        }
        pthread_mutex_unlock(&row->lock);
        if ( rc ) break;
    }
    return(0);
}

int
hash_destroy(hash_t *hash, void (*user_function)(void*) )
{
hash_row_t      *row;
hash_entry_t    *he, *he_next;
unsigned int    index;

    assert( hash != NULL);
    assert( hash->table != NULL );
    if ( hash->valid != HASH_VALID ) return(EINVAL);
    pthread_mutex_lock(&hash->lock);
    hash->valid = 0;
    pthread_mutex_unlock(&hash->lock);
    for(index=0;index<hash->rows;index++) {
        row = &hash->table[index];
        pthread_mutex_lock(&row->lock);
        he = row->first;
        while(he) {
            if ( he->flags & HASH_ENTRY_DELETED ) {
                he = he->next;
                continue;
            }
            he_next = he->next;

            while ( he->ref_count > 1 )
                pthread_cond_wait(&he->ref_count_cv, &row->lock);

            if ( (he->data != NULL) && (user_function != NULL) )
                (*user_function)(he->data);
            if ( !he->prev ) 
                row->first = he->next;
              else
                he->prev->next = he->next;
            if ( he->next )
                he->next->prev = he->prev;

            row->counter--;
            switch(hash->type) {
            case(HASH_KEY_STRING):
                free((char*)he->key);
                break;
                }
            pthread_cond_destroy(&he->ref_count_cv);
            free(he);
            he = he_next;
        }
        assert(row->counter == 0);
        pthread_mutex_unlock(&row->lock);
        pthread_mutex_destroy(&row->lock);
    }
    pthread_mutex_destroy(&hash->lock);
    free(hash->table);
    free(hash);
    return(0);
}


static unsigned int
string_hash(char *str)
{
unsigned int res = 0;

    assert( str != NULL);
    while(*str)
        res = ( res << 3 ) + *((unsigned char*)(str++));
    return(res);
}
