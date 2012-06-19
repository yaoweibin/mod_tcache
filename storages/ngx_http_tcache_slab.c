
#include "ngx_http_tcache_module.h"


typedef struct {
    ngx_rbtree_t                     rbtree;
    ngx_rbtree_node_t                sentinel;
    ngx_queue_t                      queue;
} ngx_http_tcache_slab_sh_t;


typedef struct {
    ngx_rbtree_node_t                node;
    ngx_queue_t                      queue;

    u_char                           key[NGX_HTTP_CACHE_KEY_LEN
                                         - sizeof(ngx_rbtree_key_t)];
    ngx_http_tcache_node_t          *data;
} ngx_http_tcache_slab_node_index_t;


static ngx_int_t ngx_http_tcache_slab_init(ngx_http_tcache_t *cache);
static ngx_http_tcache_node_t * ngx_http_tcache_slab_lookup(
    ngx_http_tcache_t *cache, u_char *key);
static ngx_http_tcache_node_t * ngx_http_tcache_slab_create(
    ngx_http_tcache_t *cache, u_char *key);
static u_char * ngx_http_tcache_slab_alloc(ngx_http_tcache_t *cache,
    size_t size);
static ngx_int_t ngx_http_tcache_slab_put(ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *tn, u_char *data, size_t size);
static void ngx_http_tcache_slab_delete(ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *tn);
static void ngx_http_tcache_slab_expire(ngx_http_tcache_t *cache);
static void ngx_http_tcache_slab_force_expire(ngx_http_tcache_t *cache);
static void ngx_http_tcache_slab_cleanup(ngx_http_tcache_t *cache);

static ngx_http_tcache_node_t * ngx_http_tcache_slab_alloc_node(
    ngx_slab_pool_t *shpool);
static void ngx_http_tcache_slab_free_node(ngx_slab_pool_t *shpool,
    ngx_http_tcache_node_t *tn);

static void ngx_http_tcache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);


ngx_http_tcache_storage_t tcache_slab = {
    ngx_http_tcache_slab_init,
    ngx_http_tcache_slab_create,
    ngx_http_tcache_slab_lookup,
    ngx_http_tcache_slab_alloc,
    ngx_http_tcache_slab_put,
    NULL,
    ngx_http_tcache_slab_delete,
    ngx_http_tcache_slab_expire,
    ngx_http_tcache_slab_force_expire,
    ngx_http_tcache_slab_cleanup,
};


static ngx_int_t
ngx_http_tcache_slab_init(ngx_http_tcache_t *cache)
{
    ngx_slab_pool_t            *shpool;
    ngx_http_tcache_slab_sh_t  *sh;

    shpool = cache->shpool;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cache->log, 0,
                   "tcache slab init");

    cache->sh = ngx_slab_alloc_locked(shpool,
                                      sizeof(ngx_http_tcache_slab_sh_t));
    if (cache->sh == NULL) {
        return NGX_ERROR;
    }

    sh = cache->sh;

    ngx_rbtree_init(&sh->rbtree, &sh->sentinel,
                    ngx_http_tcache_rbtree_insert_value);

    ngx_queue_init(&sh->queue);

    return NGX_OK;
}


static ngx_http_tcache_node_t *
ngx_http_tcache_slab_lookup(ngx_http_tcache_t *cache, u_char *key)
{
    time_t                             now;
    ngx_int_t                          rc;
    ngx_rbtree_key_t                   node_key;
    ngx_rbtree_node_t                 *node, *sentinel;
    ngx_http_tcache_node_t            *tn;
    ngx_http_tcache_slab_sh_t         *sh;
    ngx_http_tcache_slab_node_index_t *index;

    ngx_memcpy((u_char *) &node_key, key, sizeof(ngx_rbtree_key_t));

    now = ngx_time();
    sh = cache->sh;
    node = sh->rbtree.root;
    sentinel = sh->rbtree.sentinel;

    while (node != sentinel) {

        if (node_key < node->key) {
            node = node->left;
            continue;
        }

        if (node_key > node->key) {
            node = node->right;
            continue;
        }

        /* node_key == node->key */

        index = (ngx_http_tcache_slab_node_index_t *) node;

        rc = ngx_memcmp(&key[sizeof(ngx_rbtree_key_t)], index->key,
                        NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));

        if (rc == 0) {
            tn = (ngx_http_tcache_node_t *) index->data;
            if (tn->expires < now) {
                ngx_http_tcache_slab_delete(cache, tn);
                return NULL;
            }
            else {
                return tn;
            }
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static ngx_http_tcache_node_t *
ngx_http_tcache_slab_create(ngx_http_tcache_t *cache, u_char *key)
{
    ngx_slab_pool_t                   *shpool;
    ngx_http_tcache_node_t            *tn;
    ngx_http_tcache_slab_sh_t         *sh;
    ngx_http_tcache_slab_node_index_t *index;

    shpool = cache->shpool;
    sh = cache->sh;

    tn = ngx_http_tcache_slab_alloc_node(shpool);
    if (tn == NULL) {

        (void) ngx_http_tcache_slab_expire(cache);

        tn = ngx_http_tcache_slab_alloc_node(shpool);
        if (tn == NULL) {

            (void) ngx_http_tcache_slab_force_expire(cache);

            tn = ngx_http_tcache_slab_alloc_node(shpool);
            if (tn == NULL) {
                return NULL;
            }
        }
    }

    index =  tn->index;
    ngx_memcpy((u_char *) &index->node.key, key, sizeof(ngx_rbtree_key_t));

    ngx_memcpy(index->key, &key[sizeof(ngx_rbtree_key_t)],
               NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));

    index->data = tn;
    tn->payload = NULL;

    ngx_rbtree_insert(&sh->rbtree, &index->node);
    ngx_queue_insert_head(&sh->queue, &index->queue);

    return tn;
}


static u_char *
ngx_http_tcache_slab_alloc(ngx_http_tcache_t *cache, size_t size)
{
    u_char                          *payload;
    ngx_slab_pool_t                 *shpool;

    payload = NULL;
    shpool = cache->shpool;

    payload = ngx_slab_alloc_locked(shpool, size);
    if (payload == NULL) {

        (void) ngx_http_tcache_slab_expire(cache);

        payload = ngx_slab_alloc_locked(shpool, size);

        if (payload == NULL) {

            (void) ngx_http_tcache_slab_force_expire(cache);

            payload = ngx_slab_alloc_locked(shpool, size);
            if (payload == NULL) {
                return NULL;
            }
        }
    }

    return payload;
}


static ngx_int_t
ngx_http_tcache_slab_put(ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *tn, u_char *data, size_t size)
{
    tn->payload = ngx_http_tcache_slab_alloc(cache, size);
    if (tn->payload == NULL) {
        return NGX_ERROR;
    }

    tn->length = size;
    (void) ngx_copy(tn->payload, data, size); 

    return NGX_OK;
}


static void
ngx_http_tcache_slab_delete(ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *tn)
{
    ngx_slab_pool_t                   *shpool;
    ngx_http_tcache_slab_sh_t         *sh;
    ngx_http_tcache_slab_node_index_t *index;

    shpool = cache->shpool;
    sh = cache->sh;
    index = tn->index;

    if (tn->payload) {
        ngx_slab_free_locked(shpool, tn->payload);
    }

    ngx_queue_remove(&index->queue);
    ngx_rbtree_delete(&sh->rbtree, &index->node);

    ngx_http_tcache_slab_free_node(shpool, tn);
}


static void
ngx_http_tcache_slab_expire(ngx_http_tcache_t *cache)
{
    time_t                             now;
    ngx_queue_t                       *q;
    ngx_slab_pool_t                   *shpool;
    ngx_http_tcache_node_t            *tn;
    ngx_http_tcache_slab_sh_t         *sh;
    ngx_http_tcache_slab_node_index_t *index;

    shpool = cache->shpool;
    sh = cache->sh;

    now = ngx_time();

    for ( ;; ) {
        if (ngx_queue_empty(&sh->queue)) {
            return;
        }

        q = ngx_queue_last(&sh->queue);

        index = ngx_queue_data(q, ngx_http_tcache_slab_node_index_t, queue);
        tn = index->data;

        if (tn->expires < now) {
            ngx_http_tcache_slab_delete(cache, tn);
        }
    }
}


static void
ngx_http_tcache_slab_force_expire(ngx_http_tcache_t *cache)
{
    time_t                             now;
    ngx_uint_t                         tries;
    ngx_queue_t                       *q;
    ngx_slab_pool_t                   *shpool;
    ngx_http_tcache_node_t            *tn;
    ngx_http_tcache_slab_sh_t         *sh;
    ngx_http_tcache_slab_node_index_t *index;

    shpool = cache->shpool;
    sh = cache->sh;

    now = ngx_time();

    tries = 20;

    while(tries--) {
        if (ngx_queue_empty(&sh->queue)) {
            return;
        }

        q = ngx_queue_last(&sh->queue);

        index = ngx_queue_data(q, ngx_http_tcache_slab_node_index_t, queue);
        tn = index->data;

        ngx_http_tcache_slab_delete(cache, tn);
    }
}


static void
ngx_http_tcache_slab_cleanup(ngx_http_tcache_t *cache)
{
    /* Nginx should take care of the shared memory */
}


static ngx_http_tcache_node_t *
ngx_http_tcache_slab_alloc_node(ngx_slab_pool_t *shpool)
{
    ngx_http_tcache_node_t   *tn;

    tn = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_tcache_node_t));
    if (tn == NULL) {
        return NULL;
    }

    tn->index = ngx_slab_alloc_locked(shpool,
                                     sizeof(ngx_http_tcache_slab_node_index_t));
    if (tn->index == NULL) {
        ngx_slab_free_locked(shpool, tn);
        return NULL;
    }

    return tn;
}


static void
ngx_http_tcache_slab_free_node(ngx_slab_pool_t *shpool,
    ngx_http_tcache_node_t *tn)
{
    ngx_slab_free_locked(shpool, tn->index);
    ngx_slab_free_locked(shpool, tn);
}


static void
ngx_http_tcache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t                  **p;
    ngx_http_tcache_slab_node_index_t   *ni, *nit;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            ni = (ngx_http_tcache_slab_node_index_t *) node;
            nit = (ngx_http_tcache_slab_node_index_t *) temp;

            p = (ngx_memcmp(ni->key, nit->key,
                            NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t))
                 < 0)
                    ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}
