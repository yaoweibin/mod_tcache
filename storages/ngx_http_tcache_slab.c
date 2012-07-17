
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
static ngx_int_t ngx_http_tcache_slab_get(
    ngx_http_tcache_t *cache, ngx_http_tcache_ctx_t *ctx, ngx_flag_t lookup);
static ngx_http_tcache_node_t * ngx_http_tcache_slab_create(
    ngx_http_tcache_t *cache, ngx_http_tcache_ctx_t *ctx);
static u_char * ngx_http_tcache_slab_alloc(ngx_http_tcache_t *cache,
    size_t size);
static ngx_int_t ngx_http_tcache_slab_put(ngx_http_tcache_t *cache, 
    ngx_http_tcache_ctx_t *ctx);
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
    ngx_http_tcache_slab_get,
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
    ngx_int_t                          rc;
    ngx_rbtree_key_t                   node_key;
    ngx_rbtree_node_t                 *node, *sentinel;
    ngx_http_tcache_slab_sh_t         *sh;
    ngx_http_tcache_slab_node_index_t *index;

    ngx_memcpy((u_char *) &node_key, key, sizeof(ngx_rbtree_key_t));

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
            return (ngx_http_tcache_node_t *) index->data;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static ngx_int_t
ngx_http_tcache_slab_get(ngx_http_tcache_t *cache,
    ngx_http_tcache_ctx_t *ctx, ngx_flag_t lookup)
{
    time_t                  now;
    ngx_buf_t              *buf;
    ngx_http_tcache_node_t *tn;

    tn = ngx_http_tcache_slab_lookup(cache, ctx->key);
    if (tn == NULL) {
        return NGX_DECLINED;
    }

    now = ngx_time();

    if (lookup) {

        if (tn->status != ctx->status) {

            if (ctx->can_use_stale) {

                if (tn->use_stale) {

                    /*TODO: try interval*/
                    if ((now - tn->last_try) > 3) {

                        tn->last_try = now;
                        return NGX_DECLINED;
                    }

                } else {
                    tn->last_try = now;
                    tn->use_stale = 1;
                }

                return NGX_AGAIN;

            } else {
                return NGX_DECLINED;
            }
        }

        return NGX_OK;
    }

    if (tn->expires < now) {
        if (tn->stale > now) {
            if (tn->use_stale) {
                /* Try once again */
                if ((now - tn->last_try) > 3) {
                    tn->last_try = now;
                    return NGX_DECLINED;
                }

                goto use_cache;
            }
        }

        return NGX_DECLINED;
    }

use_cache:
    
    ctx->node = tn;
    ctx->cache_length = tn->length;
    ctx->valid = tn->expires - now;
    ctx->age = now - tn->date;

    buf = ngx_create_temp_buf(ctx->pool, tn->length);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->last = ngx_copy(buf->pos, tn->payload, tn->length);

    ctx->cache_content = buf;
    ctx->payload = buf->pos;

    return NGX_OK;
}


static ngx_http_tcache_node_t *
ngx_http_tcache_slab_create(ngx_http_tcache_t *cache, ngx_http_tcache_ctx_t *ctx)
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
    ngx_memcpy((u_char *) &index->node.key, ctx->key, sizeof(ngx_rbtree_key_t));

    ngx_memcpy(index->key, &ctx->key[sizeof(ngx_rbtree_key_t)],
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
ngx_http_tcache_slab_put(ngx_http_tcache_t *cache, ngx_http_tcache_ctx_t *ctx)
{
    ngx_http_tcache_node_t            *tn;

    tn = ngx_http_tcache_slab_lookup(cache, ctx->key);
    if (tn) {
        if ((tn->last_modified > 0)
             && (tn->last_modified == ctx->last_modified)) {

            return NGX_OK;
        }

        ngx_http_tcache_slab_delete(cache, tn);
    }

    tn = ngx_http_tcache_slab_create(cache, ctx);
    if (tn == NULL) {
        return NGX_ERROR;
    }

    ctx->node = tn;
    tn->status = ctx->status;
    tn->date = ngx_time();
    tn->expires = tn->date + ctx->valid;
    tn->stale =  tn->expires + ctx->grace;
    tn->last_modified = ctx->last_modified;

    tn->length = ctx->cache_length;
    tn->payload = ngx_http_tcache_slab_alloc(cache, tn->length);
    if (tn->payload == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_copy(tn->payload, ctx->payload, tn->length); 

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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cache->log, 0,
            "http tcache expire delete: \"%p\"", &index->queue);

    ngx_queue_remove(&index->queue);
    ngx_rbtree_delete(&sh->rbtree, &index->node);

    ngx_http_tcache_slab_free_node(shpool, tn);
}


static void
ngx_http_tcache_slab_expire(ngx_http_tcache_t *cache)
{
    time_t                             now;
    ngx_uint_t                         freed;
    ngx_queue_t                       *q;
    ngx_slab_pool_t                   *shpool;
    ngx_http_tcache_node_t            *tn;
    ngx_http_tcache_slab_sh_t         *sh;
    ngx_http_tcache_slab_node_index_t *index;

    shpool = cache->shpool;
    sh = cache->sh;

    freed = 0;
    now = ngx_time();

    for ( ;; ) {

        if (ngx_queue_empty(&sh->queue)) {
            return;
        }

        q = ngx_queue_last(&sh->queue);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cache->log, 0,
                       "http tcache expire: \"%p\"", q);

        index = ngx_queue_data(q, ngx_http_tcache_slab_node_index_t, queue);
        tn = index->data;

        if (tn->stale < now) {
            ngx_http_tcache_slab_delete(cache, tn);
            freed++;
        } else if (tn->expires < now) {
            /* Free more than 4 records */
            if (freed < 4) {
                ngx_http_tcache_slab_delete(cache, tn);
                freed++;
            }
            else {
                break;
            }
        }
        else {
            break;
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
