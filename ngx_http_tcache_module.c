
#include <ngx_md5.h>
#include "ngx_http_tcache_module.h"
#include "ngx_http_tcache_headers.h"


#define DEFAULT_KEY "$scheme$proxy_host$request_uri"


typedef struct {
    ngx_str_t                   name;
    ngx_http_tcache_storage_t  *value;
} ngx_conf_storage_t;

static ngx_int_t ngx_http_tcache_access_handler(ngx_http_request_t *r);

static void ngx_http_tcache_create_key(ngx_http_tcache_ctx_t *ctx,
    ngx_str_t *key);
static ngx_int_t ngx_http_tcache_send(ngx_http_request_t *r,
    ngx_http_tcache_ctx_t *ctx);

static ngx_int_t ngx_http_tcache_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_tcache_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

static ngx_int_t
ngx_http_tcache_deep_copy_chain(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);

static char *ngx_http_tcache_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_tcache_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char * ngx_http_tcache_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_http_tcache_storage_t * ngx_http_tcache_get_storage(
    ngx_str_t *type);

static void *ngx_http_tcache_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_tcache_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_http_tcache_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_tcache_post_config(ngx_conf_t *cf);
static ngx_int_t ngx_http_tcache_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);

static void * ngx_http_tcache_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_tcache_init_main_conf(ngx_conf_t *cf, void *conf);


extern ngx_http_tcache_storage_t tcache_slab;
extern ngx_http_tcache_storage_t tcache_freelist;
extern ngx_http_tcache_storage_t tcache_mdb;

static ngx_conf_storage_t  ngx_http_tcache_storages[] = {
    { ngx_string("FREELIST"), &tcache_freelist },
    { ngx_string("MDB"),      &tcache_mdb      },
    { ngx_string("SLAB"),     &tcache_slab     },
    { ngx_null_string, NULL}
};


static ngx_conf_bitmask_t  ngx_http_tcache_method_mask[] = {
   { ngx_string("GET"),    NGX_HTTP_GET    },
   { ngx_string("HEAD"),   NGX_HTTP_HEAD   },
   { ngx_string("POST"),   NGX_HTTP_POST   },
   { ngx_string("PUT"),    NGX_HTTP_PUT    },
   { ngx_string("DELETE"), NGX_HTTP_DELETE },
   { ngx_null_string, 0 }
};

static ngx_conf_bitmask_t  ngx_http_tcache_use_stale_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_tcache_commands[] = {

    { ngx_string("tcache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_tcache_enable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tcache_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_tcache_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tcache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, valid),
      NULL },

    { ngx_string("tcache_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, bypass),
      NULL },

    { ngx_string("tcache_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, methods),
      &ngx_http_tcache_method_mask },

    { ngx_string("tcache_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, default_expires),
      NULL },

    { ngx_string("tcache_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, use_stale),
      &ngx_http_tcache_use_stale_masks },

    { ngx_string("tcache_shm_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE123,
      ngx_http_tcache_shm_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_tcache_module_ctx = {
    ngx_http_tcache_add_variables,        /* preconfiguration */
    ngx_http_tcache_post_config,          /* postconfiguration */

    ngx_http_tcache_create_main_conf,     /* create main configuration */
    ngx_http_tcache_init_main_conf,       /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_tcache_create_loc_conf,      /* create location configuration */
    ngx_http_tcache_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_tcache_module = {
    NGX_MODULE_V1,
    &ngx_http_tcache_module_ctx,           /* module context */
    ngx_http_tcache_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_http_variable_t ngx_http_tcache_variables[] = {

    { ngx_string("tcache_status"), NULL, NULL, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_tcache_access_handler(ngx_http_request_t *r)
{
    ngx_str_t                      cache_key;
    ngx_http_tcache_t             *cache;
    ngx_http_tcache_ctx_t         *ctx;
    ngx_http_tcache_node_t        *node;
    ngx_http_tcache_loc_conf_t    *conf;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_tcache_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache request \"%V\"", &r->uri);

    ctx->pool = r->pool;

    if (ngx_http_tcache_headers_init(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_tcache_module);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tcache_module);
    if (!conf->enable) {
        goto bypass;
    }

    if (!(r->method & conf->methods)) {
        goto bypass;
    }

    switch (ngx_http_test_predicates(r, conf->bypass)) {

    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_DECLINED:
        goto bypass;

    default: /* NGX_OK */
        break;
    }

    if (ngx_http_complex_value(r, &conf->key, &cache_key) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cache_key.len == 0) {
        goto bypass;
    }

    ctx->key_string = cache_key;
    ngx_http_tcache_create_key(ctx, &cache_key);

    cache = conf->shm_zone->data;
    ngx_shmtx_lock(&cache->shpool->mutex);
    node = cache->storage->get(cache, ctx, 0);
    ngx_shmtx_unlock(&cache->shpool->mutex);

    if (node) {
        return ngx_http_tcache_send(r, ctx);
    } else {
        /* not found */
        return NGX_DECLINED;
    }

bypass:

    ctx->no_cache = 1;
    return NGX_DECLINED;
}


static void
ngx_http_tcache_create_key(ngx_http_tcache_ctx_t *ctx, ngx_str_t *key)
{
    ngx_md5_t md5;

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, key->data, key->len);
    ngx_md5_final(ctx->key, &md5);
}


static ngx_int_t
ngx_http_tcache_send(ngx_http_request_t *r, ngx_http_tcache_ctx_t *ctx)
{
    ngx_int_t                              rc;
    ngx_buf_t                             *b;
    ngx_chain_t                            out;
    ngx_http_tcache_node_t                *node;
    ngx_http_tcache_content_header_t      *h;

    node = ctx->node;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache send request \"%V\"", &r->uri);

    h = (ngx_http_tcache_content_header_t *) ctx->buffer.start;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "tcache send request header_start: %z, body_start: %z",
                   h->header_start, h->body_start);

    if (h->header_start >= h->body_start) {
        return NGX_ERROR;
    }

    ctx->buffer.pos  = ctx->buffer.start + h->header_start;
    ctx->buffer.last = ctx->buffer.start + h->body_start;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache process headers: \"%*s\"",
                  ctx->buffer.last - ctx->buffer.pos, ctx->buffer.pos);

    rc = ctx->process_headers(r, &ctx->buffer);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->start = b->pos = ctx->buffer.start + h->body_start;
    b->last = b->end = ctx->buffer.end;

    b->memory = 1;

    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_output_filter(r, &out);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache send \"%V\", rc=%i", &r->uri, rc);

    if (rc == NGX_ERROR) {
        r->connection->error = 1;
        return rc;
    }

    if (rc > NGX_OK) {
        return rc;
    }

    ngx_http_finalize_request(r, rc);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_tcache_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_chain_t                   *cl;
    ngx_table_elt_t               *h;
    ngx_http_tcache_t             *cache;
    ngx_http_tcache_ctx_t         *ctx;
    ngx_http_tcache_node_t        *node;
    ngx_http_tcache_loc_conf_t    *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tcache_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_tcache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->no_cache) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tcache_module);
    if (!conf->enable) {
        return ngx_http_next_header_filter(r);
    }

    ctx->valid = ngx_http_file_cache_valid(conf->valid, r->headers_out.status);
    if (ctx->valid == 0) {
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache header filter \"%V\", %T", &r->uri, ctx->valid);

    cache = conf->shm_zone->data;
    ngx_shmtx_lock(&cache->shpool->mutex);
    node = cache->storage->get(cache, ctx, 1);
    ngx_shmtx_unlock(&cache->shpool->mutex);

    if (node) {
        return ngx_http_next_header_filter(r);
    }

    ctx->store = 1;
    r->filter_need_in_memory = 1;

    /* Store the response headers */
    rc = ctx->store_headers(r, &ctx->cache_content);
    if (rc != NGX_OK) {
        return rc;
    }

    for (cl = ctx->cache_content; cl; cl = cl->next) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "tcache header filter buffer: %z", ngx_buf_size(cl->buf));

        if (ngx_buf_in_memory(cl->buf)) {
            ctx->cache_length += ngx_buf_size(cl->buf);
        }
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "TCACHE");
    ngx_str_set(&h->value, "MISS");
    h->lowcase_key = (u_char *) "tcache";
    
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_tcache_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                         len;
    u_char                        *p;
    ngx_int_t                      last, rc;
    ngx_chain_t                   *cl;
    ngx_http_tcache_t             *cache;
    ngx_http_tcache_ctx_t         *ctx;
    ngx_http_tcache_node_t        *node;
    ngx_http_tcache_loc_conf_t    *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tcache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->no_cache || ctx->valid == 0 || ctx->store == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache body filter \"%V\"", &r->uri);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tcache_module);

    last = 0;
    for (cl = in; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            len = ngx_buf_size(cl->buf);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "tcache body filter buffer: %z", len);

            ctx->cache_length += len;
            ctx->content_length += len;
        }

        if (cl->buf->last_buf) {
            last = 1;
            break;
        }
    }

    /* store the response chains to the cache pool */
    rc = ngx_http_tcache_deep_copy_chain(r->pool, &ctx->cache_content, in);
    if (rc != NGX_OK) {
        ctx->store = 0;
    }

    if (last && ctx->store) {
        cache = conf->shm_zone->data;
        ngx_shmtx_lock(&cache->shpool->mutex);
        node = cache->storage->get(cache, ctx, 1);
        ngx_shmtx_unlock(&cache->shpool->mutex);

        if (node) {
            return ngx_http_next_body_filter(r, in);
        }

        ctx->payload = ngx_palloc(r->pool, ctx->cache_length);
        if (ctx->payload == NULL) {
            return NGX_ERROR;
        }

        p = ctx->payload;
        for (cl = ctx->cache_content; cl; cl = cl->next) {
            len = ngx_buf_size(cl->buf);
            if (ngx_buf_in_memory(cl->buf) && len) {
                p = ngx_copy(p, cl->buf->pos, len);
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "tcache body total single buffer: %z", ctx->cache_length);

        if (p != (ctx->payload + ctx->cache_length)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "tcache invalid cache_length");
            return ngx_http_next_body_filter(r, in);
        }

        ngx_shmtx_lock(&cache->shpool->mutex);
        node = cache->storage->create(cache, ctx);
        if (node == NULL) {
            ngx_shmtx_unlock(&cache->shpool->mutex);
            return NGX_ERROR;
        }

        ctx->node = node;
        node->updating = 1;
        node->date = ngx_time();
        node->expires =  node->date + ctx->valid;
        node->last_modified = r->headers_out.last_modified_time;

        rc = cache->storage->put(cache, node, ctx->payload,
                                 ctx->cache_length);
        ngx_shmtx_unlock(&cache->shpool->mutex);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t
ngx_http_tcache_deep_copy_chain(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in)
{
    size_t           len;
    ngx_chain_t     *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        if (ngx_buf_special(in->buf)) {
            cl->buf = in->buf;

        } else {

            if (ngx_buf_in_memory(in->buf)) {
                len = ngx_buf_size(in->buf);
                cl->buf = ngx_create_temp_buf(pool, len);
                if (cl->buf == NULL) {
                    return NGX_ERROR;
                }

                cl->buf->last = ngx_copy(cl->buf->pos, in->buf->pos, len);
            } else {
                return NGX_ERROR;
            }
        }

        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return NGX_OK;
}


static char *
ngx_http_tcache_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tcache_loc_conf_t *tlcf = conf;

    ngx_str_t                         *value;

    value = cf->args->elts;

    if (tlcf->shm_zone) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        tlcf->shm_zone = NULL;
        return NGX_CONF_OK;
    }

    tlcf->enable = 1;
    tlcf->shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                           &ngx_http_tcache_module);
    if (tlcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_tcache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tcache_loc_conf_t *tlcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (tlcf->key.value.len) {
        return "is duplicate";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &tlcf->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_tcache_shm_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    off_t                              max_size;
    ngx_uint_t                         i;
    ngx_str_t                          s, *value, *name;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_tcache_t                 *cache;

    value = cf->args->elts;

    name = &value[1];
    max_size = 128 * 1024 * 1024;

    cache = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcache_t));
    if (cache == NULL) {
        return NGX_CONF_ERROR;
    }

    cache->storage = &tcache_slab;

    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "size=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            max_size = ngx_parse_offset(&s);
            if (max_size < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid size value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "storage=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            cache->storage = ngx_http_tcache_get_storage(&s);
            if (cache->storage == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid storage type \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
    }

    if (max_size > (off_t) NGX_MAX_SIZE_T_VALUE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "Your OS is 32bits, you should specify the size"
                               " less than \"%z\"", NGX_MAX_SIZE_T_VALUE);
            return NGX_CONF_ERROR;
    }

    if (max_size < (off_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "size=%O is too small",
                           max_size);
        return NGX_CONF_ERROR;
    }

    cache->size = max_size;
    cache->log  = cf->log;
    cache->pool = cf->pool;

    /* 
     * The mdb library will take care of all the stuff.
     * This shared memory is only used for lock purpose
     * */
    if (cache->storage == &tcache_mdb) {
        max_size = ngx_pagesize; 
    }

    shm_zone = ngx_shared_memory_add(cf, name, (size_t) max_size,
                                     &ngx_http_tcache_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "tcache_shm_zone \"%V\" is duplicately initialized",
                        &name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_tcache_init_zone;
    shm_zone->data = cache;

    return NGX_CONF_OK;
}


static ngx_http_tcache_storage_t *
ngx_http_tcache_get_storage(ngx_str_t *type)
{
    ngx_int_t                          i;
    ngx_conf_storage_t                *storages;

    storages = ngx_http_tcache_storages;

    for (i = 0; ; i++) {
        if (storages[i].name.len == 0) {
            break;
        }
        
        if (storages[i].name.len == type->len
            && ngx_strncasecmp(storages[i].name.data,
                           type->data, type->len) == 0) {

            return storages[i].value;
        }
    }

    return NULL;
}


static void *
ngx_http_tcache_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_tcache_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcache_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->use_stale = 0;
     *     conf->methods = 0;
     *     conf->shm_zone = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->valid = NGX_CONF_UNSET_PTR;
    conf->bypass = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_tcache_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_str_t                          default_key = ngx_string(DEFAULT_KEY);
    ngx_http_tcache_loc_conf_t        *prev = parent;
    ngx_http_tcache_loc_conf_t        *conf = child;
    ngx_http_compile_complex_value_t   ccv;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->key.value.len == 0) {

        conf->key = prev->key;

        if (conf->key.value.len == 0) {

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &default_key;
            ccv.complex_value = &conf->key;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (conf->methods == 0) {
        conf->methods = prev->methods;
    }

    conf->methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->valid, prev->valid, NULL);
    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);

    ngx_conf_merge_bitmask_value(conf->use_stale, prev->use_stale,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->use_stale = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
        conf->use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_tcache_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_tcache_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcache_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    /* set by ngx_pcalloc:
     * headers_in_hash = 0;
     */

    return mcf;
}


static char *
ngx_http_tcache_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_tcache_main_conf_t    *tmcf = conf;

    ngx_array_t                     headers_in;
    ngx_hash_key_t                 *hk;
    ngx_hash_init_t                 hash;
    ngx_http_tcache_header_t       *header;

    /* init the headers hash */
    if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (header = ngx_http_tcache_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_CONF_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &tmcf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "tcache_headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_tcache_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_tcache_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_post_config(ngx_conf_t *cf)
{
    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;
    ngx_http_tcache_loc_conf_t      *conf;

    conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_tcache_module);
    if (!conf->enable) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_tcache_access_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_tcache_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_tcache_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t        *shpool;
    ngx_http_tcache_t      *cache, *ocache;

    cache = shm_zone->data;
    ocache = data;

    if (ocache) {
        cache->sh = ocache->sh;
        cache->shpool = ocache->shpool;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    cache->shpool = shpool;

    ngx_shmtx_lock(&cache->shpool->mutex);
    if (cache->storage->init(cache) != NGX_OK) {
        ngx_shmtx_unlock(&cache->shpool->mutex);
        return NGX_ERROR;
    }
    ngx_shmtx_unlock(&cache->shpool->mutex);

    return NGX_OK;
}
