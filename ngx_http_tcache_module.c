
#include <ngx_md5.h>
#include "ngx_http_tcache_module.h"
#include "ngx_http_tcache_headers.h"


#define DEFAULT_KEY "$scheme$host$request_uri"


typedef struct {
    ngx_str_t                   name;
    ngx_http_tcache_storage_t  *value;
} ngx_conf_storage_t;

static ngx_int_t ngx_http_tcache_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_tcache_poseponsed_to_access_phase_end(
    ngx_http_request_t *r);

static void ngx_http_tcache_create_key(ngx_http_tcache_ctx_t *ctx,
    ngx_str_t *key);
static ngx_int_t ngx_http_tcache_send(ngx_http_request_t *r,
    ngx_http_tcache_ctx_t *ctx);

static ngx_int_t ngx_http_tcache_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_tcache_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

static ngx_uint_t ngx_http_tcache_get_fail_status(ngx_uint_t status);

static ngx_int_t ngx_http_tcache_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

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

static void ngx_http_tcache_exit_process(ngx_cycle_t *cycle);


extern ngx_http_tcache_storage_t tcache_slab;
extern ngx_http_tcache_storage_t tcache_freelist;
#if (NGX_TCACHE_MDB)
extern ngx_http_tcache_storage_t tcache_mdb;
#endif

static ngx_conf_storage_t  ngx_http_tcache_storages[] = {
    { ngx_string("FREELIST"), &tcache_freelist },
#if (NGX_TCACHE_MDB)
    { ngx_string("MDB"),      &tcache_mdb      },
#endif
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
    { ngx_string("http_500"), NGX_HTTP_FT_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_FT_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_FT_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_FT_HTTP_504 },
    { ngx_string("http_404"), NGX_HTTP_FT_HTTP_404 },
    { ngx_string("http_408"), NGX_HTTP_FT_HTTP_408 },
    { ngx_string("updating"), NGX_HTTP_FT_HTTP_UPDATING },
    { ngx_string("off"),      NGX_HTTP_FT_HTTP_OFF},
    { ngx_null_string, 0 }
};


static ngx_str_t  ngx_http_tcache_hide_headers[] = {
    ngx_string("Connection"),
    ngx_string("Keep-Alive"),
    ngx_string("Proxy-Authenticate"),
    ngx_string("Proxy-Authorization"),
    ngx_string("TE"),
    ngx_string("Trailers"),
    ngx_string("Transfer-Encoding"),
    ngx_string("Upgrade"),
    ngx_null_string
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

    { ngx_string("tcache_grace"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, grace),
      NULL },

    { ngx_string("tcache_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, status_use_stale),
      &ngx_http_tcache_use_stale_masks },

    { ngx_string("tcache_hide_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, hide_headers),
      NULL },

    { ngx_string("tcache_pass_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, pass_headers),
      NULL },

    { ngx_string("tcache_shm_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE123,
      ngx_http_tcache_shm_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tcache_store_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tcache_loc_conf_t, default_buffer_size),
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
    ngx_http_tcache_exit_process,          /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_http_variable_t ngx_http_tcache_variables[] = {

    { ngx_string("tcache_status"),
      NULL, ngx_http_tcache_status_variable, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_tcache_access_handler(ngx_http_request_t *r)
{
    time_t                         delta;
    ngx_int_t                      rc;
    ngx_str_t                      cache_key;
    ngx_http_tcache_t             *cache;
    ngx_http_tcache_ctx_t         *ctx;
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

    ctx->cache_control = ctx->parse_cache_control(&r->headers_in.headers.part,
                                                  NULL, &delta);

    if (ctx->cache_control & TCACHE_CONTROL_NO_CACHE) {
        goto bypass;
    }

    rc = ngx_http_tcache_poseponsed_to_access_phase_end(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_complex_value(r, &conf->key, &cache_key) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cache_key.len == 0) {
        goto bypass;
    }

    ctx->key_string = cache_key;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache request key \"%V\"", &ctx->key_string);

    ngx_http_tcache_create_key(ctx, &cache_key);

    cache = conf->shm_zone->data;
    ngx_shmtx_lock(&cache->shpool->mutex);
    /* The data are filled in the ctx->cache_content */
    rc = cache->storage->get(cache, ctx, 0);
    ngx_shmtx_unlock(&cache->shpool->mutex);

    switch (rc) {

    case NGX_OK:
        /* find the record */
        ctx->use_cache = 1;
        return ngx_http_tcache_send(r, ctx);

    case NGX_DECLINED:
        /* not find the record */
        return rc;

    case NGX_ERROR:
        return NGX_ERROR;

    default:
        break;
    }

bypass:

    ctx->bypass = 1;
    return NGX_DECLINED;
}


/* 
 * This is a dirty hack from srcache, but it's useful to move this handler
 * to the end of the access phrase
 * */
static ngx_int_t
ngx_http_tcache_poseponsed_to_access_phase_end(ngx_http_request_t *r)
{
    ngx_http_phase_handler_t         tmp;
    ngx_http_phase_handler_t        *ph;
    ngx_http_phase_handler_t        *cur_ph;
    ngx_http_phase_handler_t        *last_ph;
    ngx_http_core_main_conf_t       *cmcf;
    ngx_http_tcache_main_conf_t     *tmcf;

    tmcf = ngx_http_get_module_main_conf(r, ngx_http_tcache_module);

    if (tmcf->postponed_to_access_phase_end) {
        return NGX_OK;
    }

    tmcf->postponed_to_access_phase_end = 1;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    ph = cmcf->phase_engine.handlers;
    cur_ph = &ph[r->phase_handler];

    /* we should skip the post_access phase handler here too */
    last_ph = &ph[cur_ph->next - 2];

    if (cur_ph < last_ph) {

        tmp = *cur_ph;

        memmove(cur_ph, cur_ph + 1,
                (last_ph - cur_ph) * sizeof(ngx_http_phase_handler_t));

        *last_ph = tmp;

        r->phase_handler--; /* redo the current ph */

        return NGX_DECLINED;
    }

    return NGX_OK;
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
    ngx_buf_t                             *b, *cb;
    ngx_chain_t                            out;
    ngx_http_tcache_node_t                *node;
    ngx_http_tcache_content_header_t      *h;

    node = ctx->node;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache send request \"%V\"", &r->uri);

    cb = ctx->cache_content;
    h = (ngx_http_tcache_content_header_t *) cb->start;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "tcache send request header_start: %z, body_start: %z",
                   h->header_start, h->body_start);

    if (h->header_start >= h->body_start) {
        return NGX_ERROR;
    }

    cb->pos  = cb->start + h->header_start;
    cb->last = cb->start + h->body_start;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache process headers: \"%*s\"",
                  cb->last - cb->pos, cb->pos);

    rc = ctx->process_headers(r, cb);
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

    b->start = b->pos = cb->start + h->body_start;
    b->last = b->end = cb->end;

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


ngx_buf_t *
buffer_append(ngx_buf_t *b, u_char *s, size_t len, ngx_pool_t *pool)
{
    u_char      *p;         
    ngx_uint_t   capacity, size;

    if (len > (size_t) (b->end - b->last)) {

        size = b->last - b->pos;

        capacity = b->end - b->start;
        capacity <<= 2;
        if (capacity < (size + len)) {
            capacity = size + len;  
        }

        p = ngx_palloc(pool, capacity);
        if (p == NULL) {
            return NULL;
        }

        b->last = ngx_copy(p, b->pos, size);       

        b->start = b->pos = p;
        b->end = p + capacity;
    }

    b->last = ngx_copy(b->last, s, len);

    return b;
}


static ngx_int_t
ngx_http_tcache_header_filter(ngx_http_request_t *r)
{
    time_t                         delta;
    ngx_int_t                      rc;
    ngx_uint_t                     fail_status;
    ngx_http_tcache_t             *cache;
    ngx_http_tcache_ctx_t         *ctx;
    ngx_http_tcache_loc_conf_t    *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tcache_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_tcache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->bypass || ctx->use_cache) {
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

    ctx->cache_control |= ctx->parse_cache_control(&r->headers_out.headers.part,
                                                   &r->headers_out.cache_control,
                                                   &delta);

    if ((ctx->cache_control & TCACHE_CONTROL_NO_CACHE) || 
        (ctx->cache_control & TCACHE_CONTROL_NO_STORE) ||
         (ctx->cache_control & TCACHE_CONTROL_PRIVATE)) {

        return ngx_http_next_header_filter(r);
    }

    if (delta) {
        ctx->valid = delta;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache cache_control=0x%xi, valid: %T",
                  ctx->cache_control, ctx->valid);

    ctx->status = r->headers_out.status;
    ctx->last_modified = r->headers_out.last_modified_time;
    ctx->grace = conf->grace;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache header filter \"%V\", %T", &r->uri, ctx->valid);

    fail_status = ngx_http_tcache_get_fail_status(ctx->status);
    if (fail_status & conf->status_use_stale) {
        ctx->can_use_stale = 1;
    }

    cache = conf->shm_zone->data;
    ngx_shmtx_lock(&cache->shpool->mutex);
    rc = cache->storage->get(cache, ctx, 1);
    ngx_shmtx_unlock(&cache->shpool->mutex);

    switch (rc) {

    case NGX_OK:
        /* If we find the record, we don't need insert it again. */
        return ngx_http_next_header_filter(r);

    case NGX_AGAIN:
        /* TODO: return the stale cache */
        ctx->use_stale_cache = 1;
        break;

    case NGX_ERROR:
        return NGX_ERROR;

    default: /* NGX_DECLINED */
        break;
    }

    ctx->store = 1;
    r->filter_need_in_memory = 1;

    /* Prealloc a large buffer to store the whole response, default: 128KB */
    ctx->cache_content = ngx_create_temp_buf(r->pool,
                                             conf->default_buffer_size);
    if (ctx->cache_content == NULL) {
        return NGX_ERROR;
    }

    /* Store the response headers */
    rc = ctx->store_headers(r, ctx->cache_content);
    if (rc != NGX_OK) {
        return rc;
    }

    ctx->cache_length = ngx_buf_size(ctx->cache_content);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "tcache header filter buffer: %z", ctx->cache_length);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_tcache_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                         len;
    ngx_int_t                      last, rc;
    ngx_buf_t                     *b;
    ngx_chain_t                   *cl;
    ngx_http_tcache_t             *cache;
    ngx_http_tcache_ctx_t         *ctx;
    ngx_http_tcache_loc_conf_t    *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tcache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->bypass || ctx->use_cache || ctx->valid == 0 || ctx->store == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "tcache body filter \"%V\"", &r->uri);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tcache_module);

    last = 0;
    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;

        if (ngx_buf_in_memory(b)) {
            len = ngx_buf_size(b);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "tcache body filter buffer: %z", len);

            if (buffer_append(ctx->cache_content, b->pos, len, r->pool) == NULL) {
                return NGX_ERROR;
            }

            ctx->cache_length += len;
            ctx->content_length += len;
        }

        if (b->last_buf) {
            last = 1;
            break;
        }
    }

    if (last && ctx->store) {
        cache = conf->shm_zone->data;
        ngx_shmtx_lock(&cache->shpool->mutex);
        rc = cache->storage->get(cache, ctx, 1);
        ngx_shmtx_unlock(&cache->shpool->mutex);

        if (rc == NGX_OK) {
            return ngx_http_next_body_filter(r, in);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "tcache body total single buffer: %z", ctx->cache_length);

        if ((size_t)ngx_buf_size(ctx->cache_content) != ctx->cache_length) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "tcache invalid cache_length");
            return ngx_http_next_body_filter(r, in);
        }

        ctx->payload = ctx->cache_content->pos;

        ngx_shmtx_lock(&cache->shpool->mutex);
        rc = cache->storage->put(cache, ctx);
        ngx_shmtx_unlock(&cache->shpool->mutex);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    return ngx_http_next_body_filter(r, in);
}


static ngx_uint_t
ngx_http_tcache_get_fail_status(ngx_uint_t status)
{
    ngx_uint_t ft;

    ft = 0;

    switch (status) {

    case 500:
        ft = NGX_HTTP_FT_HTTP_500;
        break;

    case 502:
        ft = NGX_HTTP_FT_HTTP_502;
        break;

    case 503:
        ft = NGX_HTTP_FT_HTTP_503;
        break;

    case 504:
        ft = NGX_HTTP_FT_HTTP_504;
        break;

    case 404:
        ft = NGX_HTTP_FT_HTTP_404;
        break;

    case 408:
        ft = NGX_HTTP_FT_HTTP_408;
        break;

    default:
        break;
    }

    return ft;
}


static ngx_int_t
ngx_http_tcache_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_tcache_ctx_t         *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_tcache_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->bypass) {
        v->len = sizeof("BYPASS") - 1;
        v->data = (u_char *) "BYPASS";

    } else if (ctx->store) {
        v->len = sizeof("MISS") - 1;
        v->data = (u_char *) "MISS";

    } else {
        v->len = sizeof("HIT") - 1;
        v->data = (u_char *) "HIT";
    } 

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

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
    max_size = 256 * 1024 * 1024;

    cache = ngx_pcalloc(cf->pool, sizeof(ngx_http_tcache_t));
    if (cache == NULL) {
        return NGX_CONF_ERROR;
    }

    cache->name = value[1];
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

#if (NGX_TCACHE_MDB)
    /* 
     * The mdb library will take care of all the stuff.
     * This shared memory is only used for lock purpose
     * */
    if (cache->storage == &tcache_mdb) {
        max_size = ngx_pagesize; 
    }
#endif

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
     *     conf->status_use_stale = 0;
     *     conf->methods = 0;
     *     conf->shm_zone = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->valid = NGX_CONF_UNSET_PTR;
    conf->bypass = NGX_CONF_UNSET_PTR;
    conf->default_expires = NGX_CONF_UNSET;
    conf->grace = NGX_CONF_UNSET;

    conf->hide_headers = NGX_CONF_UNSET_PTR;
    conf->pass_headers = NGX_CONF_UNSET_PTR;

    conf->default_buffer_size = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_tcache_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_str_t                          default_key = ngx_string(DEFAULT_KEY);
    ngx_hash_init_t                    hash;
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
    ngx_conf_merge_sec_value(conf->default_expires, prev->default_expires, 60);
    ngx_conf_merge_sec_value(conf->grace, prev->grace, 60);
    ngx_conf_merge_size_value(conf->default_buffer_size,
                              prev->default_buffer_size, 128 * 1024);

    ngx_conf_merge_bitmask_value(conf->status_use_stale, prev->status_use_stale,
                                 (NGX_CONF_BITMASK_SET | NGX_HTTP_FT_HTTP_OFF));

    if (conf->status_use_stale & NGX_HTTP_FT_HTTP_OFF) {
        conf->status_use_stale = NGX_CONF_BITMASK_SET | NGX_HTTP_FT_HTTP_OFF;
    }

    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "tcache_store_hide_headers_hash";

    if (ngx_http_tcache_hide_headers_hash(cf, conf,
        prev, ngx_http_tcache_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
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
     * tmcf->headers_in_hash = 0;
     * tmcf->postphoned_to_access_phase_end = 0;
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


static void
ngx_http_tcache_exit_process(ngx_cycle_t *cycle)
{
    /* TODO: cleanup the mdb */
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
        cache->shpool = ocache->shpool;
        cache->sh = ocache->sh;

        ngx_shmtx_lock(&ocache->shpool->mutex);
        ocache->storage->cleanup(ocache);
        ngx_shmtx_unlock(&ocache->shpool->mutex);

#if (NGX_TCACHE_MDB)
        if (cache->storage == &tcache_mdb) {
            ngx_shmtx_lock(&cache->shpool->mutex);
            if (cache->storage->init(cache) != NGX_OK) {
                ngx_shmtx_unlock(&cache->shpool->mutex);
                return NGX_ERROR;
            }
            ngx_shmtx_unlock(&cache->shpool->mutex);
        }
#endif

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
