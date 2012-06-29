#ifndef NGX_HTTP_TCACHE_MODULE_H
#define NGX_HTTP_TCACHE_MODULE_H


#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


typedef struct ngx_http_tcache_ctx_s ngx_http_tcache_ctx_t;
typedef struct ngx_http_tcache_node_s ngx_http_tcache_node_t;
typedef struct ngx_http_tcache_s ngx_http_tcache_t;


typedef ngx_int_t (*ngx_http_tcache_init_pt) (ngx_http_tcache_t *cache);
typedef ngx_int_t (*ngx_http_tcache_get_pt)
    (ngx_http_tcache_t *cache, ngx_http_tcache_ctx_t *ctx, ngx_flag_t lookup);
typedef ngx_int_t (*ngx_http_tcache_put_pt) (ngx_http_tcache_t *cache,
    ngx_http_tcache_ctx_t *ctx);
typedef ngx_int_t (*ngx_http_tcache_trim_pt) (ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *node, size_t size);
typedef void (*ngx_http_tcache_delete_pt) (ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *node);
typedef void (*ngx_http_tcache_expire_pt) (ngx_http_tcache_t *cache);
typedef void (*ngx_http_tcache_cleanup_pt) (ngx_http_tcache_t *cache);


typedef struct {
    ngx_http_tcache_init_pt         init;
    ngx_http_tcache_get_pt          get;
    ngx_http_tcache_put_pt          put;
    ngx_http_tcache_trim_pt         trim;
    ngx_http_tcache_delete_pt       delete;
    ngx_http_tcache_expire_pt       expire;
    ngx_http_tcache_expire_pt       force_expire;
    ngx_http_tcache_cleanup_pt      cleanup;
} ngx_http_tcache_storage_t;


typedef struct {
    ngx_flag_t                       enable;

    ngx_shm_zone_t                  *shm_zone;

    ngx_http_complex_value_t         key;

    ngx_uint_t                       methods;
    time_t                           default_expires;

    ngx_array_t                     *valid;
    ngx_array_t                     *bypass;

    ngx_uint_t                       use_stale;

    size_t                           default_buffer_size;

} ngx_http_tcache_loc_conf_t;


struct ngx_http_tcache_ctx_s {
    ngx_flag_t                       no_cache;
    time_t                           valid;
    time_t                           last_modified;
    off_t                            content_length;
    ngx_str_t                        key_string;
    u_char                           key[NGX_HTTP_CACHE_KEY_LEN];

    ngx_int_t                      (*process_headers)(ngx_http_request_t *r,
                                                      ngx_buf_t *buffer);
    ngx_int_t                      (*store_headers)(ngx_http_request_t *r,
                                                    ngx_buf_t *buffer);

    size_t                           cache_length;
    ngx_buf_t                       *cache_content;
    u_char                          *payload;

    ngx_pool_t                      *pool;

    unsigned                         store:1;

    ngx_http_tcache_node_t          *node;
};


typedef struct {
    ngx_hash_t                       headers_in_hash;
} ngx_http_tcache_main_conf_t;


struct ngx_http_tcache_node_s {
    /* storage specific data point */
    void                            *index;

    u_char                          *key;
    time_t                           expires;
    time_t                           last_modified;
    time_t                           date;

    unsigned                         exists:1;
    unsigned                         updating:1;

    size_t                           length;
    u_char                          *payload;
};


typedef struct {
    size_t                           header_start;
    size_t                           body_start;
} ngx_http_tcache_content_header_t;


struct ngx_http_tcache_s {
    ngx_str_t                        name;
    ngx_slab_pool_t                 *shpool;
    void                            *sh;

    void                            *mdb;
    ngx_pool_t                      *pool;

    ngx_log_t                       *log;

    size_t                           size;
    ngx_http_tcache_storage_t       *storage;
};

extern ngx_module_t  ngx_http_tcache_module;

ngx_buf_t * buffer_append(ngx_buf_t *b, u_char *s, size_t len,
    ngx_pool_t *pool);

#endif
