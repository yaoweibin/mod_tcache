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


#define NGX_HTTP_FT_HTTP_START      0x00000002
#define NGX_HTTP_FT_HTTP_FOO        0x00000004
#define NGX_HTTP_FT_HTTP_BAR        0x00000008
#define NGX_HTTP_FT_HTTP_500        0x00000010
#define NGX_HTTP_FT_HTTP_502        0x00000020
#define NGX_HTTP_FT_HTTP_503        0x00000040
#define NGX_HTTP_FT_HTTP_504        0x00000080
#define NGX_HTTP_FT_HTTP_404        0x00000100
#define NGX_HTTP_FT_HTTP_UPDATING   0x00000200
#define NGX_HTTP_FT_HTTP_OFF        0x00000400


typedef struct {
    ngx_flag_t                       enable;

    ngx_shm_zone_t                  *shm_zone;

    ngx_http_complex_value_t         key;

    ngx_uint_t                       methods;
    time_t                           default_expires;
    /* the the grace time period after node expires */
    time_t                           grace;

    ngx_array_t                     *valid;
    ngx_array_t                     *bypass;
    ngx_array_t                     *no_cache;

    ngx_uint_t                       status_use_stale;

    ngx_hash_t                       hide_headers_hash;
    ngx_array_t                     *hide_headers;
    ngx_array_t                     *pass_headers;

    size_t                           max_size;
    size_t                           default_buffer_size;

} ngx_http_tcache_loc_conf_t;


#define TCACHE_CONTROL_NO_CACHE    0x00000001
#define TCACHE_CONTROL_NO_STORE    0x00000002
#define TCACHE_CONTROL_PRIVATE     0x00000004
#define TCACHE_CONTROL_PUBLIC      0x00000008


struct ngx_http_tcache_ctx_s {
    time_t                           valid;
    ngx_uint_t                       status;
    time_t                           age;
    time_t                           grace;
    time_t                           last_modified;
    off_t                            content_length;
    ngx_str_t                        key_string;
    u_char                           key[NGX_HTTP_CACHE_KEY_LEN];

    ngx_uint_t                     (*parse_cache_control)(ngx_list_part_t *part, ngx_array_t *cache_controls, time_t *delta);
    ngx_int_t                      (*process_headers)(ngx_http_request_t *r,
                                                      ngx_buf_t *buffer);
    ngx_int_t                      (*store_headers)(ngx_http_request_t *r,
                                                    ngx_buf_t *buffer);

    size_t                           cache_length;
    ngx_buf_t                       *cache_content;
    u_char                          *payload;

    ngx_pool_t                      *pool;
    ngx_log_t                       *log;
    
    ngx_uint_t                       cache_control;

    unsigned                         updating_use_stale:1;
    unsigned                         can_use_stale:1;
    unsigned                         use_stale_cache:1;
    unsigned                         use_cache:1;
    unsigned                         bypass:1;
    unsigned                         store:1;

    ngx_http_tcache_node_t          *node;
};


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_uint_t                       postponed_to_access_phase_end;
} ngx_http_tcache_main_conf_t;


struct ngx_http_tcache_node_s {
    /* storage specific data pointer */
    void                            *index;

    u_char                          *key;
    time_t                           expires;
    time_t                           stale;
    time_t                           last_modified;
    time_t                           date;
    ngx_uint_t                       status;

    time_t                           last_try;
    ngx_uint_t                       fall_count;

    unsigned                         use_stale:1;
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
