
#ifndef NGX_HTTP_TCACHE_HEADERS_H
#define NGX_HTTP_TCACHE_HEADERS_H


#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_tcache_module.h"


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
} ngx_http_tcache_header_t;


extern ngx_http_tcache_header_t  ngx_http_tcache_headers_in[];


ngx_int_t ngx_http_tcache_headers_init(ngx_http_tcache_ctx_t *ctx);

#endif
