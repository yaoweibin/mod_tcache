
#include "ngx_http_tcache_module.h"


#define NBUCKET 33

typedef struct {
    ngx_queue_t order;
    ngx_queue_t free[NBUCKET];
    ngx_queue_t used;
} ngx_http_tcache_memory_manager_t;

typedef struct {
    ngx_buf_t storage;
} ngx_http_tcache_memory_chunk_t;


ngx_http_tcache_storage_t tcache_freelist = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};
