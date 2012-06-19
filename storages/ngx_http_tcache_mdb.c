
#include "ngx_http_tcache_module.h"


static ngx_int_t ngx_http_tcache_mdb_init(ngx_http_tcache_t *cache);
static ngx_http_tcache_node_t * ngx_http_tcache_mdb_lookup(ngx_http_tcache_t *cache, u_char *key);
static ngx_http_tcache_node_t * ngx_http_tcache_mdb_create(ngx_http_tcache_t *cache, u_char *key);
static u_char * ngx_http_tcache_mdb_alloc(ngx_http_tcache_t *cache, size_t size);
static void ngx_http_tcache_mdb_delete(ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *node);
static void ngx_http_tcache_mdb_expire(ngx_http_tcache_t *cache);
static void ngx_http_tcache_mdb_force_expire(ngx_http_tcache_t *cache);
static void ngx_http_tcache_mdb_cleanup(ngx_http_tcache_t *cache);


ngx_http_tcache_storage_t tcache_mdb = {
    ngx_http_tcache_mdb_init,
    ngx_http_tcache_mdb_create,
    ngx_http_tcache_mdb_lookup,
    ngx_http_tcache_mdb_alloc,
    NULL,
    NULL,
    ngx_http_tcache_mdb_delete,
    ngx_http_tcache_mdb_expire,
    ngx_http_tcache_mdb_force_expire,
    ngx_http_tcache_mdb_cleanup,
};


static ngx_int_t
ngx_http_tcache_mdb_init(ngx_http_tcache_t *cache)
{
    return NGX_OK;
}


static ngx_http_tcache_node_t *
ngx_http_tcache_mdb_lookup(ngx_http_tcache_t *cache, u_char *key)
{
    return NULL;
}


static ngx_http_tcache_node_t *
ngx_http_tcache_mdb_create(ngx_http_tcache_t *cache, u_char *key)
{
    return NULL;
}


static u_char *
ngx_http_tcache_mdb_alloc(ngx_http_tcache_t *cache, size_t size)
{
    return NGX_OK;
}


static void
ngx_http_tcache_mdb_delete(ngx_http_tcache_t *cache, ngx_http_tcache_node_t *node)
{
}


static void
ngx_http_tcache_mdb_expire(ngx_http_tcache_t *cache)
{
}


static void
ngx_http_tcache_mdb_force_expire(ngx_http_tcache_t *cache)
{
}


static void
ngx_http_tcache_mdb_cleanup(ngx_http_tcache_t *cache)
{
}
