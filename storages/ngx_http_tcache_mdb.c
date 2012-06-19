
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

/*#include <tbsys.h>*/
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pthread.h>

#include "libmdb_c.hpp"
#include "ngx_http_tcache_module.h"


#define MAX_PROCESS_NUM 50
#define MAX_KEY_SIZE 1024
#define MAX_VALUE_SIZE (1<<22)


typedef struct {
    uint64_t           mem_size;
    pthread_mutex_t   *mutex;
    int                area;
    mdb_t              db;
} ngx_mdb_t;


static ngx_int_t ngx_http_tcache_mdb_init(ngx_http_tcache_t *cache);
static ngx_http_tcache_node_t * ngx_http_tcache_mdb_get(
    ngx_http_tcache_t *cache, u_char *key, ngx_http_tcache_ctx_t *ctx);
static ngx_http_tcache_node_t * ngx_http_tcache_mdb_create(
    ngx_http_tcache_t *cache, u_char *key);
static void ngx_http_tcache_mdb_delete(ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *node);
static void ngx_http_tcache_mdb_expire(ngx_http_tcache_t *cache);
static void ngx_http_tcache_mdb_force_expire(ngx_http_tcache_t *cache);
static void ngx_http_tcache_mdb_cleanup(ngx_http_tcache_t *cache);


ngx_http_tcache_storage_t tcache_mdb = {
    ngx_http_tcache_mdb_init,
    ngx_http_tcache_mdb_create,
    ngx_http_tcache_mdb_get,
    NULL,
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
    uint64_t                  quota;
    ngx_mdb_t                *mdb;
    mdb_param_t               params;
    pthread_mutexattr_t       attr;

    mdb = ngx_pcalloc(cache->pool, sizeof(ngx_mdb_t));
    if (mdb == NULL) {
        return NGX_ERROR;
    }

    /*TBSYS_LOGGER.setLogLevel("warn");*/
    /*if (cache->log && cache->log->file) {*/
    /*TBSYS_LOGGER.setFileName(cache->log->file->name.data);*/
    /*}*/

    mdb->mutex = (pthread_mutex_t*)mmap(NULL, sizeof(pthread_mutex_t),
                                        PROT_READ|PROT_WRITE,
                                        MAP_SHARED|MAP_ANON, -1, 0);
    if (mdb->mutex == MAP_FAILED) {
        return NGX_ERROR;
    }

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(mdb->mutex, &attr);

    ngx_memzero(&params, sizeof(mdb_param_t));

    params.mdb_type = "mdb_shm";
    params.mdb_path = "/libmdb_shm";
    params.size = cache->size;

    mdb->db = mdb_init(&params);
    mdb->area = 0;

    quota = cache->size >> 1;
    mdb_set_quota(mdb->db, mdb->area, quota);

    cache->mdb = mdb;

    return NGX_OK;
}


static ngx_http_tcache_node_t *
ngx_http_tcache_mdb_get(ngx_http_tcache_t *cache, u_char *key,
    ngx_http_tcache_ctx_t *ctx)
{
    /*ngx_int_t rc;*/

    /*rc = mdb_get(db, 0, &key, &value, NULL, );*/

    return NULL;
}


static ngx_http_tcache_node_t *
ngx_http_tcache_mdb_create(ngx_http_tcache_t *cache, u_char *key)
{
    return NULL;
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
    ngx_mdb_t *mdb;

    mdb = cache->mdb;

    pthread_mutex_destroy(mdb->mutex);
    munmap(mdb->mutex, sizeof(pthread_mutex_t));
    mdb_destroy(mdb->db);
}
