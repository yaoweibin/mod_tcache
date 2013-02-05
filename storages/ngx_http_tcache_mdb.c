
#include "libmdb_c.hpp"
#include "ngx_http_tcache_module.h"


#define MAX_KEY_SIZE      1024   /* 1K */
#define MAX_VALUE_SIZE   (1<<20) /* 1M */
#define MIN_MDB_SIZE     (1<<28) /* 256M */


typedef struct {
    int                area;
    uint64_t           mem_size;
    uint64_t           quota;
    uint32_t           key_size;
    uint32_t           value_size;
    int                action_type;
    int                action_mode;
    char              *name; 
    char              *path; 
    char              *log; 
    mdb_t              db;
} ngx_mdb_t;


static ngx_int_t ngx_http_tcache_mdb_name(ngx_http_tcache_t *cache);
static ngx_int_t ngx_http_tcache_mdb_init(ngx_http_tcache_t *cache);
static ngx_int_t ngx_http_tcache_mdb_get(
    ngx_http_tcache_t *cache, ngx_http_tcache_ctx_t *ctx, ngx_flag_t lookup);
static ngx_int_t ngx_http_tcache_mdb_put(ngx_http_tcache_t *cache,
    ngx_http_tcache_ctx_t *ctx);
static void ngx_http_tcache_mdb_delete(ngx_http_tcache_t *cache,
    ngx_http_tcache_node_t *tn);
static void ngx_http_tcache_mdb_expire(ngx_http_tcache_t *cache);
static void ngx_http_tcache_mdb_force_expire(ngx_http_tcache_t *cache);
static void ngx_http_tcache_mdb_cleanup(ngx_http_tcache_t *cache);


ngx_http_tcache_storage_t tcache_mdb = {
    ngx_http_tcache_mdb_init,
    ngx_http_tcache_mdb_get,
    ngx_http_tcache_mdb_put,
    NULL,
    ngx_http_tcache_mdb_delete,
    ngx_http_tcache_mdb_expire,
    ngx_http_tcache_mdb_force_expire,
    ngx_http_tcache_mdb_cleanup,
};


static ngx_int_t
ngx_http_tcache_mdb_init(ngx_http_tcache_t *cache)
{
    ngx_mdb_t    *mdb;
    mdb_param_t   params;

    mdb = ngx_pcalloc(cache->pool, sizeof(ngx_mdb_t));
    if (mdb == NULL) {
        return NGX_ERROR;
    }

    cache->mdb = mdb;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cache->log, 0, "tcache mdb init");

    mdb->log = (char *) cache->log->file->name.data;
    mdb_log_file(mdb->log);
    mdb_log_level("error");

    if (ngx_http_tcache_mdb_name(cache) == NGX_ERROR) {
        return NGX_ERROR;
    }

#if NGX_LINUX && 0
    ngx_fd_t                  fd;
    struct flock              fl;

    fd = open((char *)mdb->path, O_RDWR);
    if (fd > 0) {
        fl.l_start = 0;
        fl.l_len = 0;
        fl.l_pid = 0;
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;

        /* record lock can't inherit after fork, sucks */
        if (fcntl(fd, F_SETLK, &fl) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cache->log, 0,
                          "tcache error: the shared memory \"%s\" is using",
                          mdb->name);

            return NGX_ERROR;
        }
    }

    ngx_delete_file(mdb->path);
#endif

    ngx_memzero(&params, sizeof(mdb_param_t));

    params.mdb_type = "mdb_shm";
    params.mdb_path = mdb->name;
    /* cache->size must be larger than 160M */
    params.size = cache->size > MIN_MDB_SIZE ? cache->size : MIN_MDB_SIZE;

    mdb->db = mdb_init(&params);
    mdb->area = 0;
    mdb->quota = cache->size >> 1;

    mdb_set_quota(mdb->db, mdb->area, mdb->quota);

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_mdb_name(ngx_http_tcache_t *cache)
{
    size_t        len;
    u_char       *name, *path;
    ngx_mdb_t    *mdb;

    mdb = cache->mdb;
    if (mdb == NULL) {
        return NGX_ERROR;
    }

    len = sizeof("libmdb_") - 1 + cache->name.len;

    name = ngx_pnalloc(cache->pool, len + 1);
    if (name == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(name, len, "%s%V%Z", (u_char *) "libmdb_", &cache->name);

    len += sizeof("/dev/shm/") - 1;

    path = ngx_pnalloc(cache->pool, len + 1);
    if (path == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(path, len, "/dev/shm/%s%Z", name);

    mdb->name = (char *) name;
    mdb->path = (char *) path;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_mdb_get(ngx_http_tcache_t *cache, ngx_http_tcache_ctx_t *ctx,
    ngx_flag_t lookup)
{
    int           expire;
    ngx_buf_t    *buf;
    ngx_int_t     rc;
    ngx_mdb_t    *mdb;
    data_entry_t  key, value;

    key.data = (char *) ctx->key;
    key.size = NGX_HTTP_CACHE_KEY_LEN;

    mdb = cache->mdb;

    if (lookup) {
        rc = mdb_lookup(mdb->db, mdb->area, &key);
        if (rc == true) {
            return NGX_OK;
        } else {
            return NGX_DECLINED;
        }
    }

    rc = mdb_get(mdb->db, mdb->area, &key, &value, NULL, &expire);
    if (rc != 0) {
        return NGX_DECLINED;
    }

    rc = NGX_OK;

    if (value.size == 0) {
        return rc;
    }

    ctx->cache_length = value.size;

    buf = ngx_create_temp_buf(ctx->pool, value.size);
    if (buf == NULL) {
        rc = NGX_ERROR;
        goto end;
    }

    buf->last = buf->end = ngx_copy(buf->pos, value.data, value.size);

    ctx->cache_content = buf;
    ctx->payload = buf->pos;

end:

    free(value.data);

    return rc;
}


static ngx_int_t
ngx_http_tcache_mdb_put(ngx_http_tcache_t *cache, ngx_http_tcache_ctx_t *ctx)
{
    int                     expire, rc;
    ngx_mdb_t              *mdb;
    data_entry_t            key, value;

    mdb = cache->mdb;

    key.data = (char *)ctx->key;
    key.size = NGX_HTTP_CACHE_KEY_LEN;

    value.data = (char *)ctx->payload;
    value.size = ctx->cache_length;

    expire = (int) ctx->valid + ngx_time();
    rc = mdb_put(mdb->db, mdb->area, &key, &value, 0, 1, expire);
    if (rc != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_tcache_mdb_delete(ngx_http_tcache_t *cache, ngx_http_tcache_node_t *tn)
{
    ngx_mdb_t    *mdb;
    data_entry_t  key;

    mdb = cache->mdb;

    key.data = (char *)tn->key;
    key.size = NGX_HTTP_CACHE_KEY_LEN;

   (void) mdb_del(mdb->db, mdb->area, &key, 0);
}


static void
ngx_http_tcache_mdb_expire(ngx_http_tcache_t *cache)
{
    /* Do nothing, mdb will take care of all the thing */
}


static void
ngx_http_tcache_mdb_force_expire(ngx_http_tcache_t *cache)
{
    /* Do nothing, mdb will take care of all the thing */
}


static void
ngx_http_tcache_mdb_cleanup(ngx_http_tcache_t *cache)
{
    ngx_mdb_t *mdb;

    mdb = cache->mdb;

#if 0
    if (mdb && mdb->path) {
        ngx_delete_file(mdb->path);
    }
#endif

    if (mdb && mdb->db) {
        mdb_destroy(mdb->db);
    }
}
