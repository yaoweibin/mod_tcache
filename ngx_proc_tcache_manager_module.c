
#include <ngx_event.h>
#include <ngx_core.h>
#include <ngx_config.h>
#include "ngx_http_tcache_module.h"


static char *ngx_proc_tcache_manager(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_proc_tcache_manager_create_conf(ngx_conf_t *cf);
static char *ngx_proc_tcache_manager_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_proc_tcache_manager_prepare(ngx_cycle_t *cycle);
static ngx_shm_zone_t * ngx_shared_memory_get(ngx_cycle_t *cycle,
    ngx_str_t *name, size_t size, void *tag);
static ngx_int_t ngx_proc_tcache_manager_process_init(ngx_cycle_t *cycle);
static void ngx_proc_tcache_manager_expire(ngx_event_t *event);
static ngx_int_t ngx_proc_tcache_manager_loop(ngx_cycle_t *cycle);
static void ngx_proc_tcache_manager_process_exit(ngx_cycle_t *cycle);
static void ngx_proc_tcache_manager_accept(ngx_event_t *ev);


typedef struct {
    ngx_flag_t                       enable;
    ngx_uint_t                       port;
    ngx_msec_t                       interval;;

    ngx_socket_t                     fd;
    ngx_event_t                      expire_event;
    ngx_str_t                        shm_name;
    ngx_shm_zone_t                  *shm_zone;
} ngx_proc_tcache_manager_conf_t;


static ngx_command_t ngx_proc_tcache_manager_commands[] = {

    { ngx_string("listen"),
      NGX_PROC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_PROC_CONF_OFFSET,
      offsetof(ngx_proc_tcache_manager_conf_t, port),
      NULL },

    { ngx_string("tcache_manager"),
      NGX_PROC_CONF|NGX_CONF_FLAG,
      ngx_proc_tcache_manager,
      NGX_PROC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tcache_manager_interval"),
      NGX_PROC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_msec_slot,
      NGX_PROC_CONF_OFFSET,
      offsetof(ngx_proc_tcache_manager_conf_t, interval),
      NULL },

      ngx_null_command
};


static ngx_proc_module_t ngx_proc_tcache_manager_module_ctx = {
    ngx_string("tcache_manager"),            /* name                     */
    NULL,                                    /* create main configration */
    NULL,                                    /* init main configration   */
    ngx_proc_tcache_manager_create_conf,     /* create proc configration */
    ngx_proc_tcache_manager_merge_conf,      /* merge proc configration  */
    ngx_proc_tcache_manager_prepare,         /* prepare                  */
    ngx_proc_tcache_manager_process_init,    /* process init             */
    ngx_proc_tcache_manager_loop,            /* loop cycle               */
    ngx_proc_tcache_manager_process_exit     /* process exit             */
};


ngx_module_t ngx_proc_tcache_manager_module = {
    NGX_MODULE_V1,
    &ngx_proc_tcache_manager_module_ctx,
    ngx_proc_tcache_manager_commands,
    NGX_PROC_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static char *
ngx_proc_tcache_manager(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_proc_tcache_manager_conf_t    *ptmcf = conf;
    ngx_str_t                         *value;

    value = cf->args->elts;

    if (ptmcf->shm_zone) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ptmcf->shm_zone = NULL;
        return NGX_CONF_OK;
    }

    ptmcf->enable = 1;
    ptmcf->shm_name = value[1];

    return NGX_CONF_OK;
}


static void *
ngx_proc_tcache_manager_create_conf(ngx_conf_t *cf)
{
    ngx_proc_tcache_manager_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_proc_tcache_manager_conf_t));
    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "tcache_manager create proc conf error");
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->fd = 0;
     *     conf->expire_event all NULL or 0
     *     conf->shm_name = {0, NULL};
     *     conf->shm_zone = 0;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->port = NGX_CONF_UNSET_UINT;
    conf->interval = NGX_CONF_UNSET_MSEC;

    return conf;
}


static char *
ngx_proc_tcache_manager_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_proc_tcache_manager_conf_t  *prev = parent;
    ngx_proc_tcache_manager_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->port, prev->port, 0);
    ngx_conf_merge_msec_value(conf->interval, prev->interval, 5000);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_proc_tcache_manager_prepare(ngx_cycle_t *cycle)
{
    ngx_proc_tcache_manager_conf_t *conf;

    conf = ngx_proc_get_conf(cycle->conf_ctx, ngx_proc_tcache_manager_module);
    if (!conf->enable) {
        return NGX_DECLINED;
    }

    if (conf->shm_zone) {
        return NGX_OK;
    }

    conf->shm_zone = ngx_shared_memory_get(cycle, &conf->shm_name, 0,
                                           &ngx_http_tcache_module);
    if (conf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_shm_zone_t *
ngx_shared_memory_get(ngx_cycle_t *cycle, ngx_str_t *name, size_t size,
    void *tag)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (ngx_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
            != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "the shared memory zone \"%V\" is "
                          "already declared for a different use",
                          &shm_zone[i].shm.name);
            return NULL;
        }

        return &shm_zone[i];
    }

    return NULL;
}


static ngx_int_t
ngx_proc_tcache_manager_process_init(ngx_cycle_t *cycle)
{
    int                             reuseaddr;
    ngx_event_t                    *rev, *expire;
    ngx_socket_t                    fd;
    ngx_connection_t               *c;
    struct sockaddr_in              sin;
    ngx_proc_tcache_manager_conf_t *conf;

    conf = ngx_proc_get_conf(cycle->conf_ctx, ngx_proc_tcache_manager_module);

    fd = ngx_socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "tcache_manager socket error");
        return NGX_ERROR;
    }

    reuseaddr = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *) &reuseaddr, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "tcache_manager setsockopt(SO_REUSEADDR) failed");

        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "tcache_manager nonblocking failed");

        ngx_close_socket(fd);
        return NGX_ERROR;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(conf->port);

    if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "tcache_manager bind error");
        return NGX_ERROR;
    }

    if (listen(fd, 20) == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "tcache_manager listen error");
        return NGX_ERROR;
    }

    c = ngx_get_connection(fd, cycle->log);
    if (c == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "tcache_manager no connection");
        return NGX_ERROR;
    }

    c->log = cycle->log;
    rev = c->read;
    rev->log = c->log;
    rev->accept = 1;
    rev->handler = ngx_proc_tcache_manager_accept;

    if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
        return NGX_ERROR;
    }

    conf->fd = fd;

    expire = &conf->expire_event;

    expire->handler = ngx_proc_tcache_manager_expire;
    expire->log = cycle->log;
    expire->data = conf;
    expire->timer_set = 0;
    
    ngx_add_timer(expire, conf->interval);

    return NGX_OK;
}


static void
ngx_proc_tcache_manager_expire(ngx_event_t *event)
{
    ngx_http_tcache_t              *cache;
    ngx_proc_tcache_manager_conf_t *conf;

    conf = event->data;

    if (conf == NULL || conf->shm_zone == NULL) {
        return;
    }

    cache = conf->shm_zone->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, event->log, 0,
                   "tcache_manager manager expire");

    ngx_shmtx_lock(&cache->shpool->mutex);
    cache->storage->expire(cache);
    ngx_shmtx_unlock(&cache->shpool->mutex);

    ngx_add_timer(event, conf->interval);
}


static ngx_int_t
ngx_proc_tcache_manager_loop(ngx_cycle_t *cycle)
{
    return NGX_OK;
}


static void
ngx_proc_tcache_manager_process_exit(ngx_cycle_t *cycle)
{
    ngx_proc_tcache_manager_conf_t *conf;

    conf = ngx_proc_get_conf(cycle->conf_ctx, ngx_proc_tcache_manager_module);

    if (conf->fd) {
        ngx_close_socket(conf->fd);
    }

    if (conf->expire_event.timer_set) {
        ngx_del_timer(&conf->expire_event);
    }
}


/*TODO: The manager interface handler*/
static void
ngx_proc_tcache_manager_accept(ngx_event_t *ev)
{
    u_char                sa[NGX_SOCKADDRLEN];
    ngx_str_t             output = ngx_string("Hello world");
    socklen_t             socklen;
    ngx_socket_t          s;
    ngx_connection_t     *lc;

    lc = ev->data;
    s = accept(lc->fd, (struct sockaddr *) sa, &socklen);
    if (s == -1) {
        return;
    }

    if (ngx_nonblocking(s) == -1) {
        goto finish;
    }

    ngx_write_fd(s, output.data, output.len);

finish:

    ngx_close_socket(s);
}
