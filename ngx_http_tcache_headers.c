

#include "ngx_http_tcache_headers.h"


static ngx_uint_t ngx_http_tcache_control(ngx_list_part_t *part, ngx_array_t *cache_controls, time_t *delta);

static ngx_int_t ngx_http_tcache_process_status_line(ngx_http_request_t *r,
    ngx_buf_t *buffer);
static ngx_int_t ngx_http_tcache_process_headers(ngx_http_request_t *r,
    ngx_buf_t *buffer);
static ngx_int_t ngx_http_tcache_copy_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_tcache_store_headers(ngx_http_request_t *r,
    ngx_buf_t *buffer);

static ngx_int_t ngx_http_tcache_process_content_type(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_tcache_process_content_length(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_tcache_process_last_modified(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_tcache_process_multi_header_lines(
    ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_tcache_process_allow_ranges(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_tcache_process_accept_ranges(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_tcache_ignore_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_tcache_process_content_encoding(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);


static ngx_str_t ngx_http_status_lines[] = {

    ngx_string("200 OK"),
    ngx_string("201 Created"),
    ngx_string("202 Accepted"),
    ngx_null_string,  /* "203 Non-Authoritative Information" */
    ngx_string("204 No Content"),
    ngx_null_string,  /* "205 Reset Content" */
    ngx_string("206 Partial Content"),

    /* ngx_null_string, */  /* "207 Multi-Status" */

#define NGX_HTTP_LAST_2XX  207
#define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 200)

    /* ngx_null_string, */  /* "300 Multiple Choices" */

    ngx_string("301 Moved Permanently"),
    ngx_string("302 Moved Temporarily"),
    ngx_string("303 See Other"),
    ngx_string("304 Not Modified"),
    ngx_null_string,  /* "305 Use Proxy" */
    ngx_null_string,  /* "306 unused" */
    ngx_string("307 Temporary Redirect"),

#define NGX_HTTP_LAST_3XX  308
#define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)

    ngx_string("400 Bad Request"),
    ngx_string("401 Unauthorized"),
    ngx_string("402 Payment Required"),
    ngx_string("403 Forbidden"),
    ngx_string("404 Not Found"),
    ngx_string("405 Not Allowed"),
    ngx_string("406 Not Acceptable"),
    ngx_null_string,  /* "407 Proxy Authentication Required" */
    ngx_string("408 Request Time-out"),
    ngx_string("409 Conflict"),
    ngx_string("410 Gone"),
    ngx_string("411 Length Required"),
    ngx_string("412 Precondition Failed"),
    ngx_string("413 Request Entity Too Large"),
    ngx_null_string,  /* "414 Request-URI Too Large", but we never send it
                       * because we treat such requests as the HTTP/0.9
                       * requests and send only a body without a header
                       */
    ngx_string("415 Unsupported Media Type"),
    ngx_string("416 Requested Range Not Satisfiable"),

    /* ngx_null_string, */  /* "417 Expectation Failed" */
    /* ngx_null_string, */  /* "418 unused" */
    /* ngx_null_string, */  /* "419 unused" */
    /* ngx_null_string, */  /* "420 unused" */
    /* ngx_null_string, */  /* "421 unused" */
    /* ngx_null_string, */  /* "422 Unprocessable Entity" */
    /* ngx_null_string, */  /* "423 Locked" */
    /* ngx_null_string, */  /* "424 Failed Dependency" */

#define NGX_HTTP_LAST_4XX  417
#define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)

    ngx_string("500 Internal Server Error"),
    ngx_string("501 Method Not Implemented"),
    ngx_string("502 Bad Gateway"),
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_string("504 Gateway Time-out"),

    ngx_null_string,        /* "505 HTTP Version Not Supported" */
    ngx_null_string,        /* "506 Variant Also Negotiates" */
    ngx_string("507 Insufficient Storage"),
    /* ngx_null_string, */  /* "508 unused" */
    /* ngx_null_string, */  /* "509 unused" */
    /* ngx_null_string, */  /* "510 Not Extended" */

#define NGX_HTTP_LAST_5XX  508

};


ngx_http_tcache_header_t  ngx_http_tcache_headers_in[] = {

    { ngx_string("Content-Type"),
      ngx_http_tcache_process_content_type,
      0 },

    { ngx_string("Content-Length"),
      ngx_http_tcache_process_content_length,
      0 },

    { ngx_string("Date"),
      ngx_http_tcache_copy_header_line,
      offsetof(ngx_http_headers_out_t, date) },

    { ngx_string("Last-Modified"),
      ngx_http_tcache_process_last_modified,
      0 },

    { ngx_string("ETag"),
      ngx_http_tcache_copy_header_line,
      offsetof(ngx_http_headers_out_t, etag) },

    { ngx_string("Server"),
      ngx_http_tcache_copy_header_line,
      offsetof(ngx_http_headers_out_t, server) },

    { ngx_string("WWW-Authenticate"),
      ngx_http_tcache_copy_header_line,
      offsetof(ngx_http_headers_out_t, www_authenticate) },

    { ngx_string("Location"),
      ngx_http_tcache_copy_header_line,
      offsetof(ngx_http_headers_out_t, location) },

    { ngx_string("Refresh"),
      ngx_http_tcache_copy_header_line,
      offsetof(ngx_http_headers_out_t, refresh) },

    { ngx_string("Cache-Control"),
      ngx_http_tcache_process_multi_header_lines,
      offsetof(ngx_http_headers_out_t, cache_control) },

    { ngx_string("Expires"),
      ngx_http_tcache_copy_header_line,
      offsetof(ngx_http_headers_out_t, expires) },

    { ngx_string("X-Allow-Ranges"),
      ngx_http_tcache_process_allow_ranges,
      offsetof(ngx_http_headers_out_t, accept_ranges) },

    { ngx_string("Accept-Ranges"),
      ngx_http_tcache_process_accept_ranges,
      offsetof(ngx_http_headers_out_t, accept_ranges) },

    { ngx_string("Connection"),
      ngx_http_tcache_ignore_header_line,
      0 },

    { ngx_string("Keep-Alive"),
      ngx_http_tcache_ignore_header_line,
      0 },

#if (NGX_HTTP_GZIP)
    { ngx_string("Content-Encoding"),
      ngx_http_tcache_process_content_encoding,
      offsetof(ngx_http_headers_out_t, content_encoding) },
#endif

    { ngx_null_string, NULL, 0 }
};


ngx_int_t
ngx_http_tcache_headers_init(ngx_http_tcache_ctx_t *ctx)
{
    ctx->parse_cache_control = ngx_http_tcache_control;
    ctx->process_headers = ngx_http_tcache_process_status_line;
    ctx->store_headers = ngx_http_tcache_store_headers;

    return NGX_OK;
}


static ngx_uint_t
ngx_http_tcache_control(ngx_list_part_t *part, ngx_array_t *cache_controls,
    time_t *delta)
{
    u_char                          *p, *last;
    time_t                           max_age;
    ngx_uint_t                       i, cache_flag;
    ngx_table_elt_t                 *h, **ccp;

    h = part->elts;
    cache_flag = 0;
    max_age = 0;

    if (cache_controls && cache_controls->nelts) {

        ccp = cache_controls->elts;

        for (i = 0; i < cache_controls->nelts; i++) {

            if (ccp[i]->hash == 0) {
                continue;
            }

            p = ccp[i]->value.data;
            last = p + ccp[i]->value.len;

            if (ngx_strlcasestrn(p, last, (u_char *)"no-cache", 8 - 1) != NULL) {
                cache_flag |= TCACHE_CONTROL_NO_CACHE;
            }

            if (ngx_strlcasestrn(p, last, (u_char *)"no-store", 8 - 1) != NULL) {
                cache_flag |= TCACHE_CONTROL_NO_STORE;
            }

            if (ngx_strlcasestrn(p, last, (u_char *)"private", 7 - 1) != NULL) {
                cache_flag |= TCACHE_CONTROL_PRIVATE;
            }

            if (ngx_strlcasestrn(p, last, (u_char *)"public", 6 - 1) != NULL) {
                cache_flag |= TCACHE_CONTROL_PUBLIC;
            }

            p = ngx_strlcasestrn(p, last, (u_char *) "max-age=", 8 - 1);
            if (p) {
                for (p += 8; p < last; p++) {
                    if (*p < '0' || *p > '9') {
                        break;
                    }

                    if (*p >= '0' && *p <= '9') {
                        max_age = max_age * 10 + (*p - '0');
                        continue;
                    }
                }
            }
        }

        goto end;
    }

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        p = h[i].value.data;
        last = p + h[i].value.len;

        if ((h[i].key.len == sizeof("Cache-Control") - 1)
            && ngx_strncasecmp(h[i].key.data, (u_char *)"Cache-Control",
                               sizeof("Cache-Control") - 1) == 0)
        {
            if (ngx_strlcasestrn(p, last, (u_char *)"no-cache", 8 - 1) != NULL) {
                cache_flag |= TCACHE_CONTROL_NO_CACHE;
            }

            if (ngx_strlcasestrn(p, last, (u_char *)"no-store", 8 - 1) != NULL) {
                cache_flag |= TCACHE_CONTROL_NO_STORE;
            }

            if (ngx_strlcasestrn(p, last, (u_char *)"private", 7 - 1) != NULL) {
                cache_flag |= TCACHE_CONTROL_PRIVATE;
            }

            if (ngx_strlcasestrn(p, last, (u_char *)"public", 6 - 1) != NULL) {
                cache_flag |= TCACHE_CONTROL_PUBLIC;
            }

            continue;

        } else if ((h[i].key.len == sizeof("Pragma") - 1)
                    && ngx_strncasecmp(h[i].key.data, (u_char *)"Pragma",
                                       sizeof("Pragma") - 1) == 0) {

            if (ngx_strlcasestrn(p, last, (u_char *)"no-cache", 8 - 1) != NULL)
            {
                cache_flag |= TCACHE_CONTROL_NO_CACHE;
            }
        }

        p = ngx_strlcasestrn(p, last, (u_char *) "max-age=", 8 - 1);
        if (p) {
            for (p += 8; p < last; p++) {
                if (*p < '0' || *p > '9') {
                    break;
                }

                if (*p >= '0' && *p <= '9') {
                    max_age = max_age * 10 + (*p - '0');
                    continue;
                }
            }
        }

        p = h[i].value.data;
        last = p + h[i].value.len;

        p = ngx_strlcasestrn(p, last, (u_char *) "s-maxage=", 9 - 1);
        if (p) {

            for (p += 9; p < last; p++) {
                if (*p < '0' || *p > '9') {
                    break;
                }

                if (*p >= '0' && *p <= '9') {
                    max_age = max_age * 10 + (*p - '0');
                    continue;
                }
            }
        }
    }

end:

    if (delta) {
        *delta = max_age;
    }

    return cache_flag;
}


static ngx_int_t
ngx_http_tcache_process_status_line(ngx_http_request_t *r, ngx_buf_t *buffer)
{
    size_t                         len;
    ngx_int_t                      rc;
    ngx_http_status_t              status;
    ngx_http_tcache_ctx_t         *ctx;

    ngx_memzero(&status, sizeof(ngx_http_status_t));
    
    rc = ngx_http_parse_status_line(r, buffer, &status);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tcache process an invalid HTTP/1.0 header");
        return rc;
    }

    r->headers_out.status = status.code;
    len = status.end - status.start;
    r->headers_out.status_line.len = len;

    r->headers_out.status_line.data = ngx_pnalloc(r->pool, len);
    if (r->headers_out.status_line.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(r->headers_out.status_line.data, status.start, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "tcache status %ui \"%V\"",
                   r->headers_out.status, &r->headers_out.status_line);

    if (buffer->pos == buffer->last) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_tcache_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->process_headers = ngx_http_tcache_process_headers;

    return ctx->process_headers(r, buffer);
}


static ngx_int_t
ngx_http_tcache_process_headers(ngx_http_request_t *r, ngx_buf_t *buffer)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h, header;
    ngx_http_tcache_header_t       *hh;
    ngx_http_tcache_main_conf_t    *tmcf;

    tmcf = ngx_http_get_module_main_conf(r, ngx_http_tcache_module);

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, buffer, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = &header;

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&tmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh) {
                if (hh->handler(r, h, hh->offset) != NGX_OK) {
                    return NGX_ERROR;
                }

            } else {
                if (ngx_http_tcache_copy_header_line(r, h, 0)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "tcache fetch from cache, header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "tcache parse header done");

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* there was error while a header line parsing */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tcache process an invalid header");

        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho, **ph;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_store_headers(ngx_http_request_t *r, ngx_buf_t *buffer)
{
    size_t                                 len;
    u_char                                *header_start, *body_start;
    ngx_buf_t                             *b;
    ngx_str_t                             *status_line;
    ngx_uint_t                            status, i;
    ngx_list_part_t                      *part;
    ngx_table_elt_t                      *header;
    ngx_http_tcache_loc_conf_t           *conf;
    ngx_http_tcache_content_header_t     *ch;

    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED
            && r->headers_out.status != NGX_HTTP_NO_CONTENT)
        {
            r->headers_out.last_modified_time = -1;
            r->headers_out.last_modified = NULL;
        }
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tcache_module);

    len = sizeof(ngx_http_tcache_content_header_t);

    len += sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
          /* the end of the header */
          + sizeof(CRLF) - 1;

    if (r->headers_out.status_line.len) {
        len += r->headers_out.status_line.len;
        status_line = &r->headers_out.status_line;
        status = 0;

    } else {
        status = r->headers_out.status;

        if (status >= NGX_HTTP_OK
            && status < NGX_HTTP_LAST_2XX)
        {
            /* 2XX */

            status -= NGX_HTTP_OK;
            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_MOVED_PERMANENTLY
                   && status < NGX_HTTP_LAST_3XX)
        {
            /* 3XX */

            status = status - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;
            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_BAD_REQUEST
                   && status < NGX_HTTP_LAST_4XX)
        {
            /* 4XX */
            status = status - NGX_HTTP_BAD_REQUEST
                            + NGX_HTTP_OFF_4XX;

            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_INTERNAL_SERVER_ERROR
                   && status < NGX_HTTP_LAST_5XX)
        {
            /* 5XX */
            status = status - NGX_HTTP_INTERNAL_SERVER_ERROR
                            + NGX_HTTP_OFF_5XX;

            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else {
            len += NGX_INT_T_LEN;
            status_line = NULL;
        }
    }

    if (r->headers_out.content_type.len) {
        len += sizeof("Content-Type: ") - 1
               + r->headers_out.content_type.len + 2;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + 2;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (ngx_hash_find(&conf->hide_headers_hash, header[i].hash,
                          header[i].lowcase_key, header[i].key.len))
        {
            continue;
        }

        len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len
               + sizeof(CRLF) - 1;
    }

    b = buffer;
    
    if ((size_t)(b->end - b->last) < len) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tcache store headers, not enough buffer.",
                      ngx_buf_size(b), len);

        return NGX_ERROR;
    }

    b->last += sizeof(ngx_http_tcache_content_header_t);

    header_start = b->last;

    /* "HTTP/1.x " */
    b->last = ngx_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */
    if (status_line) {
        b->last = ngx_copy(b->last, status_line->data, status_line->len);

    } else {
        b->last = ngx_sprintf(b->last, "%ui", status);
    }
    *b->last++ = CR; *b->last++ = LF;

    if (r->headers_out.content_type.len) {
        b->last = ngx_cpymem(b->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        b->last = ngx_copy(b->last, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = ngx_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = ngx_copy(b->last, r->headers_out.charset.data,
                               r->headers_out.charset.len);
        }

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        b->last = ngx_sprintf(b->last, "Content-Length: %O" CRLF,
                              r->headers_out.content_length_n);
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        b->last = ngx_cpymem(b->last, "Last-Modified: ",
                sizeof("Last-Modified: ") - 1);

        b->last = ngx_http_time(b->last, r->headers_out.last_modified_time);

        *b->last++ = CR; *b->last++ = LF;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (ngx_hash_find(&conf->hide_headers_hash, header[i].hash,
                          header[i].lowcase_key, header[i].key.len))
        {
            continue;
        }

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    /* the end of HTTP header */
    *b->last++ = CR; *b->last++ = LF;

    body_start = b->last;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "tcache store headers \"%*s\"",
                   (size_t)(body_start - header_start),
                   header_start);

    ch = (ngx_http_tcache_content_header_t *) b->pos;
    ch->header_start = header_start - b->pos;
    ch->body_start = body_start - b->pos;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_process_content_type(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char  *p, *last;

    r->headers_out.content_type_len = h->value.len;
    r->headers_out.content_type = h->value;
    r->headers_out.content_type_lowcase = NULL;

    for (p = h->value.data; *p; p++) {

        if (*p != ';') {
            continue;
        }

        last = p;

        while (*++p == ' ') { /* void */ }

        if (*p == '\0') {
            return NGX_OK;
        }

        if (ngx_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
            continue;
        }

        p += 8;

        r->headers_out.content_type_len = last - h->value.data;

        if (*p == '"') {
            p++;
        }

        last = h->value.data + h->value.len;

        if (*(last - 1) == '"') {
            last--;
        }

        r->headers_out.charset.len = last - p;
        r->headers_out.charset.data = p;

        return NGX_OK;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_process_content_length(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.content_length = ho;
    r->headers_out.content_length_n = ngx_atoof(h->value.data, h->value.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_process_last_modified(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.last_modified = ho;

    r->headers_out.last_modified_time = ngx_http_parse_time(h->value.data,
                                                            h->value.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_process_multi_header_lines(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_array_t      *pa;
    ngx_table_elt_t  *ho, **ph;

    pa = (ngx_array_t *) ((char *) &r->headers_out + offset);

    if (pa->elts == NULL) {
        if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ph = ngx_array_push(pa);
    if (ph == NULL) {
        return NGX_ERROR;
    }

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;
    *ph = ho;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_process_accept_ranges(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.accept_ranges = ho;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_process_allow_ranges(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    r->allow_ranges = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_ignore_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_tcache_process_content_encoding(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.content_encoding = ho;

    return NGX_OK;
}


ngx_int_t
ngx_http_tcache_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_tcache_loc_conf_t *conf, ngx_http_tcache_loc_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash)
{
    ngx_str_t       *h;
    ngx_uint_t       i, j;
    ngx_array_t      hide_headers;
    ngx_hash_key_t  *hk;

    if (conf->hide_headers == NGX_CONF_UNSET_PTR
        && conf->pass_headers == NGX_CONF_UNSET_PTR)
    {
        conf->hide_headers_hash = prev->hide_headers_hash;

        if (conf->hide_headers_hash.buckets) {
            return NGX_OK;
        }

        conf->hide_headers = prev->hide_headers;
        conf->pass_headers = prev->pass_headers;

    } else {
        if (conf->hide_headers == NGX_CONF_UNSET_PTR) {
            conf->hide_headers = prev->hide_headers;
        }

        if (conf->pass_headers == NGX_CONF_UNSET_PTR) {
            conf->pass_headers = prev->pass_headers;
        }
    }

    if (ngx_array_init(&hide_headers, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (h = default_hide_headers; h->len; h++) {
        hk = ngx_array_push(&hide_headers);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = *h;
        hk->key_hash = ngx_hash_key_lc(h->data, h->len);
        hk->value = (void *) 1;
    }

    if (conf->hide_headers != NGX_CONF_UNSET_PTR) {

        h = conf->hide_headers->elts;

        for (i = 0; i < conf->hide_headers->nelts; i++) {

            hk = hide_headers.elts;

            for (j = 0; j < hide_headers.nelts; j++) {
                if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    goto exist;
                }
            }

            hk = ngx_array_push(&hide_headers);
            if (hk == NULL) {
                return NGX_ERROR;
            }

            hk->key = h[i];
            hk->key_hash = ngx_hash_key_lc(h[i].data, h[i].len);
            hk->value = (void *) 1;

        exist:

            continue;
        }
    }

    if (conf->pass_headers != NGX_CONF_UNSET_PTR) {

        h = conf->pass_headers->elts;
        hk = hide_headers.elts;

        for (i = 0; i < conf->pass_headers->nelts; i++) {
            for (j = 0; j < hide_headers.nelts; j++) {

                if (hk[j].key.data == NULL) {
                    continue;
                }

                if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    hk[j].key.data = NULL;
                    break;
                }
            }
        }
    }

    hash->hash = &conf->hide_headers_hash;
    hash->key = ngx_hash_key_lc;
    hash->pool = cf->pool;
    hash->temp_pool = NULL;

    return ngx_hash_init(hash, hide_headers.elts, hide_headers.nelts);
}

