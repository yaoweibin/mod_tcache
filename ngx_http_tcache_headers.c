

#include "ngx_http_tcache_headers.h"


static ngx_int_t ngx_http_tcache_process_status_line(ngx_http_request_t *r,
    ngx_buf_t *buffer);
static ngx_int_t ngx_http_tcache_process_headers(ngx_http_request_t *r,
    ngx_buf_t *buffer);
static ngx_int_t ngx_http_tcache_copy_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_tcache_store_headers(ngx_http_request_t *r,
    ngx_chain_t **chain);

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
    ctx->process_headers = ngx_http_tcache_process_status_line;
    ctx->store_headers = ngx_http_tcache_store_headers;

    return NGX_OK;
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

            h = ngx_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = 1;
            ngx_str_set(&h->key, "TCACHE");
            ngx_str_set(&h->value, "HIT");
            h->lowcase_key = (u_char *) "tcache";

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
ngx_http_tcache_store_headers(ngx_http_request_t *r, ngx_chain_t **chain)
{
    size_t                                 len;
    ngx_buf_t                             *b, *sb;
    ngx_str_t                             *status_line;
    ngx_uint_t                            status, i;
    ngx_chain_t                          *cl;
    ngx_list_part_t                      *part;
    ngx_table_elt_t                      *header;
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

    len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
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

        /* TODO: hide headers */

        len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len
               + sizeof(CRLF) - 1;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

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

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    /* the end of HTTP header */
    *b->last++ = CR; *b->last++ = LF;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "tcache store headers \"%*s\"", (size_t) (b->last - b->pos),
                   b->pos);

    sb = ngx_create_temp_buf(r->pool, sizeof(ngx_http_tcache_content_header_t));
    if (sb == NULL) {
        return NGX_ERROR;
    }

    ch = (ngx_http_tcache_content_header_t *) sb->pos;
    ch->header_start = sizeof(ngx_http_tcache_content_header_t);
    ch->body_start = ch->header_start + ngx_buf_size(b);

    sb->last = sb->pos + ch->header_start ;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = sb;
    cl->next = NULL;

    *chain = cl;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    (*chain)->next = cl;

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

