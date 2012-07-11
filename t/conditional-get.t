# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(100);

plan tests => repeat_each() * 4 * blocks();

no_shuffle();

run_tests();

__DATA__

=== TEST 1: cache miss
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header.last_modified = "Thu, 10 May 2012 07:50:59 GMT"
            ngx.say("hello")
        ';
    }
--- request
GET /cats
--- response_headers
TCACHE: MISS
Last-Modified: Thu, 10 May 2012 07:50:59 GMT
--- response_body
hello


=== TEST 2: cache hit
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /cats
--- response_headers
TCACHE: HIT
Last-Modified: Thu, 10 May 2012 07:50:59 GMT
--- response_body
hello


=== TEST 3: cache hit (I-M-S conditional GET, exactly)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /cats
--- more_headers
If-Modified-Since: Thu, 10 May 2012 07:50:59 GMT
--- response_headers
TCACHE: HIT
Last-Modified: Thu, 10 May 2012 07:50:59 GMT
--- error_code: 304
--- response_body


=== TEST 4: cache hit (I-M-S conditional GET, exact failed)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /cats
--- more_headers
If-Modified-Since: Thu, 10 May 2012 07:51:00 GMT
--- response_headers
TCACHE: HIT
Last-Modified: Thu, 10 May 2012 07:50:59 GMT
--- response_body
hello


=== TEST 5: cache hit (I-M-S conditional GET, exact failed, before suceeded)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        if_modified_since before;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /cats
--- more_headers
If-Modified-Since: Thu, 10 May 2012 07:51:00 GMT
--- response_headers
TCACHE: HIT
Last-Modified: Thu, 10 May 2012 07:50:59 GMT
--- response_body
--- error_code: 304



=== TEST 6: cache hit (I-U-S conditional GET, 412)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /cats
--- more_headers
If-Unmodified-Since: Thu, 10 May 2012 07:50:58 GMT
--- response_headers
!TCACHE
!Last-Modified
--- response_body_like: 412 Precondition Failed
--- error_code: 412



=== TEST 7: cache hit (I-U-S conditional GET, precondition succeeded)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /cats
--- more_headers
If-Unmodified-Since: Thu, 10 May 2012 07:50:59 GMT
--- response_headers
TCACHE: HIT
Last-Modified: Thu, 10 May 2012 07:50:59 GMT
--- response_body
hello



=== TEST 8: cache hit (I-U-S conditional GET, precondition succeeded, newer)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /cats
--- more_headers
If-Unmodified-Since: Thu, 10 May 2012 07:51:00 GMT
--- response_headers
TCACHE: HIT
Last-Modified: Thu, 10 May 2012 07:50:59 GMT
--- response_body
hello
