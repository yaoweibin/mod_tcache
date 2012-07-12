# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 4 * blocks();

no_shuffle();

run_tests();

__DATA__

=== TEST 1: basic fetch (cache miss)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;
    }

--- user_files
>>> foo 201103040521.59
hello
--- request
GET /foo
--- response_headers
TCACHE: MISS
Last-Modified: Fri, 04 Mar 2011 05:21:59 GMT
--- response_body
hello


=== TEST 2: basic fetch (cache hit)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: HIT
Last-Modified: Fri, 04 Mar 2011 05:21:59 GMT
--- response_body
hello


=== TEST 3: basic fetch (cache miss), hide Last-Modified
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_valid 200    1h;
        tcache_hide_header  Last-Modified;

        add_header TCACHE $tcache_status;
    }

--- user_files
>>> bar 201103040521.59
hello
--- request
GET /bar
--- response_headers
TCACHE: MISS
Last-Modified: Fri, 04 Mar 2011 05:21:59 GMT
--- response_body
hello


=== TEST 4: basic fetch (cache hit)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /bar
--- response_headers
TCACHE: HIT
Last-Modified: Fri, 04 Mar 2011 05:21:59 GMT
--- response_body
hello
