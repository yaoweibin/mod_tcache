# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 3 * blocks();

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
        tcache_key abcd;
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
--- response_body
hello


=== TEST 2: basic fetch (cache hit), fixed key
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_key abcd;
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
--- response_body
hello


=== TEST 3: basic fetch (cache miss)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /uri {
        tcache test;
        tcache_key $uri;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("nihao")
        ';
    }

--- request
GET /uri
--- response_headers
TCACHE: MISS
--- response_body
nihao


=== TEST 4: basic fetch (cache hit)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /uri {
        tcache test;
        tcache_key $uri;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /uri?a=b&c=e
--- response_headers
TCACHE: HIT
--- response_body
nihao
