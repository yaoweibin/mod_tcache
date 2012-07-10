# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * 3 * blocks();

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

#master_on();
no_shuffle();

run_tests();

__DATA__


=== TEST 1: basic fetch (cache miss but stored)
--- http_config
    tcache_shm_zone test;

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("yahoo")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
--- response_body
yahoo


=== TEST 2: basic fetch (cache hit, stored in the previous case)
--- http_config
    tcache_shm_zone test;

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
--- response_body
yahoo


=== TEST 3: basic fetch (cache miss), and not stored due to Cache-Control: no-cache
--- http_config
    tcache_shm_zone test;

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE   $tcache_status;

        content_by_lua '
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- more_headers
Cache-control: no-cache
--- response_headers
TCACHE: BYPASS
--- response_body
hello


=== TEST 4: basic fetch (cache miss), and not stored due to Cache-Control: no-cache and no-store
--- http_config
    tcache_shm_zone test;

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
--- more_headers
Cache-control: no-cache
Cache-control: no-store
--- response_headers
TCACHE: BYPASS
--- response_body
world


=== TEST 5: basic fetch (cache miss), and not stored due to Pragma: no-cache
--- http_config
    tcache_shm_zone test;

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("hello")
        ';
    }
--- more_headers
Pragma: no-cache
--- request
GET /foo
--- response_headers
TCACHE: BYPASS
--- response_body
hello


=== TEST 6: basic fetch (cache hit, stored in the previous case)
--- http_config
    tcache_shm_zone test;

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
--- response_body
yahoo
