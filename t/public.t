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


=== TEST 1: basic fetch (cache miss), and stored due to Cache-Control: public
--- http_config
    tcache_shm_zone test;

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header.cache_control = "public"
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
--- response_body
hello


=== TEST 2: basic fetch (cache hit, stored in the previous case)
--- http_config
    tcache_shm_zone test;

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header.cache_control = "private"
            ngx.say("world")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: HIT
--- response_body
hello


=== TEST 3: basic fetch (cache miss)
--- http_config
    tcache_shm_zone test;

--- config
    location /bar {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header.cache_control = { "blah", "blah; public" }
            ngx.say("yahoo")
        ';
    }
--- request
GET /bar
--- response_headers
TCACHE: MISS
--- response_body
yahoo


=== TEST 4: basic fetch (cache miss again, not stored in the previous case)
--- http_config
    tcache_shm_zone test;

--- config
    location /bar {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header.cache_control = "private"
            ngx.say("world")
        ';
    }
--- request
GET /bar
--- response_headers
TCACHE: HIT
--- response_body
yahoo
