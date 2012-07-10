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


=== TEST 1: basic fetch (cache miss), and not stored due to Cache-Control: private.t
--- http_config
    tcache_shm_zone test;

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header.cache_control = "private"
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
--- response_body
hello


=== TEST 2: basic fetch (cache miss again, not stored in the previous case)
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
TCACHE: MISS
--- response_body
world


=== TEST 3: basic fetch (cache miss), and not stored due to Cache-Control: private
--- http_config
    tcache_shm_zone test;

--- config
    location /foo {
        tcache test;
        tcache_valid 200    1h;
        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header.cache_control = { "blah", "blah; private" }
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
--- response_body
hello


=== TEST 4: basic fetch (cache miss again, not stored in the previous case)
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
TCACHE: MISS
--- response_body
world
