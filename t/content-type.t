# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * (5 * blocks());

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

no_shuffle();

run_tests();

__DATA__

=== TEST 1: basic fetch (Set-Cookie and Proxy-Authenticate hide by default)
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
            ngx.header.content_type = "text/plain"
            ngx.header.proxy_authenticate = "test"
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
Proxy-Authenticate: test
Content-Type: text/plain
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
!Proxy-Authenticate
Content-Type: text/plain
--- response_body
hello
