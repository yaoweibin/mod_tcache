# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * (4 * blocks());

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

#master_on();
no_shuffle();

run_tests();

__DATA__


=== TEST 1: basic fetch (Proxy-Authenticate hide by default)
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
            ngx.header["Set-Cookie"] = "foo=baz"
            ngx.header["Proxy-Authenticate"] = "blah"
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
Proxy-Authenticate: blah
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
--- response_body
hello


=== TEST 3: basic fetch (Proxy-Authenticate pass)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_valid 200    1h;
        tcache_pass_header Proxy-Authenticate;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header["Proxy-Authenticate"] = "blah"
            ngx.say("hello")
        ';
    }
--- request
GET /bar
--- response_headers
TCACHE: MISS
Proxy-Authenticate: blah
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
Proxy-Authenticate: blah
--- response_body
hello
