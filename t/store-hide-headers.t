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

        content_by_lua '
            ngx.header["Foo-Bar"] = "hi world"
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
Foo-Bar: hi world
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
Foo-Bar: hi world
--- response_body
hello


=== TEST 3: basic fetch (cache miss, hide the Foo-Bar header)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_valid 200    1h;
        tcache_hide_header  Foo-Bar;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header["Foo-Bar"] = "hi world"
            ngx.say("hello")
        ';
    }
--- request
GET /bar
--- response_headers
TCACHE: MISS
Foo-Bar: hi world
--- response_body
hello


=== TEST 4: basic fetch (cache hit, hide the Foo-Bar header)
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
!Foo-Bar
--- response_body
hello


=== TEST 5: basic fetch (hide Content-Type in store)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /third {
        tcache test;
        tcache_valid 200    1h;
        tcache_hide_header  Content-Type;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header["Content-Type"] = "text/plain"
            ngx.header["Foo-Bar"] = "hi world"
            ngx.say("hello")
        ';
    }
--- request
GET /third
--- response_headers
TCACHE: MISS
Foo-Bar: hi world
Content-Type: text/plain


=== TEST 6: basic fetch (hide Content-Type in store, skip)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /third {
        tcache test;
        tcache_valid 200    1h;
        tcache_hide_header  Content-Type;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header["Content-Type"] = "text/plain"
            ngx.header["Foo-Bar"] = "hi world"
            ngx.say("hello")
        ';
    }
--- request
GET /third
--- response_headers
TCACHE: HIT
Foo-Bar: hi world
Content-Type: text/plain


=== TEST 6: basic fetch (hide Content-Type in store, skip)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /third {
        tcache test;
        tcache_valid 200    1h;
        tcache_hide_header  Content-Type;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.header["Content-Type"] = "text/plain"
            ngx.header["Foo-Bar"] = "hi world"
            ngx.say("hello")
        ';
    }
--- request
GET /third
--- response_headers
TCACHE: HIT
Foo-Bar: hi world
Content-Type: text/plain
