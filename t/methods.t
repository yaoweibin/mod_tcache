# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

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
        tcache_methods GET;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
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
        tcache_methods GET;
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
hello


=== TEST 3: basic fetch (POST cache miss for POST by default)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        tcache test;
        tcache_methods GET;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
POST /foo
hiya, china
--- response_headers
TCACHE: BYPASS
--- response_body
world


=== TEST 4: basic fetch (POST cache hit if we enable POST explicitly)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        tcache test;
        tcache_methods POST;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
POST /foo
hiya, china
--- response_headers
TCACHE: HIT
--- response_body
hello


=== TEST 5: basic fetch (GET still cache hit if we enable POST  and PUT explicitly)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        tcache test;
        tcache_methods POST PUT;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
POST /foo
hiya, china
--- response_headers
TCACHE: HIT
--- response_body
hello


=== TEST 6: basic fetch (HEAD still cache hit if we enable POST explicitly)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        tcache test;
        tcache_methods POST PUT;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
HEAD /foo
--- response_headers
Content-Length: 6
--- response_body


=== TEST 7: basic fetch (cache miss), POST stored when POST is enabled in tcache_methods
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_methods POST PUT;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
POST /bar
--- response_headers
TCACHE: MISS
--- response_body
world


=== TEST 8: basic fetch (cache hit)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_methods POST PUT;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("haha")
        ';
    }
--- request
GET /bar
--- response_headers
TCACHE: HIT
--- response_body
world
