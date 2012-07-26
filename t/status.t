# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 3 * blocks() - 3;

no_shuffle();

run_tests();

__DATA__

=== TEST 1: basic fetch (http 1.0)
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
            ngx.say("hello")
        ';
    }
--- request
GET /foo HTTP/1.0
--- response_headers
TCACHE: MISS
--- response_body
hello



=== TEST 2: cache hit
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
--- response_body
hello


=== TEST 3: basic fetch (cache 500 404 200 statuses)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_valid 200 404 500   1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.exit(404)
        ';
    }
--- request
GET /bar HTTP/1.0
--- response_headers
!TCACHE
--- error_code: 404


=== TEST 4: basic fetch (cache 500 404 200 statuses)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_valid 200 404 500   1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /bar HTTP/1.0
--- response_headers
!TCACHE
--- error_code: 404


=== TEST 5: basic fetch (cache 200 500)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /third {
        tcache test;
        tcache_valid 200 500   1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.exit(404)
        ';
    }
--- request
GET /third HTTP/1.0
--- response_headers
!TCACHE
--- error_code: 404


=== TEST 6: basic fetch (cache 200 500)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /third {
        tcache test;
        tcache_valid 200 500   1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /third HTTP/1.0
--- response_headers
TCACHE: MISS
--- response_body
world


=== TEST 7: basic fetch (cache 301 by default)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /forth {
        tcache test;
        tcache_valid 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.redirect("/bah", 301)
        ';
    }
--- request
GET /forth HTTP/1.0
--- response_headers
TCACHE: MISS
--- response_body_like: 301 Moved Permanently
--- error_code: 301


=== TEST 8: basic fetch (cache 301 by default)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /forth {
        tcache test;
        tcache_valid 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /forth HTTP/1.0
--- response_headers
TCACHE: HIT
--- response_body_like: 301 Moved Permanently
--- error_code: 301


=== TEST 9: basic fetch (cache 302 by default)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /fifth {
        tcache test;
        tcache_valid 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.redirect("/bah", 302)
        ';
    }
--- request
GET /fifth HTTP/1.0
--- response_headers
TCACHE: MISS
--- response_body_like: 302 Found 
--- error_code: 302


=== TEST 10: basic fetch (cache 302 by default)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /fifth {
        tcache test;
        tcache_valid 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /fifth HTTP/1.0
--- response_headers
TCACHE: HIT
--- response_body_like: 302 Found 
--- error_code: 302


=== TEST 11: basic fetch (201 not cached by default)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /sixth {
        tcache test;
        tcache_valid 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.status = 201
            ngx.say("Dog created")
        ';
    }
--- request
GET /sixth HTTP/1.0
--- response_headers
!TCACHE
--- response_body
Dog created
--- error_code: 201


=== TEST 12: basic fetch (201 not cached by default)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /sixth {
        tcache test;
        tcache_valid 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /sixth HTTP/1.0
--- response_headers
TCACHE: MISS
--- response_body
world


=== TEST 13: basic fetch (explicitly do not cache 302)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /seventh {
        tcache test;
        tcache_valid 200 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.redirect("/bah", 302)
        ';
    }
--- request
GET /seventh HTTP/1.0
--- response_headers
TCACHE: MISS
--- response_body_like: 302 Found
--- error_code: 302


=== TEST 14: basic fetch (explicitly do not cache 302)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /seventh {
        tcache test;
        tcache_valid 200 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /seventh HTTP/1.0
--- response_headers
TCACHE: MISS
--- response_body
world


=== TEST 15: basic fetch (cache any)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /eighth {
        tcache test;
        tcache_valid any 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.exit("500")
        ';
    }
--- request
GET /eighth HTTP/1.0
--- error_code: 500
--- response_headers
!TCACHE
!FOO

=== TEST 16: basic fetch (cache any, hit)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /eighth {
        tcache test;
        tcache_valid any 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.exit("404")
        ';
    }
--- request
GET /eighth HTTP/1.0
--- error_code: 500
--- response_headers
!TCACHE
!FOO

=== TEST 17: basic fetch (cache any, hit)
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /eighth {
        tcache test;
        tcache_use_stale http_404 http_500;
        tcache_valid any 1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.exit("403")
        ';
    }
--- request
GET /eighth HTTP/1.0
--- error_code: 500
--- response_headers
!TCACHE
!FOO
