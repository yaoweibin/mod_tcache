# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * 3 * blocks();

#master_on();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: basic fetch (cache miss), first time
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
GET /foo
--- response_headers
TCACHE: MISS
--- response_body
hello

=== TEST 2: basic fetch (cache miss), bypass true
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        set $testpass "1";

        tcache test;
        tcache_valid 200    1h;
        tcache_bypass $testpass;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: BYPASS
--- response_body
world


=== TEST 3: basic fetch (cache hit), bypass false
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        set $testpass "0";

        tcache test;
        tcache_valid 200    1h;
        tcache_bypass $testpass;

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
