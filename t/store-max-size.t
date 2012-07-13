# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * 3 * blocks();

no_shuffle();

run_tests();

__DATA__

=== TEST 1: just hit tcache_store_max_size
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        tcache test;
        tcache_valid 200 1h;
        tcache_store_max_size 67;

        default_type text/plain;
        content_by_lua '
            ngx.say("hello")
        ';

        add_header TCACHE $tcache_status;

    }
--- request
    GET /foo
--- response_headers
TCACHE: MISS
--- response_body
hello

=== TEST 2: just hit tcache_store_max_size
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /foo {
        tcache test;
        tcache_valid 200 1h;
        tcache_store_max_size 67;

        add_header TCACHE $tcache_status;

        default_type text/plain;
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


=== TEST 3: less than tcache_store_max_size
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_valid 200 1h;
        tcache_store_max_size 68;

        default_type text/plain;
        content_by_lua '
            ngx.say("hello")
        ';

        add_header TCACHE $tcache_status;

    }
--- request
    GET /bar
--- response_headers
TCACHE: MISS
--- response_body
hello


=== TEST 4: less then tcache_store_max_size
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /bar {
        tcache test;
        tcache_valid 200 1h;
        tcache_store_max_size 68;

        add_header TCACHE $tcache_status;

        default_type text/plain;
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


=== TEST 5: more than tcache_store_max_size
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /third {
        tcache test;
        tcache_valid 200 1h;
        tcache_store_max_size 66;

        default_type text/plain;
        content_by_lua '
            ngx.say("hello")
        ';

        add_header TCACHE $tcache_status;

    }
--- request
    GET /third
--- response_headers
TCACHE: MISS
--- response_body
hello


=== TEST 6: more than tcache_store_max_size
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /third {
        tcache test;
        tcache_valid 200 1h;
        tcache_store_max_size 66;

        add_header TCACHE $tcache_status;

        default_type text/plain;
        content_by_lua '
            ngx.say("world")
        ';
    }
--- request
    GET /third
--- response_headers
TCACHE: MISS
--- response_body
world
