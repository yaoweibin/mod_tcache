# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * 4 * blocks();

no_shuffle();

run_tests();

__DATA__

=== TEST 1: basic fetch (cache miss), and not stored due to Content-Encoding
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
            ngx.header.content_encoding = "gzip"
            ngx.say("hello")
        ';
    }
--- request
GET /foo
--- response_headers
TCACHE: MISS
Content-Encoding: gzip
--- response_body
hello


=== TEST 2: basic fetch (cache HIT)
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
Content-Encoding: gzip
--- response_body
hello
