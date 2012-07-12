# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * 2 * blocks();

no_shuffle();

run_tests();

__DATA__

=== TEST 1: basic fetch
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location @err {
        content_by_lua '
            ngx.say("err")
        ';
    }

    location /foo {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.exit(404)
        ';
        error_page 404 = @err;
    }

--- request
GET /foo
--- response_body
err



=== TEST 2: fetch again
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location @err {
        content_by_lua '
            ngx.say("hello")
        ';
    }

    location /foo {
        tcache test;
        tcache_valid 200 404  1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.exit(404)
        ';
        error_page 404 = @err;
    }

--- request
GET /foo
--- response_body
hello
