# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(100);

plan tests => repeat_each() * (3 * blocks());

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: cache miss
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test;
        tcache_valid 200    1h;

        root html;

        index index.html index.htm;

        add_header TCACHE $tcache_status;
    }
--- request
GET /
--- response_headers
TCACHE: MISS
--- response_body_like: It works!


=== TEST 2: cache hit
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test;
        tcache_valid 200    1h;

        root html;

        index index.html index.htm;

        add_header TCACHE $tcache_status;
    }
--- request
GET /
--- response_headers
TCACHE: HIT
--- response_body_like: It works!

