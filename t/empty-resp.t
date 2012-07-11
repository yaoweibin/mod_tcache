# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(100);

plan tests => repeat_each() * (3 * blocks());

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
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        echo -n '';
    }
--- request
GET /cats
--- response_headers
TCACHE: MISS
--- response_body:



=== TEST 2: cache hit
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location /cats {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("hello")
        ';
    }
--- request
GET /cats
--- response_headers
TCACHE: HIT
Content-length: 0
