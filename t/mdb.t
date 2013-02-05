# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();
no_root_location();
no_shuffle();

#no_diff;

run_tests();

__DATA__

=== TEST 1: tcache module with mdb first time

--- http_config
    tcache_shm_zone test_mdb storage=mdb size=256M;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test_mdb;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_headers
TCACHE: MISS

=== TEST 2: tcache module with mdb second time

--- http_config
    tcache_shm_zone test_mdb storage=mdb size=256M;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test_mdb;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_headers
TCACHE: HIT
