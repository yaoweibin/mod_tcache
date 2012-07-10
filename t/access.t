# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * 2 * blocks();

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: fetch, allow
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
GET /
--- response_body_like: ^<.+>$

=== TEST 2: fetch deny
--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test;
        tcache_valid 200    1h;

        deny all;

        add_header TCACHE $tcache_status;

        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
GET /
--- response_body_like: 403 Forbidden
--- error_code: 403
