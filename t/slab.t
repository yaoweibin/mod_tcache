# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();
no_root_location();
no_shuffle();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the basic tcache module, first

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
--- response_headers
TCACHE: MISS

=== TEST 2: the basic tcache module, second

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
--- response_headers
TCACHE: HIT 

=== TEST 3: the tcache module, slab, with manager process
--- main_config

processes {
    process tcache_manager {
        tcache_manager test;
        delay_start 300ms;
        listen 1982;
    }
}

--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test;
        tcache_valid 200    1s;

        add_header TCACHE $tcache_status;

        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_headers
TCACHE: HIT

=== TEST 4: the tcache module, slab, with manager process
--- main_config

processes {
    process tcache_manager {
        tcache_manager test;
        tcache_manager_interval 3s;

        delay_start 300ms;
        listen 1982;
    }
}

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
--- response_headers
TCACHE: HIT

=== TEST 5: the tcache module, slab, GET 
--- main_config

processes {
    process tcache_manager {
        tcache_manager test;
        tcache_manager_interval 3s;

        delay_start 300ms;
        listen 1982;
    }
}

--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test;
        tcache_methods GET;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_headers
TCACHE: HIT

=== TEST 6: the tcache module, slab, POST 
--- main_config

processes {
    process tcache_manager {
        tcache_manager test;
        tcache_manager_interval 3s;

        delay_start 300ms;
        listen 1982;
    }
}

--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        tcache test;
        tcache_methods GET;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    POST /
--- response_headers
TCACHE: BYPASS

=== TEST 7: the tcache module, slab, bypass 
--- main_config

processes {
    process tcache_manager {
        tcache_manager test;
        tcache_manager_interval 3s;

        delay_start 300ms;
        listen 1982;
    }
}

--- http_config
    tcache_shm_zone test;

    upstream backends {
        server www.taobao.com;
    }

--- config
    location / {
        set $testpass "1";

        tcache test;
        tcache_valid 200 1h;
        tcache_bypass $testpass;

        add_header TCACHE $tcache_status;

        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_headers
TCACHE: BYPASS
