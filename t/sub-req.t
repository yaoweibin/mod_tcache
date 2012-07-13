# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(2);

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: simple fetch
--- http_config
    tcache_shm_zone test;
--- config
    location /main {
        echo_location /foo;
        echo_location /foo;
        echo_location /foo;
    }

    location /foo {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("dog")
        ';
    }

--- request
GET /main
--- response_body eval
"dog
dog
dog
"


=== TEST 2: deep nested pure echo_location
--- http_config
    tcache_shm_zone test;
--- config
    location /main {
        echo_location /bar;
        echo_location /bar;
        echo_location /group;
    }

    location /group {
        echo_location /foo;
        echo_location /foo;
    }

    location /foo {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("dog")
        ';
    }

    location /bar {
        tcache test;
        tcache_valid 200    1h;

        add_header TCACHE $tcache_status;

        content_by_lua '
            ngx.say("cat")
        ';
    }


--- request
GET /main
--- response_body eval
"cat
cat
dog
dog
"
