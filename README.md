# Name #

**ngx\_http\_tcache\_module**

add the support memory cache in Nginx

# Examples #

	http {
        tcache_shm_zone box size=256M;

        server {
            tcache box;
            tcache_valid 200 1h;

            proxy_pass http://www.example.com;
        }
	}

# Directives #

## tcache ##


Syntax: **tcache_shm_zone** `name [size=memory_size]`

Default: `none`

Context: `http, server, location`

Specify the shared memory name and it's size. If you don't set the size, the default the memory size is 256M byte.


Syntax: **tcache** `shm_zone_name`

Default: `none`

Context: `http, server, location`

Turn on this tcache module. It will store and fetch the HTTP response to and from the shared memory.


Syntax: **tcache_key** `key_string`

Default: `$scheme$host$request_uri`

Context: `http, server, location`

The key mapping to the cache file. 


Syntax: **tcache_valid** `[status codes] time`

Default: `none`

Context: `http, server, location`

Sets caching time for different response codes. For example, the following directives

    tcache_valid 200 302 10m;
    tcache_valid 404      1m;
    set 10 minutes of caching for responses with codes 200 and 302, and 1 minute for responses with code 404.

If only caching time is specified

    tcache_valid 5m;

then only 200, 301, and 302 responses are cached.

In addition, it can be specified to cache any responses using the any parameter:

    tcache_valid 200 302 10m;
    tcache_valid 301      1h;
    tcache_valid any      1m;


Syntax: **tcache_bypass** `variable ...`

Default: `none`

Context: `http, server, location`

Defines conditions under which the response will not be taken from a cache. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be taken from the cache:

    tcache_bypass $cookie_nocache $arg_nocache$arg_comment;
    tcache_bypass $http_pragma    $http_authorization;


Syntax: **tcache_no_cache** `variable ...`

Default: `none`

Context: `http, server, location`

Defines conditions under which the response will not be saved to a cache. If at least one value of the string parameters is not empty and is not equal to “0” then the response will not be saved:

    tcache_no_cache $cookie_nocache $arg_nocache$arg_comment;
    tcache_no_cache $http_pragma    $http_authorization;


Syntax: **tcache_methods** `methods`

Default: `GET HEAD`

Context: `http, server, location`

This directive specifies the HTTP request methods are allowed to use the cache, otherwise, the request will be bypassed and not fetch the cache.

The following HTTP methods are allowed: GET, HEAD, POST, PUT, and DELETE. The GET and HEAD methods are always implicitly included in the list regardless of their presence in this directive.


Syntax: **tcache_expires** `time`

Default: `60s`

Context: `http, server, location`

Specify the expires time for the cache record. This module will be marked to be expires. And the request will try to fetch a newer version content from origin server.


Syntax: **tcache_grace** `time`

Default: `120s`

Context: `http, server, location`

Specify the grace time for the cache record. It should be larger than the expires time. This module will still keep the record in the grace time while it already expire.


Syntax: **tcache_use_stale** `updating | http_500 | http_502 | http_503 | http_504 | http_404 | off`

Default: `off`

Context: `http, server, location`

If an error occurs while working with the proxied server it is possible to use a stale cached response. This directives determines in which cases it is permitted. The directive’s parameters match the response status code.

Additionally, the updating parameter permits to use a stale cached response if it is currently being updated. This allows to minimize the number of accesses to proxied servers when updating cached data.


Syntax: **tcache_hide_header** `header_name`

Default: `none`

Context: `http, server, location`

By default, this module caches all the response headers except the following ones:

    Connection
    Keep-Alive
    Proxy-Authenticate
    Proxy-Authorization
    TE
    Trailers
    Transfer-Encoding
    Upgrade

You can hide more response headers (case-insensitive) by means of this directive. For examples,

    tcache_hide_header X-Foo;
    tcache_hide_header Last-Modified;

Multiple occurrences of this directive are allowed in a single location.


Syntax: **tcache_pass_header** `header_name`

Default: `none`

Context: `http, server, location`

You can force this module to store one or more response headers (case-insensitive) by means of this directive. For examples,

    tcache_store_pass_header Set-Cookie;
    tcache_store_pass_header Proxy-Authenticate;

Multiple occurrences of this directive are allowed in a single location.


Syntax: **tcache_store_max_size** `size`

Default: `1M`

Context: `http, server, location`

Specify the maximum size of the cached response. If it's large than this size, the response will not be cached.


Syntax: **tcache_store_buffer_size** `size`

Default: `128K`

Context: `http, server, location`

This module will preallocate an fixed size buffer for storing the response. After it fetches all the response content, this buffer will be copied to the shared memory.
