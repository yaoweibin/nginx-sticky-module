
/*
 * Copyright (C) 2010 Jerome Loyet (jerome at loyet dot net)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef ngx_int_t (*ngx_http_sticky_misc_hash_pt)(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest);

ngx_int_t ngx_http_sticky_misc_set_cookie (ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value, ngx_str_t *domain, ngx_str_t *path, time_t expires);
ngx_int_t ngx_http_sticky_misc_md5(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest);
ngx_int_t ngx_http_sticky_misc_sha1(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest);
