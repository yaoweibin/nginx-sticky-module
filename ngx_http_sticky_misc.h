#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#define NGX_XTOKEN_HASH_LENGTH (MD5_DIGEST_LENGTH * 2)

ngx_int_t ngx_http_sticky_misc_set_cookie (ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value, ngx_str_t *domain, ngx_str_t *path, time_t expires);
ngx_int_t ngx_http_sticky_misc_hmac_md5(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *message, ngx_str_t *digest);
ngx_int_t ngx_http_sticky_misc_generate_uid(ngx_http_request_t *r, uint32_t start_value, uint32_t *sequencer, ngx_str_t *uid);
ngx_int_t ngx_http_sticky_misc_redirect(ngx_http_request_t *r, ngx_str_t *location);
ngx_int_t ngx_http_sticky_misc_get_var(ngx_http_request_t *r, u_char *name, ngx_str_t *value);
ngx_int_t ngx_http_sticky_misc_forge_url(ngx_http_request_t *r, ngx_str_t *url, ngx_int_t base64);
ngx_int_t ngx_http_sticky_misc_decode_base64(ngx_http_request_t *r, ngx_str_t *in, ngx_str_t *out);
