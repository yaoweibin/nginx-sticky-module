
/*
 * Copyright (C) 2010 Jerome Loyet (jerome at loyet dot net)
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>

#include "ngx_http_sticky_misc.h"

ngx_int_t ngx_http_sticky_misc_set_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value, ngx_str_t *domain, ngx_str_t *path, time_t expires)
{
	u_char  *cookie, *p;
	size_t  len;
	ngx_table_elt_t *set_cookie, *elt;
	ngx_str_t remove;
	ngx_list_part_t *part;
	ngx_uint_t i;

	if (value == NULL) {
		remove.len = sizeof("_remove_") - 1;
		remove.data = (u_char *)"_remove_";
		value = &remove;
	}


	/*    name        =   value */
	len = name->len + 1 + value->len;

	/*; Domain= */
	if (domain->len > 0) {
		len += sizeof("; Domain=") - 1 + domain->len;
	}

	/*; Max-Age= */
	if (expires > NGX_CONF_UNSET) {
		len += sizeof("; Max-Age=") - 1 + sizeof("1275396350") - 1;
	}

	/* ; Path= */
	if (path->len > 0) {
		len += sizeof("; Path=") - 1 + path->len;
	}

	cookie = ngx_pnalloc(r->pool, len + 1);	
	if (cookie == NULL) {
		return NGX_ERROR;
	}

	p = ngx_copy(cookie, name->data, name->len);
	*p++ = '=';
	p = ngx_copy(p, value->data, value->len);

	if (domain->len > 0) {
		p = ngx_copy(p, "; Domain=", sizeof("; Domain=") - 1);	
		p = ngx_copy(p, domain->data, domain->len);
	}

	if (expires > NGX_CONF_UNSET) {
		p = ngx_copy(p, "; Max-Age=", sizeof("; Max_Age=") - 1);
		p = ngx_snprintf(p, sizeof("1275396350") - 1, "%T", expires);
	}

	if (path->len > 0) {
		p = ngx_copy(p, "; Path=", sizeof("; Path=") - 1);	
		p = ngx_copy(p, path->data, path->len);
	}

	part = &r->headers_out.headers.part;
	elt = (ngx_table_elt_t *)part->elts;
	set_cookie = NULL;

	for (i=0 ;; i++) {
		if (part->nelts > 1 || i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}
			part = part->next;
			elt = (ngx_table_elt_t *)part->elts;
			i = 0;
		}
		// ... //
		if (ngx_strncmp(elt->value.data, name->data, name->len) == 0) {
			set_cookie = elt;
			break;
		}
	}

	if (set_cookie != NULL) { // found a Set-Cookie header with the same name: replace it
		set_cookie->value.len = p - cookie;
		set_cookie->value.data = cookie;
		return NGX_OK;
	}

	set_cookie = ngx_list_push(&r->headers_out.headers);
	if (set_cookie == NULL) {
		return NGX_ERROR;
	}
	set_cookie->hash = 1;
	set_cookie->key.len = sizeof("Set-Cookie") - 1;
	set_cookie->key.data = (u_char *) "Set-Cookie";
	set_cookie->value.len = p - cookie;
	set_cookie->value.data = cookie;

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_md5(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest)
{
	ngx_md5_t md5;
	u_char hash[MD5_DIGEST_LENGTH + 1];

	digest->data = ngx_pcalloc(pool, (MD5_DIGEST_LENGTH * 2) + 1);
	if (digest->data == NULL) {
		return NGX_ERROR;
	}

	digest->len = MD5_DIGEST_LENGTH * 2;
	ngx_md5_init(&md5);
	ngx_md5_update(&md5, in, len);
	ngx_md5_final(hash, &md5);

	ngx_hex_dump(digest->data, hash, MD5_DIGEST_LENGTH);
	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_sha1(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest)
{
	ngx_sha1_t sha1;
	u_char hash[SHA_DIGEST_LENGTH + 1];

	digest->data = ngx_pcalloc(pool, (SHA_DIGEST_LENGTH * 2) + 1);
	if (digest->data == NULL) {
		return NGX_ERROR;
	}

	digest->len = SHA_DIGEST_LENGTH * 2;
	ngx_sha1_init(&sha1);
	ngx_sha1_update(&sha1, in, len);
	ngx_sha1_final(hash, &sha1);

	ngx_hex_dump(digest->data, hash, SHA_DIGEST_LENGTH);
	return NGX_OK;
}
