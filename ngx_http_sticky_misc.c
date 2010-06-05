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

ngx_int_t ngx_http_sticky_misc_remove_set_cookies(ngx_http_request_t *r, ngx_str_t *cookie_name)
{
	ngx_list_part_t *part;
	ngx_uint_t i;
	ngx_table_elt_t *elt;

	part = &r->headers_out.headers.part;
	elt = (ngx_table_elt_t *)part->elts;

	for (i=0 ;; i++) {
		if (part->nelts > 1 || i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}
			part = part->next;
			elt = (ngx_table_elt_t *)part->elts;
			i = 0;
		}
		if (ngx_strncmp(elt->key.data, cookie_name->data, cookie_name->len) == 0) {
			part->nelts = 0;
		}
	}

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_hmac_md5(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *message, ngx_str_t *digest)
{
	u_char hash[MD5_DIGEST_LENGTH + 1];
	u_char k[MD5_CBLOCK];
	ngx_md5_t md5;
	u_int i;

	digest->data = ngx_pcalloc(r->pool, (MD5_DIGEST_LENGTH * 2) + 1);
	if (digest->data == NULL) {
		return NGX_ERROR;
	}
	digest->len = MD5_DIGEST_LENGTH * 2;

	ngx_memzero(k, sizeof(k));

	if (key->len > MD5_CBLOCK) {
		ngx_md5_init(&md5);
		ngx_md5_update(&md5, key->data, key->len);
		ngx_md5_final(k, &md5);
	} else {
		ngx_memcpy(k, key->data, key->len);
	}

	/* XOR ipad */
	for (i=0; i < MD5_CBLOCK; i++) {
		k[i] ^= 0x36;
	}

	ngx_md5_init(&md5);
	ngx_md5_update(&md5, k, MD5_CBLOCK);
	ngx_md5_update(&md5, message->data, message->len);
	ngx_md5_final(hash, &md5);

	/* Convert k to opad -- 0x6A = 0x36 ^ 0x5C */
	for (i=0; i < MD5_CBLOCK; i++) {
		k[i] ^= 0x6a;
	}

	ngx_md5_init(&md5);
	ngx_md5_update(&md5, k, MD5_CBLOCK);
	ngx_md5_update(&md5, hash, MD5_DIGEST_LENGTH);
	ngx_md5_final(hash, &md5);

	ngx_hex_dump(digest->data, hash, MD5_DIGEST_LENGTH);

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_generate_uid(ngx_http_request_t *r, uint32_t start_value, uint32_t *sequencer, ngx_str_t *uid)
{
	ngx_md5_t md5;
	uint32_t v1 = (uint32_t) ngx_time();
	uint32_t v2 = start_value;
	uint32_t v3 = *sequencer;
	ngx_uint_t i;
	ngx_list_part_t *part;
	ngx_table_elt_t *header;
	u_char hash[MD5_DIGEST_LENGTH + 1];

	uid->data = ngx_pcalloc(r->pool, (MD5_DIGEST_LENGTH * 2) + 1);
	if (uid->data == NULL) {
		return NGX_ERROR;
	}
	uid->len = MD5_DIGEST_LENGTH * 2;

	*sequencer += 0x100;

	ngx_md5_init(&md5);
	ngx_md5_update(&md5, &v1, sizeof(v1));
	ngx_md5_update(&md5, &v2, sizeof(v2));
	ngx_md5_update(&md5, &v3, sizeof(v3));

	part = &r->headers_in.headers.part;
	header = part->elts;

	for (i=0; /* void */; i++) {
		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}
			part = part->next;
			header = part->elts;
			i = 0;
		}

		ngx_md5_update(&md5, header[i].value.data, header[i].value.len);
	}
	ngx_md5_final(hash, &md5);

	ngx_hex_dump(uid->data, hash, MD5_DIGEST_LENGTH);
	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_redirect(ngx_http_request_t *r, ngx_str_t *url)
{
	ngx_table_elt_t *location;

	location = ngx_list_push(&r->headers_out.headers);
	if (location == NULL) {
		return(NGX_ERROR);
	}

	location->hash = 1;
	location->key.len = sizeof("Location") - 1;
	location->key.data = (u_char *) "Location";
	location->value = *url;

	r->headers_out.location = location;

	return NGX_HTTP_MOVED_TEMPORARILY;
}

ngx_int_t ngx_http_sticky_misc_get_var(ngx_http_request_t *r, u_char *name, ngx_str_t *value)
{
	ngx_http_variable_value_t *t;
	ngx_int_t key;
	ngx_str_t hash, n;

	n.len = ngx_strlen(name);
	n.data = name;

	hash.len = n.len;
	hash.data = ngx_pnalloc(r->pool, n.len + 1);
	if (hash.data == NULL) {
		return NGX_ERROR;
	}

	value->len = 0;
	value->data = (u_char *)"";

	key = ngx_hash_strlow(hash.data, n.data, n.len);
	t = ngx_http_get_variable(r, &n, key);

	value->len = t->len;
	value->data = t->data;

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_forge_url(ngx_http_request_t *r, ngx_str_t *url, ngx_int_t base64)
{
	ngx_str_t scheme, host;

	ngx_http_sticky_misc_get_var(r, (u_char *)"scheme", &scheme);
	ngx_http_sticky_misc_get_var(r, (u_char *)"host", &host);

	url->len = scheme.len + (sizeof("://") - 1) + host.len + r->unparsed_uri.len;
	url->data = ngx_pnalloc(r->pool, url->len + 1);
	if (url->data == NULL) {
		return NGX_ERROR;
	}

	ngx_snprintf(url->data, url->len, "%V://%V%V", &scheme, &host, &r->unparsed_uri);

	if (base64) {
		ngx_str_t url64;

		url64.len = ngx_base64_encoded_length(url->len);
		url64.data = ngx_pnalloc(r->pool, url64.len + 1);
		if (url64.data == NULL) {
			return NGX_ERROR;
		}
		ngx_encode_base64(&url64, url);
		url->len = url64.len;
		url->data = url64.data;
	}

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_decode_base64(ngx_http_request_t *r, ngx_str_t *in, ngx_str_t *out)
{
	out->len = ngx_base64_decoded_length(in->len);
	out->data = ngx_pnalloc(r->pool, out->len + 1);
	if (out->data == NULL) {
		return NGX_ERROR;
	}

	if (ngx_decode_base64(out, in) == NGX_ERROR) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_split_str(ngx_str_t *in, u_char *start, ngx_str_t *out) 
{
	size_t start_len = ngx_strlen(start);

	if (in->len <= start_len) {
		return NGX_ERROR;
	}

	if ((u_char *)ngx_strstr(in->data, start) != in->data) {
		return NGX_ERROR;
	}

	out->len  = in->len - start_len;
	out->data = (u_char *)(in->data + start_len);
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
