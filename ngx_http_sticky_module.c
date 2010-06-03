
/*
 * Copyright (C) Igor Sysoev
 */

#include "ngx_http_sticky_misc.h"

typedef struct {
	ngx_flag_t enable;
	ngx_str_t  cookie_name;
	ngx_str_t  cookie_domain;
	ngx_str_t  cookie_path;
	time_t     cookie_expires;
} ngx_http_sticky_loc_conf_t;


static char      *ngx_http_sticky_set_sticky      (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t  ngx_http_sticky_init            (ngx_conf_t *cf);
static ngx_int_t  ngx_http_sticky_init_worker     (ngx_cycle_t *cycle);

static ngx_int_t ngx_http_sticky_handler       (ngx_http_request_t *r);

static ngx_command_t  ngx_http_sticky_commands[] = {

	{ ngx_string("sticky"),
		NGX_HTTP_UPS_CONF|NGX_CONF_ANY,
		ngx_http_sticky_set_sticky,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL },

	ngx_null_command
};


static ngx_http_module_t  ngx_http_sticky_module_ctx = {
	NULL,                            /* preconfiguration */
	ngx_http_sticky_init,            /* postconfiguration */

	NULL,                            /* create main configuration */
	NULL,                            /* init main configuration */

	NULL,                            /* create server configuration */
	NULL,                            /* merge server configuration */

	NULL,                            /* create location configuration */
	NULL,                            /* merge location configuration */
};


ngx_module_t  ngx_http_sticky_module = {
	NGX_MODULE_V1,
	&ngx_http_sticky_module_ctx, /* module context */
	ngx_http_sticky_commands,   /* module directives */
	NGX_HTTP_MODULE,               /* module type */
	NULL,                          /* init master */
	NULL,                          /* init module */
	NULL,                          /* init process */
	ngx_http_sticky_init_worker,   /* init thread */
	NULL,                          /* exit thread */
	NULL,                          /* exit process */
	NULL,                          /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static ngx_int_t ngx_http_sticky_handler(ngx_http_request_t *r)
{
/*
	ngx_http_sticky_loc_conf_t  *conf;
	ngx_table_elt_t  **h;
	ngx_str_t cookie_expires, cookie_hash, cookie_uid, hash;
	time_t expires;

	h = r->headers_in.cookies.elts;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_sticky_module);

	if (!conf->enable_filter) return NGX_DECLINED;

	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->cookie_name_expires, &cookie_expires) == NGX_DECLINED) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky] client did not send cookie \"%V\"", &conf->cookie_name_expires);
		return ngx_http_sticky_redirect_to_server(r, conf);
	}
	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->cookie_name_hash, &cookie_hash) == NGX_DECLINED) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky] client did not send cookie \"%V\"", &conf->cookie_name_hash);
		return ngx_http_sticky_redirect_to_server(r, conf);
	}
	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->cookie_name_uid, &cookie_uid) == NGX_DECLINED) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky] client did not send cookie \"%V\"", &conf->cookie_name_uid);
		return ngx_http_sticky_redirect_to_server(r, conf);
	}

	if (cookie_uid.len != NGX_XTOKEN_HASH_LENGTH) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky] cookie \"%V\" has a wrong size (%d)", &conf->cookie_name_uid, NGX_XTOKEN_HASH_LENGTH);
		return ngx_http_sticky_redirect_to_server(r, conf);
	}

	expires = ngx_atotm(cookie_expires.data, cookie_expires.len);
	if (expires == NGX_ERROR) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky] cookie \"%V\" has a wrong format (/^\\d+$)", &conf->cookie_name_expires);
		return ngx_http_sticky_redirect_to_server(r, conf);
	}

	if (expires < ngx_time()) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky] cookie \"%V\" has expired", &conf->cookie_name_expires);
		return ngx_http_sticky_redirect_to_server(r, conf);
	}

	if (cookie_hash.len != NGX_XTOKEN_HASH_LENGTH) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky] cookie \"%V\" has a wrong size (%d)", &conf->cookie_name_hash, NGX_XTOKEN_HASH_LENGTH);
		return ngx_http_sticky_redirect_to_server(r, conf);
	}

	if (ngx_http_sticky_make_hash(r, conf, &cookie_expires, &cookie_uid, &hash) != NGX_OK) {
		return NGX_ERROR;
	}

	if (ngx_strncmp(hash.data, cookie_hash.data, hash.len) != 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky] cookie \"%V\" is a wrong hash", &conf->cookie_name_hash);
		return ngx_http_sticky_redirect_to_server(r, conf);
	}
*/
	/* keep going - access is allowed */
	return NGX_DECLINED;
}

static char *ngx_http_sticky_set_sticky(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_uint_t i;
	ngx_str_t name, domain, path;
	time_t expires;

	for (i=1; i<cf->args->nelts; i++) {
		ngx_str_t *value = cf->args->elts;
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] parsing \"%V\"", &value[i]);

		if ((u_char *)ngx_strstr(value[i].data, "name=") == value[i].data) {
			if (value[i].len <= sizeof("name=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] a value must be provided to \"name=\"");
				return NGX_CONF_ERROR;
			}
			name.len = value[i].len - ngx_strlen("name=");
			name.data = (u_char *)(value[i].data + sizeof("name=") - 1);
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] name=%V", &name);
		}

		if ((u_char *)ngx_strstr(value[i].data, "domain=") == value[i].data) {
			if (value[i].len <= ngx_strlen("domain=")) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] a value must be provided to \"domain=\"");
				return NGX_CONF_ERROR;
			}
			domain.len = value[i].len - ngx_strlen("domain=");
			domain.data = (u_char *)(value[i].data + sizeof("domain=") - 1);
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] domain=%V", &domain);
		}

		if ((u_char *)ngx_strstr(value[i].data, "path=") == value[i].data) {
			if (value[i].len <= ngx_strlen("path=")) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] a value must be provided to \"path=\"");
				return NGX_CONF_ERROR;
			}
			path.len = value[i].len - sizeof("path=") - 1;
			path.data = (u_char *)(value[i].data + sizeof("path=") - 1);
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] path=%V", &path);
		}

		if ((u_char *)ngx_strstr(value[i].data, "expires=") == value[i].data) {
			size_t len;
			if (value[i].len <= sizeof("expires=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] a value must be provided to \"expires=\"");
				return NGX_CONF_ERROR;
			}
			len =  value[i].len - ngx_strlen("expires=");
			expires = ngx_atotm((u_char *)(value[i].data + sizeof("expires=") - 1), len);
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] %V => %s => %d", &value[i], (u_char *)(value[i].data + sizeof("expires=") - 1), expires);
			if (expires == NGX_ERROR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[sticky] invalid value for \"expires=\"");
				return NGX_CONF_ERROR;
			}
		}
	}
/*
	ngx_http_sticky_loc_conf_t *c;

	c = ngx_http_conf_get_module_loc_conf(cf, ngx_http_sticky_module);
	c->enable = 1;
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "sticky has been called !!");
	{
	ngx_http_core_loc_conf_t  *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_sticky_server_handler;
	}
*/
	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_sticky_init_worker(ngx_cycle_t *cycle)
{
	return NGX_OK;
}

static ngx_int_t ngx_http_sticky_init(ngx_conf_t *cf)
{
/*
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	// handle sticky_clea_cookie
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_sticky_clear_cookies_handler;

	// handle sticky_filter
	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_sticky_filter_handler;
*/
	void *tmp = (void *)ngx_http_sticky_handler;
	tmp = NULL;
	ngx_http_next_header_filter = NULL;
	return NGX_OK;
}
