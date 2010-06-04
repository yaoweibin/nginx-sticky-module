#include "ngx_http_sticky_misc.h"

typedef struct {
	ngx_http_upstream_rr_peer_data_t   rrp;
	ngx_http_request_t                 *r;
} ngx_http_sticky_peer_data_t;


static ngx_int_t  ngx_http_sticky_ups_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t  ngx_http_sticky_ups_get(ngx_peer_connection_t *pc, void *data);
static char      *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_sticky_commands[] = {

	{ ngx_string("sticky"),
		NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
		ngx_http_sticky_set,
		0,
		0,
		NULL },

	ngx_null_command
};


static ngx_http_module_t  ngx_http_sticky_module_ctx = {
	NULL,                                  /* preconfiguration */
	NULL,                                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	NULL,                                  /* create location configuration */
	NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_sticky_module = {
	NGX_MODULE_V1,
	&ngx_http_sticky_module_ctx, /* module context */
	ngx_http_sticky_commands,    /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


ngx_int_t ngx_http_sticky_ups_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
	if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
		return NGX_ERROR;
	}

	us->peer.init = ngx_http_sticky_ups_init_peer;

	return NGX_OK;
}


static ngx_int_t ngx_http_sticky_ups_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
	ngx_str_t cookie_name = ngx_string("route");
	ngx_str_t route;
	ngx_http_sticky_peer_data_t *spd;
	ngx_http_upstream_rr_peer_data_t *rrp;

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky/ups_init_peer] enter");

	spd = ngx_palloc(r->pool, sizeof(ngx_http_sticky_peer_data_t));
	if (spd == NULL) {
		return NGX_ERROR;
	}

	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, &route) != NGX_DECLINED) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky/ups_init_peer] got cookie route=%V", &route);			
	}

	if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
		return NGX_ERROR;
	}

	rrp = r->upstream->peer.data;
	spd->rrp = *rrp;
	spd->r = r;
	r->upstream->peer.data = &spd->rrp;

	r->upstream->peer.get = ngx_http_sticky_ups_get;

	return NGX_OK;
}


static ngx_int_t ngx_http_sticky_ups_get(ngx_peer_connection_t *pc, void *data)
{
	ngx_uint_t i;
	ngx_str_t digest;
	ngx_http_sticky_peer_data_t *spd = data;

	ngx_log_error(NGX_LOG_ERR, pc->log, 0, "[sticky/ups_get] enter (tries=%d) spd=0x%p", pc->tries, spd->r->pool);

	if ((i = ngx_http_upstream_get_round_robin_peer(pc, data)) != NGX_OK) {
		return i;
	}

	if (ngx_http_sticky_misc_md5(spd->r->pool, pc->sockaddr, pc->socklen, &digest) == NGX_OK) {
		ngx_str_t cookie_name = ngx_string("route");
		ngx_str_t cookie_domain = ngx_string(".egasys.com");
		ngx_str_t cookie_path = ngx_string("/");

		ngx_http_sticky_misc_set_cookie(spd->r, &cookie_name, &digest, &cookie_domain, &cookie_path, NGX_CONF_UNSET);
	}

	return NGX_OK;
}

static char *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_upstream_srv_conf_t  *uscf;

	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	uscf->peer.init_upstream = ngx_http_sticky_ups_init;

	uscf->flags = NGX_HTTP_UPSTREAM_CREATE
		|NGX_HTTP_UPSTREAM_WEIGHT
		|NGX_HTTP_UPSTREAM_MAX_FAILS
		|NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
		|NGX_HTTP_UPSTREAM_DOWN
		|NGX_HTTP_UPSTREAM_BACKUP;

	return NGX_CONF_OK;
}
