#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_sticky_misc.h"

typedef struct {
	ngx_http_upstream_rr_peers_t rr_peers;
	ngx_uint_t  number;
	ngx_str_t peer[1];
} ngx_http_sticky_peers_data_t;

typedef struct {
	ngx_http_upstream_srv_conf_t  uscf;
	ngx_str_t                     cookie_name;
	ngx_str_t                     cookie_domain;
	ngx_str_t                     cookie_path;
	time_t                        cookie_expires;
	ngx_http_sticky_misc_hash_pt  hash;
	ngx_http_sticky_peers_data_t  *peers;
} ngx_http_sticky_srv_conf_t;

typedef struct {
	ngx_http_upstream_rr_peer_data_t   rrp;
	ngx_http_request_t                 *r;
	ngx_str_t                          route;
	ngx_flag_t                         tried_route;
	ngx_http_sticky_srv_conf_t         *sticky_cf;
} ngx_http_sticky_peer_data_t;

static ngx_int_t  ngx_http_sticky_ups_init_peer (ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t  ngx_http_sticky_ups_get       (ngx_peer_connection_t *pc, void *data);
static char      *ngx_http_sticky_set           (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void      *ngx_http_sticky_create_conf   (ngx_conf_t *cf);

static ngx_command_t  ngx_http_sticky_commands[] = {
	{ ngx_string("sticky"),
		NGX_HTTP_UPS_CONF|NGX_CONF_ANY,
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
	ngx_http_sticky_create_conf,           /* create server configuration */
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
	ngx_http_upstream_rr_peers_t *rr_peers;
	ngx_http_sticky_srv_conf_t *conf;
	ngx_uint_t i;

	if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
		return NGX_ERROR;
	}
	rr_peers = us->peer.data;

	conf = ngx_http_conf_upstream_srv_conf(us, ngx_http_sticky_module);
	conf->peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_sticky_peers_data_t) + sizeof(ngx_str_t) * (rr_peers->number - 1));
	if (conf->peers == NULL) {
		return NGX_ERROR;
	}
	conf->peers->number = rr_peers->number;

	for (i=0; i<rr_peers->number; i++) {
		conf->hash(cf->pool, rr_peers->peer[i].sockaddr, rr_peers->peer[i].socklen, &conf->peers->peer[i]);
	}

	us->peer.init = ngx_http_sticky_ups_init_peer;

	return NGX_OK;
}

static ngx_int_t ngx_http_sticky_ups_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
	ngx_http_sticky_peer_data_t *spd;
	ngx_http_upstream_rr_peer_data_t *rrp;

	spd = ngx_palloc(r->pool, sizeof(ngx_http_sticky_peer_data_t));
	if (spd == NULL) {
		return NGX_ERROR;
	}

	spd->sticky_cf = ngx_http_conf_upstream_srv_conf(us, ngx_http_sticky_module);
	spd->tried_route = 1; /* presume a route cookie has not been found */

	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &spd->sticky_cf->cookie_name, &spd->route) != NGX_DECLINED) {
		/* a route cookie has been found. Let's give it a try */
		spd->tried_route = 0;
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[sticky/ups_init_peer] got cookie route=%V", &spd->route);
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
	ngx_http_sticky_peer_data_t *spd = data;
	ngx_http_sticky_srv_conf_t *conf = spd->sticky_cf;

	if (!spd->tried_route) {
		spd->tried_route = 1;
		if (spd->route.len > 0) {
			/* we got a route and we never tried it. Let's use it first! */
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/ups_get] We got a route and never tried it. TRY IT !");

			for (i=0; i<conf->peers->number && i<spd->rrp.peers->number; i++) {
				ngx_http_upstream_rr_peer_t *peer = &spd->rrp.peers->peer[i];

				if (ngx_strncmp(spd->route.data, conf->peers->peer[i].data, conf->peers->peer[i].len) != 0) {
					ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/ups_get] peer \"%V\" with digest \"%V\" does not match \"%V\"", &peer->name, &conf->peers->peer[i], &spd->route);
					continue;
				}

				ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/ups_get] peer \"%V\" with digest \"%V\" DOES MATCH \"%V\"", &peer->name, &conf->peers->peer[i], &spd->route);
				spd->tried_route = 1;
				pc->sockaddr = peer->sockaddr;
				pc->socklen = peer->socklen;
				pc->name = &peer->name;
				return NGX_OK;
			}
		}
	}

	/* switch back to classic rr */
	if ((i = ngx_http_upstream_get_round_robin_peer(pc, data)) != NGX_OK) {
		return i;
	}

	for (i=0; i<conf->peers->number && i<spd->rrp.peers->number; i++) {
		ngx_http_upstream_rr_peer_t *peer = &spd->rrp.peers->peer[i];

		if (peer->sockaddr == pc->sockaddr && peer->socklen == pc->socklen) {
			ngx_http_sticky_misc_set_cookie(spd->r, &conf->cookie_name, &conf->peers->peer[i], &conf->cookie_domain, &conf->cookie_path, conf->cookie_expires);
			break;
		}
	}

	return NGX_OK;
}

static char *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_upstream_srv_conf_t  *uscf;
	ngx_http_sticky_srv_conf_t *usscf;
	ngx_uint_t i;
	ngx_str_t tmp;
	ngx_str_t name = ngx_string("route");
	ngx_str_t domain = ngx_string("");
	ngx_str_t path = ngx_string("");
	time_t expires = NGX_CONF_UNSET;
	ngx_http_sticky_misc_hash_pt hash = ngx_http_sticky_misc_md5;

	for (i=1; i<cf->args->nelts; i++) {
		ngx_str_t *value = cf->args->elts;

		if ((u_char *)ngx_strstr(value[i].data, "name=") == value[i].data) {
			if (value[i].len <= sizeof("name=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"name=\"");
				return NGX_CONF_ERROR;
			}
			name.len = value[i].len - ngx_strlen("name=");
			name.data = (u_char *)(value[i].data + sizeof("name=") - 1);
			continue;
		}

		if ((u_char *)ngx_strstr(value[i].data, "domain=") == value[i].data) {
			if (value[i].len <= ngx_strlen("domain=")) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"domain=\"");
				return NGX_CONF_ERROR;
			}
			domain.len = value[i].len - ngx_strlen("domain=");
			domain.data = (u_char *)(value[i].data + sizeof("domain=") - 1);
			continue;
		}

		if ((u_char *)ngx_strstr(value[i].data, "path=") == value[i].data) {
			if (value[i].len <= ngx_strlen("path=")) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"path=\"");
				return NGX_CONF_ERROR;
			}
			path.len = value[i].len - ngx_strlen("path=");
			path.data = (u_char *)(value[i].data + sizeof("path=") - 1);
			continue;
		}

		if ((u_char *)ngx_strstr(value[i].data, "expires=") == value[i].data) {
			if (value[i].len <= sizeof("expires=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"expires=\"");
				return NGX_CONF_ERROR;
			}
			tmp.len =  value[i].len - ngx_strlen("expires=");
			tmp.data = (u_char *)(value[i].data + sizeof("expires=") - 1);
			expires = ngx_parse_time(&tmp, 1);
			if (expires == NGX_ERROR || expires < 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value for \"expires=\"");
				return NGX_CONF_ERROR;
			}
			continue;
		}
	
		if ((u_char *)ngx_strstr(value[i].data, "hash=") == value[i].data) {
			if (value[i].len <= sizeof("hash=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"hash=\"");
				return NGX_CONF_ERROR;
			}
			tmp.len =  value[i].len - ngx_strlen("hash=");
			tmp.data = (u_char *)(value[i].data + sizeof("hash=") - 1);
			if (ngx_strncmp(tmp.data, "md5", sizeof("md5") - 1) == 0 ) {
				hash = ngx_http_sticky_misc_md5;
				continue;
			}
			if (ngx_strncmp(tmp.data, "sha1", sizeof("sha1") - 1) == 0 ) {
				hash = ngx_http_sticky_misc_sha1;
				continue;
			}
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "wrong value for \"hash=\": md5 or sha1");
			return NGX_CONF_ERROR;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid arguement (%V)", &value[i]);
		return NGX_CONF_ERROR;
	}

	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
	uscf->peer.init_upstream = ngx_http_sticky_ups_init;
	uscf->flags = NGX_HTTP_UPSTREAM_CREATE
		|NGX_HTTP_UPSTREAM_WEIGHT
		|NGX_HTTP_UPSTREAM_MAX_FAILS
		|NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
		|NGX_HTTP_UPSTREAM_DOWN
		|NGX_HTTP_UPSTREAM_BACKUP;

	usscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_sticky_module);
	usscf->cookie_name = name;
	usscf->cookie_domain = domain;
	usscf->cookie_path = path;
	usscf->cookie_expires = expires;
	usscf->hash = hash;
	
	return NGX_CONF_OK;
}

static void *ngx_http_sticky_create_conf(ngx_conf_t *cf)
{
	ngx_http_sticky_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sticky_srv_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	return conf;
}
