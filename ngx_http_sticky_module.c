#include "ngx_http_sticky_misc.h"

typedef struct {
	/* the round robin data must be first */
	ngx_http_upstream_rr_peer_data_t   rrp;
	ngx_uint_t                         hash;
	u_char                             addr[3];
	u_char                             tries;
	ngx_event_get_peer_pt              get_rr_peer;
	ngx_http_request_t                 *r;
} ngx_http_sticky_peer_data_t;


static ngx_int_t  ngx_http_sticky_ups_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t  ngx_http_sticky_ups_get(ngx_peer_connection_t *pc, void *data);
static char      *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void       ngx_http_upstream_sticky_up_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static ngx_uint_t static_index = 0;

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
	u_char                                 *p;
	struct sockaddr_in                     *sin;
	ngx_http_sticky_peer_data_t  *iphp;
	ngx_str_t cookie_name = ngx_string("route");
	ngx_str_t route;

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky/ups_init_peer] enter");

	iphp = ngx_palloc(r->pool, sizeof(ngx_http_sticky_peer_data_t));
	if (iphp == NULL) {
		return NGX_ERROR;
	}

	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie_name, &route) != NGX_DECLINED) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[sticky/ups_init_peer] got cookie route=%V", &route);			
	}

	r->upstream->peer.data = &iphp->rrp;

	if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
		return NGX_ERROR;
	}

	r->upstream->peer.get = ngx_http_sticky_ups_get;
	r->upstream->peer.free = ngx_http_upstream_sticky_up_free_peer;

	/* AF_INET only */

	if (r->connection->sockaddr->sa_family == AF_INET) {

		sin = (struct sockaddr_in *) r->connection->sockaddr;
		p = (u_char *) &sin->sin_addr.s_addr;
		iphp->addr[0] = p[0];
		iphp->addr[1] = p[1];
		iphp->addr[2] = p[2];

	} else {
		iphp->addr[0] = 0;
		iphp->addr[1] = 0;
		iphp->addr[2] = 0;
	}

	iphp->hash = 89;
	iphp->tries = 0;
	iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;
	iphp->r = r;

	return NGX_OK;
}


static ngx_int_t ngx_http_sticky_ups_get(ngx_peer_connection_t *pc, void *data)
{
	ngx_http_sticky_peer_data_t  *iphp = data;

	time_t                        now;
	uintptr_t                     m;
	ngx_uint_t                    i, n, p, hash, index;
	ngx_http_upstream_rr_peer_t  *peer;

	ngx_log_error(NGX_LOG_ERR, pc->log, 0, "[sticky/ups_get] enter (tries=%d)", pc->tries);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
			"get ip hash peer, try: %ui", pc->tries);

	/* TODO: cached */

	if (iphp->tries > 20 || iphp->rrp.peers->single) {
		return iphp->get_rr_peer(pc, &iphp->rrp);
	}

	now = ngx_time();

	pc->cached = 0;
	pc->connection = NULL;

	hash = iphp->hash;

	index = static_index++;
	if (static_index >= iphp->rrp.peers->number) {
		static_index = 0;
	}

	for ( ;; ) {

		for (i = 0; i < 3; i++) {
			hash = (hash * 113 + iphp->addr[i]) % 6271;
		}

		p = hash % iphp->rrp.peers->number;
		p = index;

		n = p / (8 * sizeof(uintptr_t));
		m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

		if (!(iphp->rrp.tried[n] & m)) {

			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
					"get ip hash peer, hash: %ui %04XA", p, m);

			peer = &iphp->rrp.peers->peer[p];

			/* ngx_lock_mutex(iphp->rrp.peers->mutex); */

			if (!peer->down) {

				if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
					break;
				}

				if (now - peer->accessed > peer->fail_timeout) {
					peer->fails = 0;
					break;
				}
			}

			iphp->rrp.tried[n] |= m;

			/* ngx_unlock_mutex(iphp->rrp.peers->mutex); */

			pc->tries--;
		}

		if (++iphp->tries >= 20) {
			return iphp->get_rr_peer(pc, &iphp->rrp);
		}
	}

	iphp->rrp.current = p;

	pc->sockaddr = peer->sockaddr;
	pc->socklen = peer->socklen;
	pc->name = &peer->name;

	/* ngx_unlock_mutex(iphp->rrp.peers->mutex); */

	iphp->rrp.tried[n] |= m;
	iphp->hash = hash;
	{
		ngx_str_t digest;

		if (ngx_http_sticky_misc_md5(iphp->r->pool, peer->sockaddr, peer->socklen, &digest) == NGX_OK) {
			ngx_str_t cookie_name = ngx_string("route");
			ngx_str_t cookie_domain = ngx_string(".egasys.com");
			ngx_str_t cookie_path = ngx_string("/");

			ngx_http_sticky_misc_set_cookie(iphp->r, &cookie_name, &digest, &cookie_domain, &cookie_path, NGX_CONF_UNSET);
		}
	}

	return NGX_OK;
}

static void ngx_http_upstream_sticky_up_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
	ngx_str_t digest;
	ngx_str_t cookie_name = ngx_string("route");
	ngx_str_t cookie_domain = ngx_string("");
	ngx_str_t cookie_path = ngx_string("");

	ngx_http_sticky_peer_data_t *iphp;

	ngx_log_error(NGX_LOG_ERR, pc->log, 0, "[sticky/ups_free] %V : (state=%d)", pc->name, state);
	return;
	if (state == 0) {
		iphp = (ngx_http_sticky_peer_data_t *)pc->data;
		if (ngx_http_sticky_misc_md5(iphp->r->pool, pc->sockaddr, pc->socklen, &digest) == NGX_OK) {
			ngx_log_error(NGX_LOG_ERR, pc->log, 0, "[sticky/ups_free] set cookie for %V:%V / header_sent:%d", pc->name, &digest, iphp->r->header_sent);
			ngx_http_sticky_misc_set_cookie(iphp->r, &cookie_name, &digest, &cookie_domain, &cookie_path, 0);
		}
		return;
	}
}

static char *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_upstream_srv_conf_t  *uscf;

	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	uscf->peer.init_upstream = ngx_http_sticky_ups_init;

	uscf->flags = NGX_HTTP_UPSTREAM_CREATE
		|NGX_HTTP_UPSTREAM_MAX_FAILS
		|NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
		|NGX_HTTP_UPSTREAM_DOWN;

	return NGX_CONF_OK;
}
