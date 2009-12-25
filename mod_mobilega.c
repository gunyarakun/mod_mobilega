/* mod_mobilega */
/*
Copyright (c) 2009- Brazil, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#undef PACKAGE
#undef VERSION
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h" // lighttpd's config.h

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "plugin.h"

#include "fdevent.h"

#include "inet_ntop_cache.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include "md5.h"

#define data_mobilega data_fastcgi

typedef struct {
  buffer *ad_type;
  buffer *channel;
  buffer *client;
  buffer *format;
  buffer *markup;
  buffer *oe;
  buffer *output;

  unsigned short debug;
} plugin_config;

typedef struct {
  PLUGIN_DATA;

  plugin_config **config_storage;
  plugin_config conf;
} plugin_data;

typedef enum {
  GA_STATE_INIT,
  GA_STATE_CONNECT,
  GA_STATE_PREPARE_WRITE,
  GA_STATE_WRITE,
  GA_STATE_READ,
  GA_STATE_ERROR
} ga_connection_state_t;

typedef struct {
  ga_connection_state_t state;
  //time_t state_timestamp;

  data_mobilega *host;

  buffer *response;
  buffer *response_header;

  chunkqueue *wb;
  int fd; /* fd to the proxy process */
  int fde_ndx; /* index into the fd-event buffer */

  //size_t path_info_offset; /* start of path_info in uri.path */

  connection *remote_conn;  /* dump pointer */
  plugin_data *plugin_data; /* dump pointer */
} handler_ctx;

INIT_FUNC(mod_mobilega_init) {
  plugin_data *p;

  if ((p = calloc(1, sizeof(plugin_data)))) {
    /* TODO: init */
    return p;
  }
  return NULL;
}

/* detroy the plugin data */
FREE_FUNC(mod_mobilega_free) {
  plugin_data *p = p_d;
  UNUSED(srv);
  if (!p) return HANDLER_GO_ON;
  if (p->config_storage) {
    size_t i;
    for (i = 0; i < srv->config_context->used; i++) {
      plugin_config *s = p->config_storage[i];
      if (!s) continue;
      free(s);
    }
    free(p->config_storage);
  }
  return HANDLER_GO_ON;
}

/* handle plugin config and check values */
SETDEFAULTS_FUNC(mod_mobilega_set_defaults) {
  plugin_data *p = p_d;
  size_t i = 0;

  // FIXME:
  config_values_t cv[] = {
//    { "groonga.db-file-name", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
    { NULL,                   NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
  };

  if (!p) return HANDLER_ERROR;

  p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

  for (i = 0; i < srv->config_context->used; i++) {
    plugin_config *s;
    s = calloc(1, sizeof(plugin_config));

//    s->db_filename = buffer_init();
//    cv[0].destination = s->db_filename;

    p->config_storage[i] = s;

    if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
      return HANDLER_ERROR;
    }
/*
    if (!buffer_is_empty(s->db_filename)) {
      return HANDLER_ERROR;
    }
*/
  }
  return HANDLER_GO_ON;
}

#define PATCH(x) \
  p->conf.x = s->x;

static int mod_mobilega_patch_connection(server *srv, connection *con, plugin_data *p) {
  size_t i, j;
  plugin_config *s = p->config_storage[0];

  // PATCH(db);

  /* skip the first, the global context */
  for (i = 1; i < srv->config_context->used; i++) {
    data_config *dc = (data_config *)srv->config_context->data[i];
    s = p->config_storage[i];

    /* condition didn't magroongah */
    if (!config_check_cond(srv, con, dc)) continue;

    /* merge config */
    for (j = 0; j < dc->value->used; j++) {
      data_unset *du = dc->value->data[j];
      /*
      if (buffer_is_equal_string(du->key, CONST_STR_LEN("groonga.db-filename"))) {
        PATCH(db_file_name);
      }
      */
    }
  }
  return 0;
}
#undef PATCH

#define GA_HOST "pagead2.googlesyndication.com"
#define GA_PORT 80
#define GA_AD_TYPE "text_image"
#define GA_CHANNEL "4846347906"
#define GA_CLIENT "ca-mb-pub-6322315354375602"
#define GA_FORMAT "mobile_single"
#define GA_MARKUP "xhtml"
#define GA_OE "utf8"
#define GA_OUTPUT "xhtml"

static int
socket_open(server *srv, handler_ctx *hctx) {
  struct sockaddr *addr;
  struct sockaddr_in addr_in;
  socklen_t servlen;

  plugin_data *p          = hctx->plugin_data;
  data_mobilega *host = hctx->host;
  int proxy_fd            = hctx->fd;

  {
    memset(&addr_in, 0, sizeof(addr_in));
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = inet_addr(GA_HOST);
    addr_in.sin_port = htons(GA_PORT);
    servlen = sizeof(addr_in);
    addr = (struct sockaddr *) &addr_in;
  }

  if (-1 == connect(proxy_fd, addr, servlen)) {
    if (errno == EINPROGRESS || errno == EALREADY) {
      if (p->conf.debug) {
        log_error_write(srv, __FILE__, __LINE__, "sd",
            "adsense connect delayed:", proxy_fd);
      }
      return 1;
    } else {
      log_error_write(srv, __FILE__, __LINE__, "sdsd",
          "adsense connect failed:", proxy_fd, strerror(errno), errno);
      return -1;
    }
  }
  if (p->conf.debug) {
    log_error_write(srv, __FILE__, __LINE__, "sd",
        "adsense connect succeeded: ", proxy_fd);
  }

  return 0;
}

static void
ga_send_request_to_google_analytics(handler_ctx *hctx, const char *path, unsigned int path_len, buffer *user_agent, data_string *accept_language)
{
  buffer *r = chunkqueue_get_append_buffer(hctx->wb);

  BUFFER_COPY_STRING_CONST(r, "GET /__utm.gif HTTP/1.0");
  if (accept_language) {
    BUFFER_COPY_STRING_CONST(r, "\r\nAccepts-Language: ");
    buffer_append_string_buffer(r, accept_language->value);
  }
  BUFFER_APPEND_STRING_CONST(r, "\r\nUser-Agent: ");
  buffer_append_string_buffer(r, user_agent);
  BUFFER_APPEND_STRING_CONST(r, "\r\n\r\n");

  hctx->wb->bytes_in += r->used - 1;
}

static int
split_get_params(array *get_params, buffer *qrystr) {
  size_t is_key = 1;
  size_t i;
  char *key = NULL, *val = NULL;

  key = qrystr->ptr;

  /* we need the  0 */
  for (i = 0; i < qrystr->used; i++) {
    switch(qrystr->ptr[i]) {
    case '=':
      if (is_key) {
        val = qrystr->ptr + i + 1;

        qrystr->ptr[i] = '\0';

        is_key = 0;
      }

      break;
    case '&':
    case '\0': /* fin symbol */
      if (!is_key) {
        data_string *ds;
        /* we need at least a = since the last & */

        /* terminate the value */
        qrystr->ptr[i] = '\0';
        if (NULL == (ds = (data_string *)array_get_unused_element(get_params, TYPE_STRING))) {
          ds = data_string_init();
        }
        buffer_copy_string_len(ds->key, key, strlen(key));
        buffer_copy_string_len(ds->value, val, strlen(val));
        buffer_urldecode_query(ds->value);

        array_insert_unique(get_params, (data_unset *)ds);
      }

      key = qrystr->ptr + i + 1;
      val = NULL;
      is_key = 1;
      break;
    }
  }

  return 0;
}

static int
parse_cookie(array *cookies, buffer *cbuf) {
  const char *p, *q;
  const char *key, *value;
  size_t key_len, value_len;

  p = cbuf->ptr;
  while (*p) {
    data_string *ds;

    for(; *p == ' '; p++);

    /* key */
    q = p;
    for(; *p != '=' && *p; p++);
    if (q == p || !*p) { break; } /* empty or invalid key */
    key = q; key_len = (size_t)(p - q);

    /* value */
    q = ++p;
    for(; *p != ';' && *p; p++);
    value = q; value_len = (size_t)(p - q); p++;

    if (NULL == (ds = (data_string *)array_get_unused_element(cookies, TYPE_STRING))) {
      ds = data_string_init();
    }

    buffer_copy_string_len(ds->key, key, key_len);
    buffer_copy_string_len(ds->value, value, value_len);
    buffer_urldecode_query(ds->value);
    array_insert_unique(cookies, (data_unset *)ds);
  }
  return 0;
}

#define GA_VERSION                 "4.4sh"
#define GA_COOKIE_NAME             "__utmmobile"
#define GA_COOKIE_PATH             "/"
#define GA_COOKIE_USER_PERSISTENCE 63072000

static buffer *
ga_get_visitor_id(buffer *guid, buffer *account, buffer *user_agent, buffer *cookie)
{
  buffer *message;
  if (cookie && CONST_BUF_LEN(cookie) != 0) {
    return buffer_init_buffer(cookie);
  }

  if (!buffer_is_empty(guid)) {
    message = buffer_init_buffer(guid);
    buffer_append_string_buffer(message, account);
  } else {
    message = buffer_init_buffer(user_agent);
    // lighttpd is single thread, so we use random()
    buffer_append_long(message, random());
    // TODO: $message = $userAgent . uniqid(getRandomNumber(), true);
  }

  {
    MD5_CTX Md5Ctx;
    unsigned char h[16];

    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, CONST_BUF_LEN(message));
    MD5_Final(h, &Md5Ctx);

    message = buffer_init_string("0x");
    buffer_append_string_encoded(message, (char *)h, 8, ENCODING_HEX);
  }
  return message;
}

static void
ga_track_page_view(handler_ctx *hctx, connection *con)
{
  time_t timestamp;
  array *get_params;
  data_string *ds = NULL;
  buffer *query_str, *domain_name, *document_referer, *document_path, *account,
         *user_agent, *dcmguid, *visitor_id,
         *utm_url;
#ifdef HAVE_IPV6
  char b2[INET6_ADDRSTRLEN + 1];
#endif

  server_socket *srv_sock = con->srv_socket;

  buffer_copy_string_buffer(query_str, con->uri.query);
  split_get_params(get_params, query_str);

  // timestamp
  timestamp = time();

  // domain_name
  domain_name = buffer_init();
  if (!buffer_is_empty(con->server_name)) {
    size_t len = con->server_name->used - 1;
    char *colon = strchr(con->server_name->ptr, ':');
    if (colon) len = colon - con->server_name->ptr;

    buffer_copy_string_len(domain_name, con->server_name->ptr, len);
  } else {
    const char *s;
#ifdef HAVE_IPV6
    s = inet_ntop(srv_sock->addr.plain.sa_family,
            srv_sock->addr.plain.sa_family == AF_INET6 ?
            (const void *) &(srv_sock->addr.ipv6.sin6_addr) :
            (const void *) &(srv_sock->addr.ipv4.sin_addr),
            b2, sizeof(b2)-1);
#else
    s = inet_ntoa(srv_sock->addr.ipv4.sin_addr);
#endif
    buffer_copy_string(domain_name, s);
  }

  // utmr -> document_referer
  /* set ref */
  if ((ds = (data_string *)array_get_element(get_params, "utmr")) &&
      !buffer_is_empty(ds->value) &&
      !buffer_is_equal_string(ds->value, "0", 1)) {
    document_referer = buffer_init_buffer(ds->value);
    buffer_urldecode_query(document_referer);
  } else {
    document_referer = buffer_init_string("-");
  }

  // utmp -> document_path
  if ((ds = (data_string *)array_get_element(get_params, "utmp")) && !buffer_is_empty(ds->value)) {
    document_path = buffer_init_buffer(ds->value);
    buffer_urldecode_query(document_path);
  } else {
    document_path = buffer_init();
  }

  // utmac -> account
  if ((ds = (data_string *)array_get_element(get_params, "utmac"))) {
    account = buffer_init_buffer(ds->value);
  } else {
    account = buffer_init();
  }

  // user_agent
  if ((ds = (data_string *)array_get_element(con->request.headers, "User-Agent")) && !buffer_is_empty(ds->value)) {
    user_agent = buffer_init_buffer(ds->value);
  } else {
    user_agent = buffer_init();
  }

  // dcmguid
  if ((ds = (data_string *)array_get_element(con->request.headers, "X-DCMGUID"))) {
    dcmguid = ds->value;
  } else {
    dcmguid = NULL;
  }

  // cookie -> visitor_id
  if ((ds = (data_string *)array_get_element(con->request.headers, "Cookie"))) {
    array *cookies;
    array_reset(cookies);
    parse_cookie(cookies, ds->value);
    if ((ds = (data_string *)array_get_element(cookies, GA_COOKIE_NAME))) {
      visitor_id = ga_get_visitor_id(dcmguid, account, user_agent, ds->value);
    } else {
      visitor_id = ga_get_visitor_id(dcmguid, account, user_agent, NULL);
    }
  } else {
    visitor_id = ga_get_visitor_id(dcmguid, account, user_agent, NULL);
  }

  // Always try and add the cookie to the response.
  if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
    ds = data_response_init();
  }
  BUFFER_COPY_STRING_CONST(ds->key, "Set-Cookie");
  BUFFER_COPY_STRING_CONST(ds->value, GA_COOKIE_NAME);
  BUFFER_APPEND_STRING_CONST(ds->value, "=");

  buffer_append_string_buffer(ds->value, visitor_id);
  BUFFER_APPEND_STRING_CONST(ds->value, "; Path=" GA_COOKIE_PATH);
  buffer_append_string_len(ds->value, CONST_STR_LEN("; Version=1"));

  buffer_append_string_len(ds->value, CONST_STR_LEN("; max-age="));
  buffer_append_long(ds->value, GA_COOKIE_USER_PERSISTENCE);

  array_insert_unique(con->response.headers, (data_unset *)ds);

  // Construct the gif hit url.
#define GA_UTM_GIF_LOCATION "TODO"
  utm_url = buffer_init_string(GA_UTM_GIF_LOCATION "?"
                               "utmwv=" VERSION
                               "&utmn=");
  buffer_append_long(utm_url, random() % 0x7fffffff);
  BUFFER_APPEND_STRING_CONST(utm_url, "&utmhn=");
  buffer_append_string_encoded(utm_url, CONST_BUF_LEN(domain_name), ENCODING_REL_URI_PART);
  BUFFER_APPEND_STRING_CONST(utm_url, "&utmr=");
  buffer_append_string_encoded(utm_url, CONST_BUF_LEN(document_referer), ENCODING_REL_URI_PART);
  BUFFER_APPEND_STRING_CONST(utm_url, "&utmp=");
  buffer_append_string_encoded(utm_url, CONST_BUF_LEN(document_path), ENCODING_REL_URI_PART);
  BUFFER_APPEND_STRING_CONST(utm_url, "&utmac=");
  buffer_append_buffer(utm_url, account);
  BUFFER_APPEND_STRING_CONST(utm_url, "&utmcc=__utma%3D999.999.999.999.999.1%3B"
                                      "&utmvid=");
  buffer_append_buffer(utm_url, visitor_id);
  BUFFER_APPEND_STRING_CONST(utm_url, "&utmip=");

  // remote_addr
  {
    const char *s;
    struct in_addr ia;
    switch (con->dst_addr.plain.sa_family) {
    case AF_INET:
      ia = con->dst_addr.ipv4.sin_addr;
      // Capture the first three octects of the IP address and replace the forth
      // with 0, e.g. 124.455.3.123 becomes 124.455.3.0
      ia.s_addr &= 0x00ffffffU;
      if ((s = inet_ntoa(ia))) {
        buffer_append_string_encoded(utm_url, s, strlen(s), ENCODING_REL_URI_PART);
      }
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      /* TODO: implement */
      break;
#endif
    default:
      break;
    }
  }

  // dcmguid
  if ((ds = (data_string *)array_get_element(con->request.headers, "X-DCMGUID"))) {
    dcmguid = ds->value;
  } else {
    dcmguid = NULL;
  }

  ga_send_request_to_google_analytics(hctx, CONST_BUF_LEN(utm_url), user_agent, (data_string *)array_get_element(con->request.headers, "Accept-Language"));

  ga_write_gif_data();
}

static handler_t ga_handle_fdevent(void *s, void *ctx, int revents);

static handler_t ga_write_request(server *srv, handler_ctx *hctx) {
  plugin_data *p    = hctx->plugin_data;
  connection *con   = hctx->remote_conn;

  int ret;

  switch(hctx->state) {
  case GA_STATE_INIT:
    if (-1 == (hctx->fd = socket(AF_INET, SOCK_STREAM, 0))) {
      log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed: ", strerror(errno));
  return HANDLER_ERROR;
    }
    hctx->fde_ndx = -1;

    srv->cur_fds++;

    fdevent_register(srv->ev, hctx->fd, ga_handle_fdevent, hctx);

    if (-1 == fdevent_fcntl_set(srv->ev, hctx->fd)) {
      log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl failed: ", strerror(errno));

      return HANDLER_ERROR;
    }

    /* fall through */

  case GA_STATE_CONNECT:
    /* try to finish the connect() */
    if (hctx->state == GA_STATE_INIT) {
      /* first round */
      switch (proxy_establish_connection(srv, hctx)) {
      case 1:
        proxy_set_state(srv, hctx, GA_STATE_CONNECT);

        /* connection is in progress, wait for an event and call getsockopt() below */

        fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);

        return HANDLER_WAIT_FOR_EVENT;
      case -1:
        /* if ECONNREFUSED choose another connection -> FIXME */
        hctx->fde_ndx = -1;

        return HANDLER_ERROR;
      default:
        /* everything is ok, go on */
        break;
      }
    } else {
      int socket_error;
      socklen_t socket_error_len = sizeof(socket_error);

      /* we don't need it anymore */
      fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);

      /* try to finish the connect() */
      if (0 != getsockopt(hctx->fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len)) {
        log_error_write(srv, __FILE__, __LINE__, "ss",
            "getsockopt failed:", strerror(errno));

        return HANDLER_ERROR;
      }
      if (socket_error != 0) {
        log_error_write(srv, __FILE__, __LINE__, "ss",
            "establishing connection failed:", strerror(socket_error),
            "port:", hctx->host->port);

        return HANDLER_ERROR;
      }
      if (p->conf.debug) {
        log_error_write(srv, __FILE__, __LINE__,  "s", "proxy - connect - delayed success");
      }
    }

    proxy_set_state(srv, hctx, GA_STATE_PREPARE_WRITE);
    /* fall through */
  case GA_STATE_PREPARE_WRITE:
    proxy_create_env(srv, hctx);

    proxy_set_state(srv, hctx, GA_STATE_WRITE);

    /* fall through */
  case GA_STATE_WRITE:;
    ret = srv->network_backend_write(srv, con, hctx->fd, hctx->wb);

    chunkqueue_remove_finished_chunks(hctx->wb);

    if (-1 == ret) {
      if (errno != EAGAIN &&
          errno != EINTR) {
        log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed:", strerror(errno), errno);

        return HANDLER_ERROR;
      } else {
        fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);

        return HANDLER_WAIT_FOR_EVENT;
      }
    }

    if (hctx->wb->bytes_out == hctx->wb->bytes_in) {
      proxy_set_state(srv, hctx, GA_STATE_READ);

      fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
      fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
    } else {
      fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);

      return HANDLER_WAIT_FOR_EVENT;
    }

    return HANDLER_WAIT_FOR_EVENT;
  case GA_STATE_READ:
    /* waiting for a response */
    return HANDLER_WAIT_FOR_EVENT;
  default:
    log_error_write(srv, __FILE__, __LINE__, "s", "(debug) unknown state");
    return HANDLER_ERROR;
  }

  return HANDLER_GO_ON;
}

static int ga_demux_response(server *srv, handler_ctx *hctx) {
  int fin = 0;
  int b;
  ssize_t r;

  plugin_data *p    = hctx->plugin_data;
  connection *con   = hctx->remote_conn;
  int proxy_fd       = hctx->fd;

  /* check how much we have to read */
  if (ioctl(hctx->fd, FIONREAD, &b)) {
    log_error_write(srv, __FILE__, __LINE__, "sd",
        "ioctl failed: ",
        proxy_fd);
    return -1;
  }


  if (p->conf.debug) {
    log_error_write(srv, __FILE__, __LINE__, "sd",
             "proxy - have to read:", b);
  }

  if (b > 0) {
    if (hctx->response->used == 0) {
      /* avoid too small buffer */
      buffer_prepare_append(hctx->response, b + 1);
      hctx->response->used = 1;
    } else {
      buffer_prepare_append(hctx->response, b);
    }

    if (-1 == (r = read(hctx->fd, hctx->response->ptr + hctx->response->used - 1, b))) {
      if (errno == EAGAIN) return 0;
      log_error_write(srv, __FILE__, __LINE__, "sds",
          "unexpected end-of-file (perhaps the proxy process died):",
          proxy_fd, strerror(errno));
      return -1;
    }

    /* this should be catched by the b > 0 above */
    assert(r);

    hctx->response->used += r;
    hctx->response->ptr[hctx->response->used - 1] = '\0';

#if 0
    log_error_write(srv, __FILE__, __LINE__, "sdsbs",
        "demux: Response buffer len", hctx->response->used, ":", hctx->response, ":");
#endif

    if (0 == con->got_response) {
      con->got_response = 1;
      buffer_prepare_copy(hctx->response_header, 128);
    }

    if (0 == con->file_started) {
      char *c;

      /* search for the \r\n\r\n in the string */
      if (NULL != (c = buffer_search_string_len(hctx->response, "\r\n\r\n", 4))) {
        size_t hlen = c - hctx->response->ptr + 4;
        size_t blen = hctx->response->used - hlen - 1;
        /* found */

        buffer_append_string_len(hctx->response_header, hctx->response->ptr, c - hctx->response->ptr + 4);
#if 0
        log_error_write(srv, __FILE__, __LINE__, "sb", "Header:", hctx->response_header);
#endif
        /* parse the response header */
        proxy_response_parse(srv, con, p, hctx->response_header);

        /* enable chunked-transfer-encoding */
        if (con->request.http_version == HTTP_VERSION_1_1 &&
            !(con->parsed_response & HTTP_CONTENT_LENGTH)) {
          con->response.transfer_encoding = HTTP_TRANSFER_ENCODING_CHUNKED;
        }

        con->file_started = 1;
        if (blen) {
          http_chunk_append_mem(srv, con, c + 4, blen + 1);
          joblist_append(srv, con);
        }
        hctx->response->used = 0;
      }
    } else {
      http_chunk_append_mem(srv, con, hctx->response->ptr, hctx->response->used);
      joblist_append(srv, con);
      hctx->response->used = 0;
    }

  } else {
    /* reading from upstream done */
    con->file_finished = 1;

    http_chunk_append_mem(srv, con, NULL, 0);
    joblist_append(srv, con);

    fin = 1;
  }

  return fin;
}

static void
include_mobile_adsense(connection *con)
{
  data_string *ds = NULL;
  buffer *url;
  url = buffer_init_string("/pagead/ads?"
    "ad_type=" GA_AD_TYPE
    "&channel=" GA_CHANNEL
    "&client=" GA_CLIENT
    "&format=" GA_FORMAT
    "&markup=" GA_MARKUP
    "&oe=" GA_OE
    "&output=" GA_OUTPUT);

  /* set dt */
  {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    BUFFER_APPEND_STRING_CONST(url, "&dt=");
    buffer_append_long(url, tv.tv_sec * 1000 + tv.tv_usec / 1000);
  }

  /* set ip */
  {
    const char *s;
    switch (con->dst_addr.plain.sa_family) {
    case AF_INET:
      if ((s = inet_ntoa(con->dst_addr.ipv4.sin_addr))) {
        BUFFER_APPEND_STRING_CONST(url, "&ip=");
        buffer_append_string_encoded(url, s, strlen(s), ENCODING_REL_URI_PART);
      }
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      /* TODO: implement */
      break;
#endif
    default:
      break;
    }
  }

  /* set ref */
  if ((ds = (data_string *)array_get_element(con->request.headers, "Referer"))) {
    BUFFER_APPEND_STRING_CONST(url, "&ref=");
    buffer_append_string_encoded(url, CONST_BUF_LEN(ds->value), ENCODING_REL_URI_PART);
  }

  /* set url */
  if (!buffer_is_empty(con->request.orig_uri)) {
    BUFFER_APPEND_STRING_CONST(url, "&url=");
    buffer_append_string_encoded(url, CONST_BUF_LEN(con->request.orig_uri), ENCODING_REL_URI);
    if (!buffer_is_empty(con->uri.query)) {
      BUFFER_APPEND_STRING_CONST(url, "%3F");
      buffer_append_string_encoded(url, CONST_BUF_LEN(con->uri.query), ENCODING_REL_URI_PART);
    }
  }

  /* set user agent */
  if ((ds = (data_string *)array_get_element(con->request.headers, "User-Agent"))) {
    BUFFER_APPEND_STRING_CONST(url, "&useragent=");
    buffer_append_string_encoded(url, CONST_BUF_LEN(ds->value), ENCODING_REL_URI_PART);
  }
  if (!ds || buffer_is_empty(ds->value)) {
    /* set via/accept */
    BUFFER_APPEND_STRING_CONST(url, "&via=");
    ds = (data_string *)array_get_element(con->request.headers, "Via");
    if (ds) {
      buffer_append_string_encoded(url, CONST_BUF_LEN(ds->value), ENCODING_REL_URI_PART);
    }
    BUFFER_APPEND_STRING_CONST(url, "&accept=");
    ds = (data_string *)array_get_element(con->request.headers, "Accept");
    if (ds) {
      buffer_append_string_encoded(url, CONST_BUF_LEN(ds->value), ENCODING_REL_URI_PART);
    }
  }

  /* set screen res */
  if (!(ds = (data_string *)array_get_element(con->request.headers, "UA-pixels"))) {
    if (!(ds = (data_string *)array_get_element(con->request.headers, "x-up-devcap-screenpixels"))) {
      ds = (data_string *)array_get_element(con->request.headers, "x-jphone-display");
    }
  }
  if (ds) {
    int u_w = 0, u_h = 0;
    size_t wl = strcspn(ds->value->ptr, "x,*");
    char d = *(ds->value->ptr + wl);
    if (d == 'x' || d == ',' || d == '*') {
      u_w = atoi(ds->value->ptr);
      u_h = atoi(ds->value->ptr + wl + 1);
    }
    if (u_w && u_h) {
      BUFFER_APPEND_STRING_CONST(url, "&u_w=");
      buffer_append_long(url, u_w);
      BUFFER_APPEND_STRING_CONST(url, "&u_h=");
      buffer_append_long(url, u_h);
    }
  }

  /* set muid */
  if (!(ds = (data_string *)array_get_element(con->request.headers, "X-DCMGUID"))) {
    if (!(ds = (data_string *)array_get_element(con->request.headers, "X-UP-SUBNO"))) {
      if (!(ds = (data_string *)array_get_element(con->request.headers, "X-JPHONE_UID"))) {
        ds = (data_string *)array_get_element(con->request.headers, "X-EM-UID");
      }
    }
  }
  if (ds) {
    BUFFER_APPEND_STRING_CONST(url, "&muid=");
    buffer_append_string_encoded(url, CONST_BUF_LEN(ds->value), ENCODING_REL_URI_PART);
  }
}

SUBREQUEST_FUNC(mod_mobilega_handle_subrequest) {
  plugin_data *p = p_d;
  size_t m;
  off_t max_fsize;
  stat_cache_entry *sce = NULL;

  handler_ctx *hctx = con->plugin_ctx[p->id];
  data_mobilega *host;

  if (NULL == hctx) return HANDLER_GO_ON;

  mod_mobilega_patch_connection(srv, con, p);
  host = hctx->host;

  if (con->mode != p->id) return HANDLER_GO_ON;

  switch(proxy_write_request(srv, hctx)) {
  case HANDLER_ERROR:
    log_error_write(srv, __FILE__, __LINE__,  "sbdd", "proxy-server disabled:",
      host->host,
      host->port,
      hctx->fd);

    /* disable this server */
    host->is_disabled = 1;
    host->disable_ts = srv->cur_ts;

    proxy_connection_close(srv, hctx);

    /* reset the enviroment and restart the sub-request */
    buffer_reset(con->physical.path);
    con->mode = DIRECT;

    joblist_append(srv, con);

    /* mis-using HANDLER_WAIT_FOR_FD to break out of the loop
     * and hope that the childs will be restarted
     *
     */

    return HANDLER_WAIT_FOR_FD;
  case HANDLER_WAIT_FOR_EVENT:
    return HANDLER_WAIT_FOR_EVENT;
  case HANDLER_WAIT_FOR_FD:
    return HANDLER_WAIT_FOR_FD;
  default:
    break;
  }

  if (con->file_started == 1) {
    return HANDLER_FINISHED;
  } else {
    return HANDLER_WAIT_FOR_EVENT;
  }
}

static handler_t ga_handle_fdevent(void *s, void *ctx, int revents) {
  server      *srv  = (server *)s;
  handler_ctx *hctx = ctx;
  connection  *con  = hctx->remote_conn;
  plugin_data *p    = hctx->plugin_data;

  if ((revents & FDEVENT_IN) &&
      hctx->state == GA_STATE_READ) {

    switch (proxy_demux_response(srv, hctx)) {
    case 0:
      break;
    case 1:
      hctx->host->usage--;

      /* we are done */
      proxy_connection_close(srv, hctx);

      joblist_append(srv, con);
      return HANDLER_FINISHED;
    case -1:
      if (con->file_started == 0) {
        /* nothing has been send out yet, send a 500 */
        connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
        con->http_status = 500;
        con->mode = DIRECT;
      } else {
        /* response might have been already started, kill the connection */
        connection_set_state(srv, con, CON_STATE_ERROR);
      }

      joblist_append(srv, con);
      return HANDLER_FINISHED;
    }
  }

  if (revents & FDEVENT_OUT) {
    if (p->conf.debug) {
      log_error_write(srv, __FILE__, __LINE__, "sd",
          "proxy: fdevent-out", hctx->state);
    }

    if (hctx->state == GA_STATE_CONNECT ||
        hctx->state == GA_STATE_WRITE) {
      /* we are allowed to send something out
       *
       * 1. in a unfinished connect() call
       * 2. in a unfinished write() call (long POST request)
       */
      return mod_mobilega_handle_subrequest(srv, con, p);
    } else {
      log_error_write(srv, __FILE__, __LINE__, "sd",
          "proxy: out", hctx->state);
    }
  }

  /* perhaps this issue is already handled */
  if (revents & FDEVENT_HUP) {
    if (p->conf.debug) {
      log_error_write(srv, __FILE__, __LINE__, "sd",
          "proxy: fdevent-hup", hctx->state);
    }

    if (hctx->state == GA_STATE_CONNECT) {
      /* connect() -> EINPROGRESS -> HUP */

      /**
       * what is proxy is doing if it can't reach the next hop ?
       *
       */

      proxy_connection_close(srv, hctx);
      joblist_append(srv, con);

      con->http_status = 503;
      con->mode = DIRECT;

      return HANDLER_FINISHED;
    }

    con->file_finished = 1;

    proxy_connection_close(srv, hctx);
    joblist_append(srv, con);
  } else if (revents & FDEVENT_ERR) {
    /* kill all connections to the proxy process */

    log_error_write(srv, __FILE__, __LINE__, "sd", "proxy-FDEVENT_ERR, but no HUP", revents);

    joblist_append(srv, con);
    proxy_connection_close(srv, hctx);
  }

  return HANDLER_FINISHED;
}

int mod_mobilega_plugin_init(plugin *p) {
  p->version     = LIGHTTPD_VERSION_ID;
  p->name        = buffer_init_string("mobilega");

  p->init        = mod_mobilega_init;
  p->cleanup     = mod_mobilega_free;
  p->set_defaults = mod_mobilega_set_defaults;

  /* TODO: implement!! */
//  p->connection_reset        = mod_mobilega_connection_close_callback; /* end of req-resp cycle */
//  p->handle_connection_close = mod_mobilega_connection_close_callback; /* end of client connection */
//  p->handle_uri_clean        = mod_mobilega_check_extension;
  p->handle_subrequest       = mod_mobilega_handle_subrequest;
//  p->handle_trigger          = mod_mobilega_trigger;

  p->data        = NULL;

  return 0;
}
