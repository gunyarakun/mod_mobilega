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
#include "stream.h"
#include "plugin.h"

#include "fdevent.h"

#include "inet_ntop_cache.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_PCRE_H
#include <pcre.h>
#endif

 /* debug */ #include <stdio.h>

#include "md5.h"

#define data_mobilega data_fastcgi
#define data_mobilega_init data_fastcgi_init

#define GAN_HOST                    "www.google-analytics.com"
#define GAN_PORT                    80
#define GAN_VERSION                 "4.4sh"
#define GAN_COOKIE_NAME             "__utmmobile"
#define GAN_COOKIE_PATH             "/"
#define GAN_COOKIE_USER_PERSISTENCE 63072000
#define GAN_UTM_GIF_PATH            "/__utm.gif"

#define GAD_HOST    "pagead2.googlesyndication.com"
#define GAD_PORT    80
#define GAD_AD_TYPE "text_image"
#define GAD_CHANNEL "4846347906"
#define GAD_CLIENT  "ca-mb-pub-6322315354375602"
#define GAD_FORMAT  "mobile_single"
#define GAD_MARKUP  "xhtml"
#define GAD_OE      "utf8"
#define GAD_OUTPUT  "xhtml"

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

  buffer *parse_response;

  data_mobilega *analytics_host;
  array *get_params;
  array *cookies;

#ifdef HAVE_PCRE_H
  pcre *analytics_regex;
#endif

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
  time_t state_timestamp;

  buffer *response;
  buffer *response_header;

  chunkqueue *wb;
  int fd; /* fd to the proxy process */
  int fde_ndx; /* index into the fd-event buffer */

  connection *remote_conn;  /* dump pointer */
  plugin_data *plugin_data; /* dump pointer */
} handler_ctx;

static handler_ctx * handler_ctx_init() {
  handler_ctx * hctx;

  hctx = calloc(1, sizeof(*hctx));

  hctx->state = GA_STATE_INIT;

  hctx->response = buffer_init();
  hctx->response_header = buffer_init();

  hctx->wb = chunkqueue_init();

  hctx->fd = -1;
  hctx->fde_ndx = -1;

  return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
  buffer_free(hctx->response);
  buffer_free(hctx->response_header);
  chunkqueue_free(hctx->wb);

  free(hctx);
}

INIT_FUNC(mod_mobilega_init) {
  plugin_data *p;
  struct hostent *he;

  /* TODO: re-query host ip address */
  if (!(he = gethostbyname(GAN_HOST))) {
    return NULL;
  }
  if (he->h_addrtype != AF_INET) {
    return NULL;
  }
  if (he->h_length != sizeof(struct in_addr)) {
    return NULL;
  }
  if ((p = calloc(1, sizeof(plugin_data)))) {
    struct in_addr ad;
    ad.s_addr = *(unsigned int *)he->h_addr_list[0];
    p->analytics_host = data_mobilega_init();
    /* TODO: save addr */
    buffer_copy_string(p->analytics_host->host, inet_ntoa(ad));
    p->analytics_host->port = GAN_PORT;
    p->get_params = array_init();
    p->cookies = array_init();
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
  if (p->cookies) {
    array_free(p->cookies);
  }
  if (p->get_params) {
    array_free(p->get_params);
  }
#ifdef HAVE_PCRE_H
  if (p->analytics_regex) {
    pcre_free(p->analytics_regex);
  }
#endif
  free(p);
  return HANDLER_GO_ON;
}

static void ga_connection_close(server *srv, handler_ctx *hctx) {
  plugin_data *p;
  connection *con;

  if (NULL == hctx) return;

  p    = hctx->plugin_data;
  con  = hctx->remote_conn;

  if (hctx->fd != -1) {
    fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
    fdevent_unregister(srv->ev, hctx->fd);

    close(hctx->fd);
    srv->cur_fds--;
  }

  handler_ctx_free(hctx);
  con->plugin_ctx[p->id] = NULL;
}

static int ga_establish_connection(server *srv, handler_ctx *hctx) {
  struct sockaddr *ga_addr;
  struct sockaddr_in ga_addr_in;
#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
  struct sockaddr_in6 ga_addr_in6;
#endif
  socklen_t servlen;

  plugin_data *p      = hctx->plugin_data;
  data_mobilega *host = p->analytics_host;
  int ga_fd           = hctx->fd;

#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
  if (strstr(host->host->ptr, ":")) {
    memset(&ga_addr_in6, 0, sizeof(ga_addr_in6));
    ga_addr_in6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, host->host->ptr, (char *) &ga_addr_in6.sin6_addr);
    ga_addr_in6.sin6_port = htons(host->port);
    servlen = sizeof(ga_addr_in6);
    ga_addr = (struct sockaddr *) &ga_addr_in6;
  } else
#endif
  {
    memset(&ga_addr_in, 0, sizeof(ga_addr_in));
    ga_addr_in.sin_family = AF_INET;
    ga_addr_in.sin_addr.s_addr = inet_addr(host->host->ptr);
    ga_addr_in.sin_port = htons(host->port);
    servlen = sizeof(ga_addr_in);
    ga_addr = (struct sockaddr *) &ga_addr_in;
  }

  if (-1 == connect(ga_fd, ga_addr, servlen)) {
    if (errno == EINPROGRESS || errno == EALREADY) {
      if (p->conf.debug) {
        log_error_write(srv, __FILE__, __LINE__, "sd",
            "connect delayed:", ga_fd);
      }

      return 1;
    } else {

      log_error_write(srv, __FILE__, __LINE__, "sdsd",
          "connect failed:", ga_fd, strerror(errno), errno);

      return -1;
    }
  }
  if (p->conf.debug) {
    log_error_write(srv, __FILE__, __LINE__, "sd",
        "connect succeeded: ", ga_fd);
  }

  return 0;
}

/* handle plugin config and check values */
SETDEFAULTS_FUNC(mod_mobilega_set_defaults) {
  plugin_data *p = p_d;
  size_t i = 0;
#ifdef HAVE_PCRE_H
  const char *errptr;
  int erroff;
#endif

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
#ifdef HAVE_PCRE_H
  /* allow 2 params */
  if (NULL == (p->analytics_regex = pcre_compile("<!--#(mobile_analytics|mobile_adsense)\\s+(?:([a-z]+)=\"(.*?)(?<!\\\\)\"\\s*)?(?:([a-z]+)=\"(.*?)(?<!\\\\)\"\\s*)?-->", 0, &errptr, &erroff, NULL))) {
    log_error_write(srv, __FILE__, __LINE__, "sds",
      "mod_mobilega: pcre ",
      erroff, errptr);
    return HANDLER_ERROR;
  }
#else
  log_error_write(srv, __FILE__, __LINE__, "s",
    "mod_mobilega: pcre support is missing, please recompile with pcre support or remove mod_mobilega from the list of modules");
  return HANDLER_ERROR;
#endif
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


static void
ga_send_request_to_google_analytics(handler_ctx *hctx, const char *path, unsigned int path_len, buffer *user_agent, data_string *accept_language)
{
  buffer *r = chunkqueue_get_append_buffer(hctx->wb);

  BUFFER_COPY_STRING_CONST(r, "GET ");
  buffer_append_string_len(r, path, path_len);
  BUFFER_APPEND_STRING_CONST(r, " HTTP/1.0");
  if (accept_language) {
    BUFFER_APPEND_STRING_CONST(r, "\r\nAccepts-Language: ");
    buffer_append_string_buffer(r, accept_language->value);
  }
  BUFFER_APPEND_STRING_CONST(r, "\r\nUser-Agent: ");
  buffer_append_string_buffer(r, user_agent);
  BUFFER_APPEND_STRING_CONST(r, "\r\n\r\n");

  if (false) {
    /* for debug */
    fprintf(stderr, "req: %.*s\n", r->used - 1, r->ptr);
  }

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

static buffer *
ga_get_visitor_id(buffer *guid, buffer *account, buffer *user_agent, buffer *cookie)
{
  buffer *message;
  if (cookie) {
    if (CONST_BUF_LEN(cookie) != 0) {
      return buffer_init_buffer(cookie);
    }
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
make_google_analytics_request(handler_ctx *hctx, connection *con, plugin_data *p)
{
  time_t timestamp;
  array *get_params = p->get_params;
  data_string *ds = NULL;
  buffer *query_str, *domain_name, *document_referer, *document_path, *account,
         *user_agent, *dcmguid, *visitor_id,
         *utm_url;
#ifdef HAVE_IPV6
  char b2[INET6_ADDRSTRLEN + 1];
#endif

  server_socket *srv_sock = con->srv_socket;

  query_str = buffer_init_buffer(con->uri.query);
  array_reset(get_params);
  split_get_params(get_params, query_str);

  // timestamp
  timestamp = time(NULL);

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
    array *cookies = p->cookies;
    array_reset(cookies);
    parse_cookie(cookies, ds->value);
    if ((ds = (data_string *)array_get_element(cookies, GAN_COOKIE_NAME))) {
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
  BUFFER_COPY_STRING_CONST(ds->value, GAN_COOKIE_NAME);
  BUFFER_APPEND_STRING_CONST(ds->value, "=");

  buffer_append_string_buffer(ds->value, visitor_id);
  BUFFER_APPEND_STRING_CONST(ds->value, "; Path=" GAN_COOKIE_PATH);
  buffer_append_string_len(ds->value, CONST_STR_LEN("; Version=1"));

  buffer_append_string_len(ds->value, CONST_STR_LEN("; max-age="));
  buffer_append_long(ds->value, GAN_COOKIE_USER_PERSISTENCE);

  array_insert_unique(con->response.headers, (data_unset *)ds);

  // Construct the gif hit url.
  utm_url = buffer_init_string(GAN_UTM_GIF_PATH "?"
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
  buffer_append_string_buffer(utm_url, account);
  BUFFER_APPEND_STRING_CONST(utm_url, "&utmcc=__utma%3D999.999.999.999.999.1%3B"
                                      "&utmvid=");
  buffer_append_string_buffer(utm_url, visitor_id);
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

  buffer_free(query_str);
  buffer_free(domain_name);
  buffer_free(document_referer);
  buffer_free(document_path);
  buffer_free(account);
  buffer_free(user_agent);
  buffer_free(dcmguid);
  buffer_free(visitor_id);
  buffer_free(utm_url);
}

static handler_t ga_handle_fdevent(void *s, void *ctx, int revents);

static int ga_set_state(server *srv, handler_ctx *hctx, ga_connection_state_t state) {
  hctx->state = state;
  hctx->state_timestamp = srv->cur_ts;

  return 0;
}

static void ga_set_header(connection *con, const char *key, const char *value) {
    data_string *ds_dst;

    if (NULL == (ds_dst = (data_string *)array_get_unused_element(con->request.headers, TYPE_STRING))) {
          ds_dst = data_string_init();
    }

    buffer_copy_string(ds_dst->key, key);
    buffer_copy_string(ds_dst->value, value);
    array_insert_unique(con->request.headers, (data_unset *)ds_dst);
}

static void ga_append_header(connection *con, const char *key, const char *value) {
    data_string *ds_dst;

    if (NULL == (ds_dst = (data_string *)array_get_unused_element(con->request.headers, TYPE_STRING))) {
          ds_dst = data_string_init();
    }

    buffer_copy_string(ds_dst->key, key);
    buffer_append_string(ds_dst->value, value);
    array_insert_unique(con->request.headers, (data_unset *)ds_dst);
}

static int ga_response_parse(server *srv, connection *con, plugin_data *p, buffer *in) {
  char *s, *ns;
  int http_response_status = -1;

  UNUSED(srv);

  /* \r\n -> \0\0 */

  buffer_copy_string_buffer(p->parse_response, in);

  for (s = p->parse_response->ptr; NULL != (ns = strstr(s, "\r\n")); s = ns + 2) {
    char *key, *value;
    int key_len;
    data_string *ds;
    int copy_header;

    ns[0] = '\0';
    ns[1] = '\0';

    if (-1 == http_response_status) {
      /* The first line of a Response message is the Status-Line */

      for (key=s; *key && *key != ' '; key++);

      if (*key) {
        http_response_status = (int) strtol(key, NULL, 10);
        if (http_response_status <= 0) http_response_status = 502;
      } else {
        http_response_status = 502;
      }

      con->http_status = http_response_status;
      con->parsed_response |= HTTP_STATUS;
      continue;
    }

    if (NULL == (value = strchr(s, ':'))) {
      /* now we expect: "<key>: <value>\n" */

      continue;
    }

    key = s;
    key_len = value - key;

    value++;
    /* strip WS */
    while (*value == ' ' || *value == '\t') value++;

    copy_header = 1;

    switch(key_len) {
    case 4:
      if (0 == strncasecmp(key, "Date", key_len)) {
        con->parsed_response |= HTTP_DATE;
      }
      break;
    case 8:
      if (0 == strncasecmp(key, "Location", key_len)) {
        con->parsed_response |= HTTP_LOCATION;
      }
      break;
    case 10:
      if (0 == strncasecmp(key, "Connection", key_len)) {
        copy_header = 0;
      }
      break;
    case 14:
      if (0 == strncasecmp(key, "Content-Length", key_len)) {
        con->response.content_length = strtol(value, NULL, 10);
        con->parsed_response |= HTTP_CONTENT_LENGTH;
      }
      break;
    default:
      break;
    }

    if (copy_header) {
      if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
        ds = data_response_init();
      }
      buffer_copy_string_len(ds->key, key, key_len);
      buffer_copy_string(ds->value, value);

      array_insert_unique(con->response.headers, (data_unset *)ds);
    }
  }

  return 0;
}

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
      switch (ga_establish_connection(srv, hctx)) {
      case 1:
        ga_set_state(srv, hctx, GA_STATE_CONNECT);

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
            "port:", p->analytics_host->port);

        return HANDLER_ERROR;
      }
      if (p->conf.debug) {
        log_error_write(srv, __FILE__, __LINE__,  "s", "mobilega - connect - delayed success");
      }
    }

    ga_set_state(srv, hctx, GA_STATE_PREPARE_WRITE);
    /* fall through */
  case GA_STATE_PREPARE_WRITE:
    make_google_analytics_request(hctx, con, p);
    ga_set_state(srv, hctx, GA_STATE_WRITE);

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
      ga_set_state(srv, hctx, GA_STATE_READ);

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
  int ga_fd       = hctx->fd;

  /* check how much we have to read */
  if (ioctl(hctx->fd, FIONREAD, &b)) {
    log_error_write(srv, __FILE__, __LINE__, "sd",
        "ioctl failed: ",
        ga_fd);
    return -1;
  }


  if (p->conf.debug) {
    log_error_write(srv, __FILE__, __LINE__, "sd",
             "mobilega - have to read:", b);
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
          "unexpected end-of-file:",
          ga_fd, strerror(errno));
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
        /* tasuku: comment out */
        //ga_response_parse(srv, con, p, hctx->response_header);

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
    "ad_type=" GAD_AD_TYPE
    "&channel=" GAD_CHANNEL
    "&client=" GAD_CLIENT
    "&format=" GAD_FORMAT
    "&markup=" GAD_MARKUP
    "&oe=" GAD_OE
    "&output=" GAD_OUTPUT);

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

#define GAN_PIXEL "/ga.gif"

static handler_t mod_mobilega_handle_uri_clean(server *srv, connection *con, void *p_d) {
  plugin_data *p = p_d;
  buffer *fn;

  if (con->mode != DIRECT) return HANDLER_GO_ON;

  /* Possibly, we processed already this request */
  if (con->file_started == 1) return HANDLER_GO_ON;

  mod_mobilega_patch_connection(srv, con, p);

  fn = con->uri.path;

  if (fn->used == 0) {
    return HANDLER_ERROR;
  }

  if (p->conf.debug) {
    log_error_write(srv, __FILE__, __LINE__,  "s", "mobilega - uri_clean");
  }

  /* if mobile_analytics, init handler-context */
  if (buffer_is_equal_string(con->uri.path, CONST_STR_LEN(GAN_PIXEL))) {
    handler_ctx *hctx = handler_ctx_init();

    hctx->remote_conn      = con;
    hctx->plugin_data      = p;

    con->plugin_ctx[p->id] = hctx;

    con->mode = p->id;
  }

  return HANDLER_GO_ON;
}

static int process_mobileanalytics_stmt(server *srv, connection *con, plugin_data *p,
          const char **l, size_t n) {
  buffer *b, *url;
  data_string *ds;
  url = buffer_init_string(GAN_PIXEL "?utmac=");
  buffer_append_string(url, l[3]);
  buffer_append_string_len(url, CONST_STR_LEN("&utmn="));
  buffer_append_long(url, random() & 0x7fffffff);
  if ((ds = (data_string *)array_get_element(con->request.headers, "Referer")) &&
      !buffer_is_empty(ds->value)) {
    buffer_append_string_len(url, CONST_STR_LEN("&utmr="));
    buffer_append_string_buffer(url, ds->value);
  } else {
    buffer_append_string_len(url, CONST_STR_LEN("&utmr=-"));
  }
  if (!buffer_is_empty(con->request.orig_uri)) {
    buffer_append_string_len(url, CONST_STR_LEN("&utmp="));
    buffer_append_string_encoded(url, CONST_BUF_LEN(con->request.orig_uri), ENCODING_REL_URI_PART);
  }
  buffer_append_string_len(url, CONST_STR_LEN("&guid=ON"));

  b = chunkqueue_get_append_buffer(con->write_queue);
  BUFFER_COPY_STRING_CONST(b, "<img src=\"");
  buffer_append_string_encoded(b, CONST_BUF_LEN(url), ENCODING_HTML);
  BUFFER_APPEND_STRING_CONST(b, "\" />");

  return 0;
}

static int mod_mobilega_handle_request(server *srv, connection *con, plugin_data *p) {
  stream s;
#ifdef  HAVE_PCRE_H
  int i, n;

#define N 10
  int ovec[N * 3];
#endif

  /* get a stream to the file */
  if (-1 == stream_open(&s, con->physical.path)) {
    log_error_write(srv, __FILE__, __LINE__, "sb",
        "stream-open: ", con->physical.path);
    return -1;
  }


  /**
   * <!--#element attribute=value attribute=value ... -->
   *
   */
#ifdef HAVE_PCRE_H
  for (i = 0; (n = pcre_exec(p->analytics_regex, NULL, s.start, s.size, i, 0, ovec, N * 3)) > 0; i = ovec[1]) {
    const char **l;
    /* take everything from last offset to current match pos */

    chunkqueue_append_file(con->write_queue, con->physical.path, i, ovec[0] - i);
    pcre_get_substring_list(s.start, ovec, n, &l);
    /* TODO: dispatch analytics/adsense with l[1] */
    process_mobileanalytics_stmt(srv, con, p, l, n);
    pcre_free_substring_list(l);
  }

  switch(n) {
  case PCRE_ERROR_NOMATCH:
    /* copy everything/the rest */
    chunkqueue_append_file(con->write_queue, con->physical.path, i, s.size - i);

    break;
  default:
    log_error_write(srv, __FILE__, __LINE__, "sd",
        "execution error while matching: ", n);
    break;
  }
#endif

  stream_close(&s);

  con->file_started  = 1;
  con->file_finished = 1;
  con->mode = p->id;

  // TODO: remove this logic
  response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("application/xhtml+xml; charset=UTF-8"));

  {
    /* Generate "ETag" & "Last-Modified" headers */

    stat_cache_entry *sce = NULL;
    buffer *mtime = NULL;

    stat_cache_get_entry(srv, con, con->physical.path, &sce);

    etag_mutate(con->physical.etag, sce->etag);
    response_header_overwrite(srv, con, CONST_STR_LEN("ETag"), CONST_BUF_LEN(con->physical.etag));

    mtime = (buffer *)strftime_cache_get(srv, sce->st.st_mtime);
    response_header_overwrite(srv, con, CONST_STR_LEN("Last-Modified"), CONST_BUF_LEN(mtime));
  }

  /* reset physical.path */
  buffer_reset(con->physical.path);

  return 0;
}

URIHANDLER_FUNC(mod_mobilega_physical_path) {
  plugin_data *p = p_d;
  size_t k;

  if (con->mode != DIRECT) return HANDLER_GO_ON;

  if (con->physical.path->used == 0) return HANDLER_GO_ON;

  /* Possibly, we processed already this request */
  if (con->file_started == 1) return HANDLER_GO_ON;

  mod_mobilega_patch_connection(srv, con, p);

  if (mod_mobilega_handle_request(srv, con, p)) {
    /* on error */
    con->http_status = 500;
    con->mode = DIRECT;
  }
  return HANDLER_FINISHED;
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
  host = p->analytics_host;

  if (con->mode != p->id) return HANDLER_GO_ON;

  switch(ga_write_request(srv, hctx)) {
  case HANDLER_ERROR:
    log_error_write(srv, __FILE__, __LINE__,  "sbdd", "google-analytics-server disabled:",
      host->host,
      host->port,
      hctx->fd);

    /* disable this server */
    host->is_disabled = 1;
    host->disable_ts = srv->cur_ts;

    ga_connection_close(srv, hctx);

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

    switch (ga_demux_response(srv, hctx)) {
    case 0:
      break;
    case 1:
      p->analytics_host->usage--;

      /* we are done */
      ga_connection_close(srv, hctx);

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

      ga_connection_close(srv, hctx);
      joblist_append(srv, con);

      con->http_status = 503;
      con->mode = DIRECT;

      return HANDLER_FINISHED;
    }

    con->file_finished = 1;

    ga_connection_close(srv, hctx);
    joblist_append(srv, con);
  } else if (revents & FDEVENT_ERR) {
    /* kill all connections to the proxy process */

    log_error_write(srv, __FILE__, __LINE__, "sd", "proxy-FDEVENT_ERR, but no HUP", revents);

    joblist_append(srv, con);
    ga_connection_close(srv, hctx);
  }

  return HANDLER_FINISHED;
}

static handler_t mod_mobilega_connection_close_callback(server *srv, connection *con, void *p_d) {
  plugin_data *p = p_d;

  ga_connection_close(srv, con->plugin_ctx[p->id]);
  return HANDLER_GO_ON;
}

int mod_mobilega_plugin_init(plugin *p) {
  p->version     = LIGHTTPD_VERSION_ID;
  p->name        = buffer_init_string("mobilega");

  p->init        = mod_mobilega_init;
  p->cleanup     = mod_mobilega_free;
  p->set_defaults = mod_mobilega_set_defaults;

  p->connection_reset        = mod_mobilega_connection_close_callback; /* end of req-resp cycle */
  p->handle_connection_close = mod_mobilega_connection_close_callback; /* end of client connection */
  p->handle_uri_clean        = mod_mobilega_handle_uri_clean;
  p->handle_subrequest_start = mod_mobilega_physical_path;
  p->handle_subrequest       = mod_mobilega_handle_subrequest;
//  p->handle_trigger          = mod_mobilega_trigger;

  p->data        = NULL;

  return 0;
}
