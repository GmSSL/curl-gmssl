/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * Source file for all GmSSL-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 */

#include "curl_setup.h"

#ifdef USE_GMSSL

#include <gmssl/tls.h>
#include <gmssl/version.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/socket.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "vtls/cipher_suite.h"
#include "urldata.h"
#include "curl_trc.h"
#include "progress.h"
#include "vtls/gmssl.h"
#include "vtls/vtls.h"
#include "vtls/vtls_int.h"
#include "connect.h"
#include "curlx/strdup.h"
#include "curl_sha256.h"

/*
 * GmSSL backend data structure.
 *
 * GmSSL's TLS API works through raw socket file descriptors (tls_socket_t).
 * Since curl's vtls layer uses the cfilter chain abstraction, we bridge
 * the two worlds using a socket pair:
 *
 *   socks[0]  <- given to GmSSL via tls_set_socket() (GmSSL reads/writes here)
 *   socks[1]  <- our side: we read what GmSSL wrote, write data for GmSSL
 *
 * Both ends are set non-blocking. The I/O bridge functions pump data
 * between socks[1] and the cfilter chain (cf->next).
 */
struct gmssl_ssl_backend_data {
  TLS_CTX ctx;                      /* TLS context (long-lived config) */
  TLS_CONNECT conn;                 /* TLS connection (per-connection state) */
  int socks[2];                     /* socket pair for I/O bridge */
  int *ciphersuites;                /* configured cipher suites array */
  size_t ciphersuites_cnt;          /* number of cipher suites */
  const char *alpn_protocols[3];    /* ALPN protocol strings (kept alive) */
  size_t alpn_protocols_cnt;        /* count of ALPN protocols */
  BIT(initialized);                 /* TLS connection initialized */
  BIT(ctx_initialized);             /* TLS context initialized */
  BIT(sockpair_created);            /* socket pair created */
};

/* --- I/O Bridge Functions --- */

/*
 * Drain outgoing encrypted data from the socket pair:
 * read from socks[1] (what GmSSL wrote to socks[0]) and send it
 * through the cfilter chain to the network.
 */
static CURLcode gmssl_bridge_drain_send(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct gmssl_ssl_backend_data *backend)
{
  unsigned char buf[16384];
  ssize_t nread;
  size_t nwritten;
  CURLcode result;

  /* Try to read what GmSSL wrote to socks[0] */
  nread = read(backend->socks[1], buf, sizeof(buf));
  if(nread <= 0) {
    if(errno == EAGAIN || errno == EWOULDBLOCK)
      return CURLE_OK; /* no data to drain */
    return CURLE_OK;
  }

  result = Curl_conn_cf_send(cf->next, data, (const char *)buf,
                              (size_t)nread, FALSE, &nwritten);
  if(result == CURLE_AGAIN) {
    /* Could not send everything. Data may be lost. */
    (void)nwritten;
    return CURLE_AGAIN;
  }
  return result;
}

/*
 * Feed incoming network data into the socket pair:
 * write to socks[1] so GmSSL can read it from socks[0].
 */
static CURLcode gmssl_bridge_feed_recv(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct gmssl_ssl_backend_data *backend,
                                        const unsigned char *buf, size_t len)
{
  ssize_t nwritten;

  (void)cf;
  (void)data;

  if(len == 0)
    return CURLE_OK;

  nwritten = write(backend->socks[1], buf, len);
  if(nwritten < 0) {
    if(errno == EAGAIN || errno == EWOULDBLOCK)
      return CURLE_AGAIN;
    return CURLE_SEND_ERROR;
  }

  return CURLE_OK;
}

/*
 * Perform the TLS handshake using the socket pair bridge.
 * GmSSL does I/O through socks[0]; we bridge socks[1] <-> cfilter chain.
 *
 * Returns CURLE_OK on success or when more I/O is needed (io_need set).
 * Returns error code on failure.
 */
static CURLcode gmssl_do_handshake_bridge(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct gmssl_ssl_backend_data *backend)
{
  struct ssl_connect_data *connssl = cf->ctx;
  int ret;

  for(;;) {
    ret = tls_do_handshake(&backend->conn);

    if(ret == 1) {
      /* Handshake complete -- drain any remaining outgoing data */
      CURLcode result = gmssl_bridge_drain_send(cf, data, backend);
      if(result == CURLE_AGAIN) {
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        return CURLE_OK;
      }
      if(result)
        return result;
      connssl->io_need = CURL_SSL_IO_NEED_NONE;
      return CURLE_OK;
    }
    else if(ret == TLS_ERROR_RECV_AGAIN) {
      /* GmSSL wants more data. First drain any pending outgoing data. */
      CURLcode result = gmssl_bridge_drain_send(cf, data, backend);
      if(result == CURLE_AGAIN) {
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        return CURLE_OK;
      }
      if(result)
        return result;

      /* Now try to read from the network and feed GmSSL */
      {
        unsigned char buf[16384];
        size_t nread = 0;
        result = Curl_conn_cf_recv(cf->next, data, (char *)buf,
                                    sizeof(buf), &nread);
        if(result == CURLE_AGAIN) {
          connssl->io_need = CURL_SSL_IO_NEED_RECV;
          return CURLE_OK;
        }
        if(result)
          return result;
        if(nread > 0) {
          result = gmssl_bridge_feed_recv(cf, data, backend, buf, nread);
          if(result == CURLE_AGAIN) {
            /* socket pair buffer is full; will retry */
          }
          else if(result)
            return result;
        }
      }
      /* Loop to retry handshake with the new data */
    }
    else if(ret == TLS_ERROR_SEND_AGAIN) {
      /* GmSSL has data to send. Drain through cfilter. */
      CURLcode result = gmssl_bridge_drain_send(cf, data, backend);
      if(result == CURLE_AGAIN) {
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        return CURLE_OK;
      }
      if(result)
        return result;
      /* Loop to retry handshake */
    }
    else {
      /* Real handshake error */
      CURL_TRC_CF(data, cf, "GmSSL: tls_do_handshake error %d", ret);
      failf(data, "GmSSL: handshake failed");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
}

/* --- Cipher Suite Configuration --- */

static const int gmssl_supported_ciphers[] = {
  /* TLS 1.3 cipher suites */
  TLS_cipher_sm4_gcm_sm3,                       /* 0x00c6 */
  TLS_cipher_aes_128_gcm_sha256,                /* 0x1301 */
  /* TLS 1.2 cipher suites */
  TLS_cipher_ecdhe_sm4_gcm_sm3,                 /* 0xe051 */
  TLS_cipher_ecdhe_sm4_cbc_sm3,                 /* 0xe011 */
  TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256, /* 0xc02b */
  TLS_cipher_ecdhe_ecdsa_with_aes_128_cbc_sha256, /* 0xc023 */
  0  /* sentinel */
};

static const size_t gmssl_supported_ciphers_len =
  sizeof(gmssl_supported_ciphers) / sizeof(gmssl_supported_ciphers[0]) - 1;

/* Default cipher suites (TLS 1.3 preferred, GM first, then standard) */
static const int gmssl_default_ciphers[] = {
  TLS_cipher_sm4_gcm_sm3,                       /* 0x00c6 */
  TLS_cipher_aes_128_gcm_sha256,                /* 0x1301 */
  TLS_cipher_ecdhe_sm4_gcm_sm3,                 /* 0xe051 */
  TLS_cipher_ecdhe_ecdsa_with_aes_128_gcm_sha256, /* 0xc02b */
  0
};

static CURLcode gmssl_set_selected_ciphers(struct Curl_easy *data,
                                            struct gmssl_ssl_backend_data *backend,
                                            const char *ciphers12,
                                            const char *ciphers13)
{
  const char *ciphers = ciphers13 ? ciphers13 :
                        (ciphers12 ? ciphers12 : NULL);
  int *selected = NULL;
  size_t count = 0;
  size_t i;

  if(!ciphers) {
    /* No cipher list specified -- use our default list */
    if(tls_ctx_set_cipher_suites(&backend->ctx, gmssl_default_ciphers,
        sizeof(gmssl_default_ciphers) / sizeof(gmssl_default_ciphers[0]) - 1) != 1) {
      failf(data, "GmSSL: failed to set default cipher suites");
      return CURLE_SSL_CIPHER;
    }
    return CURLE_OK;
  }

  /* Allocate space for all supported ciphers plus sentinel */
  selected = curlx_malloc(sizeof(int) * (gmssl_supported_ciphers_len + 1));
  if(!selected)
    return CURLE_OUT_OF_MEMORY;

  /* Parse cipher list string using curl's cipher suite walker */
  {
    const char *ptr, *end;
    for(ptr = ciphers; ptr[0] != '\0' && count < gmssl_supported_ciphers_len;
        ptr = end) {
      uint16_t id = Curl_cipher_suite_walk_str(&ptr, &end);

      if(!id) {
        if(ptr[0] != '\0')
          infof(data, "GmSSL: unknown cipher in list: \"%.*s\"",
                (int)(end - ptr), ptr);
        continue;
      }

      /* Check if this cipher is in our supported list */
      for(i = 0; i < gmssl_supported_ciphers_len; i++) {
        if(gmssl_supported_ciphers[i] == (int)id) {
          /* Check for duplicates */
          size_t j;
          for(j = 0; j < count && selected[j] != (int)id; j++)
            ;
          if(j >= count)
            selected[count++] = (int)id;
          break;
        }
      }
      if(i >= gmssl_supported_ciphers_len) {
        infof(data, "GmSSL: unsupported cipher in list: \"%.*s\"",
              (int)(end - ptr), ptr);
      }
    }
  }

  if(count == 0) {
    curlx_free(selected);
    failf(data, "GmSSL: no supported cipher suite in requested list");
    return CURLE_SSL_CIPHER;
  }

  selected[count] = 0;

  if(tls_ctx_set_cipher_suites(&backend->ctx, selected, count) != 1) {
    curlx_free(selected);
    failf(data, "GmSSL: failed to set cipher suites");
    return CURLE_SSL_CIPHER;
  }

  backend->ciphersuites = selected;
  backend->ciphersuites_cnt = count;
  return CURLE_OK;
}

/* --- TLS Context Initialization --- */

static CURLcode gmssl_ctx_setup(struct Curl_easy *data,
                                 struct gmssl_ssl_backend_data *backend,
                                 struct ssl_primary_config *conn_config)
{
  int protocol;

  /* Select protocol version */
  switch(conn_config->version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1_3:
    protocol = TLS_protocol_tls13;
    break;
  case CURL_SSLVERSION_TLSv1_2:
    protocol = TLS_protocol_tls12;
    break;
  default:
    failf(data, "GmSSL: unsupported TLS version: %x", conn_config->version);
    return CURLE_SSL_CONNECT_ERROR;
  }

  (void)conn_config->version_max;

  if(tls_ctx_init(&backend->ctx, protocol, 1) != 1) {
    failf(data, "GmSSL: failed to init TLS context");
    return CURLE_SSL_CONNECT_ERROR;
  }
  backend->ctx_initialized = TRUE;

  /* Set supported elliptic curve groups (SM2 and P256) */
  {
    int supported_groups[] = {
      TLS_curve_secp256r1,     /* P256 first — most servers support this */
      TLS_curve_sm2p256v1,     /* SM2 second — for GM servers */
    };
    if(tls_ctx_set_supported_groups(&backend->ctx, supported_groups,
        sizeof(supported_groups) / sizeof(supported_groups[0])) != 1) {
      failf(data, "GmSSL: failed to set supported groups");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Set signature algorithms (SM2+SM3 and ECDSA+SHA256) */
  {
    int sig_algs[] = {
      TLS_sig_ecdsa_secp256r1_sha256,
      TLS_sig_sm2sig_sm3,
    };
    if(tls_ctx_set_signature_algorithms(&backend->ctx, sig_algs,
        sizeof(sig_algs) / sizeof(sig_algs[0])) != 1) {
      failf(data, "GmSSL: failed to set signature algorithms");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  return CURLE_OK;
}

/* --- Certificate Loading --- */

static CURLcode gmssl_write_temp_file(struct Curl_easy *data,
                                       const char *prefix,
                                       const unsigned char *buf, size_t len,
                                       char **tempname)
{
  int fd;
  ssize_t nwritten;
  const char *tmpdir;

  (void)data;

  tmpdir = getenv("TMPDIR");
  if(!tmpdir)
    tmpdir = "/tmp";

  *tempname = curlx_malloc(strlen(tmpdir) + strlen(prefix) + 16);
  if(!*tempname)
    return CURLE_OUT_OF_MEMORY;

  curl_msnprintf(*tempname, strlen(tmpdir) + strlen(prefix) + 16,
                 "%s/%s-XXXXXX", tmpdir, prefix);

  fd = mkstemp(*tempname);
  if(fd < 0) {
    curlx_free(*tempname);
    *tempname = NULL;
    return CURLE_SSL_CERTPROBLEM;
  }

  nwritten = write(fd, buf, len);
  close(fd);

  if(nwritten < 0 || (size_t)nwritten != len) {
    unlink(*tempname);
    curlx_free(*tempname);
    *tempname = NULL;
    return CURLE_WRITE_ERROR;
  }

  return CURLE_OK;
}

/* Load CA certificates */
static CURLcode gmssl_load_cacert(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  const char *ssl_cafile = conn_config->CAfile;
  const bool verifypeer = conn_config->verifypeer;
  int ret;

  if(!verifypeer)
    return CURLE_OK;

  /* Handle CA info blob via temp file */
  if(ca_info_blob && ca_info_blob->len > 0) {
    char *tempname = NULL;
    CURLcode result;

    result = gmssl_write_temp_file(data, "gmssl-ca",
                                    (const unsigned char *)ca_info_blob->data,
                                    ca_info_blob->len, &tempname);
    if(result)
      return result;

    ret = tls_ctx_set_ca_certificates(&backend->ctx, tempname,
                                       TLS_DEFAULT_VERIFY_DEPTH);
    unlink(tempname);
    curlx_free(tempname);

    if(ret != 1) {
      failf(data, "GmSSL: error loading CA cert blob");
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Handle CA file */
  if(ssl_cafile && verifypeer) {
    ret = tls_ctx_set_ca_certificates(&backend->ctx, ssl_cafile,
                                       TLS_DEFAULT_VERIFY_DEPTH);
    if(ret != 1) {
      failf(data, "GmSSL: error reading CA cert file %s", ssl_cafile);
      return CURLE_SSL_CACERT_BADFILE;
    }
  }

  return CURLE_OK;
}

/* Load client certificate and private key */
static CURLcode gmssl_load_clicert(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const char *ssl_cert = ssl_config->primary.clientcert;
  const struct curl_blob *ssl_cert_blob = ssl_config->primary.cert_blob;
  const char *ssl_key = ssl_config->key;
  int ret;

  if(!ssl_cert && !ssl_cert_blob)
    return CURLE_OK;  /* No client certificate configured */

  if(ssl_cert) {
    /* File-based client certificate */
    if(!ssl_key) {
      failf(data, "GmSSL: client cert requires private key");
      return CURLE_SSL_CERTPROBLEM;
    }
    ret = tls_ctx_set_certificate_and_key(&backend->ctx,
                                           ssl_cert,
                                           ssl_key,
                                           ssl_config->key_passwd);
    if(ret != 1) {
      failf(data, "GmSSL: error setting client certificate/key");
      return CURLE_SSL_CERTPROBLEM;
    }
  }
  else if(ssl_cert_blob) {
    /* Blob-based client certificate */
    char *cert_tempname = NULL;
    char *key_tempname = NULL;
    CURLcode result;

    result = gmssl_write_temp_file(data, "gmssl-cert",
                                    (const unsigned char *)ssl_cert_blob->data,
                                    ssl_cert_blob->len, &cert_tempname);
    if(result)
      return result;

    if(ssl_config->key_blob) {
      result = gmssl_write_temp_file(data, "gmssl-key",
                                      (const unsigned char *)ssl_config->key_blob->data,
                                      ssl_config->key_blob->len, &key_tempname);
      if(result) {
        unlink(cert_tempname);
        curlx_free(cert_tempname);
        return result;
      }
    }

    ret = tls_ctx_set_certificate_and_key(&backend->ctx,
                                           cert_tempname,
                                           key_tempname ? key_tempname : ssl_key,
                                           ssl_config->key_passwd);

    unlink(cert_tempname);
    curlx_free(cert_tempname);
    if(key_tempname) {
      unlink(key_tempname);
      curlx_free(key_tempname);
    }

    if(ret != 1) {
      failf(data, "GmSSL: error setting client cert/key from blob");
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  return CURLE_OK;
}

/* --- ALPN Configuration --- */

static CURLcode gmssl_set_alpn(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct gmssl_ssl_backend_data *backend)
{
  struct ssl_connect_data *connssl = cf->ctx;
  size_t i;

  if(!connssl->alpn || connssl->alpn->count == 0)
    return CURLE_OK;

  /* Build protocol string array from alpn spec */
  for(i = 0; i < connssl->alpn->count && i < 3; i++) {
    backend->alpn_protocols[i] = connssl->alpn->entries[i];
  }
  backend->alpn_protocols_cnt = connssl->alpn->count;

  if(tls_ctx_set_application_layer_protocol_negotiation(
       &backend->ctx,
       (char **)(void *)backend->alpn_protocols,
       backend->alpn_protocols_cnt) != 1) {
    failf(data, "GmSSL: failed to set ALPN protocols");
    return CURLE_SSL_CONNECT_ERROR;
  }

  {
    struct alpn_proto_buf proto;
    Curl_alpn_to_proto_str(&proto, connssl->alpn);
    infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
  }

  return CURLE_OK;
}

/* --- Socket Pair Setup --- */

static CURLcode gmssl_create_sockpair(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       struct gmssl_ssl_backend_data *backend)
{
  int rc;
  int flags;

  if(backend->sockpair_created)
    return CURLE_OK;

  backend->socks[0] = -1;
  backend->socks[1] = -1;

  rc = socketpair(AF_UNIX, SOCK_STREAM, 0, backend->socks);
  if(rc < 0) {
    failf(data, "GmSSL: failed to create socket pair for I/O bridge");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Set both ends non-blocking */
  flags = fcntl(backend->socks[0], F_GETFL, 0);
  if(flags >= 0)
    fcntl(backend->socks[0], F_SETFL, flags | O_NONBLOCK);

  flags = fcntl(backend->socks[1], F_GETFL, 0);
  if(flags >= 0)
    fcntl(backend->socks[1], F_SETFL, flags | O_NONBLOCK);

  /* Increase socket buffer sizes for better throughput */
  {
    int sndbuf = 256 * 1024;
    int rcvbuf = 256 * 1024;
    setsockopt(backend->socks[0], SOL_SOCKET, SO_SNDBUF,
               &sndbuf, sizeof(sndbuf));
    setsockopt(backend->socks[0], SOL_SOCKET, SO_RCVBUF,
               &rcvbuf, sizeof(rcvbuf));
    setsockopt(backend->socks[1], SOL_SOCKET, SO_SNDBUF,
               &sndbuf, sizeof(sndbuf));
    setsockopt(backend->socks[1], SOL_SOCKET, SO_RCVBUF,
               &rcvbuf, sizeof(rcvbuf));
  }

  /* Give GmSSL one end of the pair */
  tls_set_socket(&backend->conn, (tls_socket_t)backend->socks[0]);
  backend->sockpair_created = TRUE;

  return CURLE_OK;
}

/* --- Connect / Handshake --- */

static CURLcode gmssl_connect_step1(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  CURLcode result;

  /* Reject SSLv2/SSLv3/TLSv1.0/TLSv1.1 */
  if(conn_config->version == CURL_SSLVERSION_SSLv2 ||
     conn_config->version == CURL_SSLVERSION_SSLv3 ||
     conn_config->version == CURL_SSLVERSION_TLSv1 ||
     conn_config->version == CURL_SSLVERSION_TLSv1_0 ||
     conn_config->version == CURL_SSLVERSION_TLSv1_1) {
    failf(data, "GmSSL: SSLv2/SSLv3/TLSv1.0/TLSv1.1 not supported");
    return CURLE_NOT_BUILT_IN;
  }

  /* Initialize TLS context with proper protocol version */
  result = gmssl_ctx_setup(data, backend, conn_config);
  if(result)
    return result;

  /* Load CA certificates */
  result = gmssl_load_cacert(cf, data);
  if(result)
    return result;

  /* Load client cert+key */
  result = gmssl_load_clicert(cf, data);
  if(result)
    return result;

  /* Configure ALPN */
  result = gmssl_set_alpn(cf, data, backend);
  if(result)
    return result;

  /* Always configure cipher suites -- GmSSL requires at least one */
  result = gmssl_set_selected_ciphers(data, backend,
                                       conn_config->cipher_list,
                                       conn_config->cipher_list13);
  if(result) {
    failf(data, "GmSSL: failed to set cipher suites");
    return result;
  }

  /* Give application a chance to configure GmSSL context */
  if(data->set.ssl.fsslctx) {
    result = (*data->set.ssl.fsslctx)(data, &backend->ctx,
                                       data->set.ssl.fsslctxp);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }

  /* Initialize TLS connection */
  if(tls_init(&backend->conn, &backend->ctx) != 1) {
    failf(data, "GmSSL: tls_init failed");
    return CURLE_SSL_CONNECT_ERROR;
  }
  backend->initialized = TRUE;

  /* Create socket pair for I/O bridge */
  result = gmssl_create_sockpair(cf, data, backend);
  if(result)
    return result;

  /* Set SNI hostname */
  if(connssl->peer.sni) {
    tls_set_server_name(&backend->conn,
                        (const uint8_t *)connssl->peer.sni,
                        strlen(connssl->peer.sni));
  }
  else if(connssl->peer.hostname &&
          connssl->peer.type == CURL_SSL_PEER_DNS) {
    tls_set_server_name(&backend->conn,
                        (const uint8_t *)connssl->peer.hostname,
                        strlen(connssl->peer.hostname));
  }

  infof(data, "GmSSL: Connecting to %s:%d",
        connssl->peer.hostname, connssl->peer.port);

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static CURLcode gmssl_connect_step2(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;
  CURLcode result;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);

  DEBUGASSERT(backend);

  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  /* Perform handshake via socket pair bridge */
  result = gmssl_do_handshake_bridge(cf, data, backend);
  if(result)
    return result;

  /* Bridge returns CURLE_OK; check if handshake needs more I/O */
  if(connssl->io_need != CURL_SSL_IO_NEED_NONE) {
    /* Handshake still in progress; caller will poll and call us again */
    return CURLE_OK;
  }

  /* Handshake complete -- report cipher suite */
  {
    const char *cipher_name;
    cipher_name = tls_cipher_suite_name(backend->conn.cipher_suite);
    infof(data, "GmSSL: %s Handshake complete, cipher is %s",
          (backend->conn.protocol == TLS_protocol_tls13) ? "TLSv1.3" : "TLSv1.2",
          cipher_name ? cipher_name : "unknown");
  }

  /* Check certificate verification result */
  if(conn_config->verifypeer) {
    if(backend->conn.verify_result != 0) {
      failf(data, "GmSSL: certificate verification failed (result=%d)",
            backend->conn.verify_result);
      return CURLE_PEER_FAILED_VERIFICATION;
    }
  }

  /* Handle ALPN result */
  if(connssl->alpn && backend->conn.alpn_selected) {
    result = Curl_alpn_set_negotiated(cf, data, connssl,
                             (const unsigned char *)backend->conn.alpn_selected,
                             strlen(backend->conn.alpn_selected));
    if(result)
      return result;
  }

  infof(data, "SSL connected");
  connssl->connecting_state = ssl_connect_3;
  return CURLE_OK;
}

static CURLcode gmssl_connect(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool *done)
{
  CURLcode result;
  struct ssl_connect_data *connssl = cf->ctx;

  /* Check if already connected */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  if(ssl_connect_1 == connssl->connecting_state) {
    result = gmssl_connect_step1(cf, data);
    if(result)
      return result;
  }

  if(ssl_connect_2 == connssl->connecting_state) {
    result = gmssl_connect_step2(cf, data);
    if(result)
      return result;
  }

  if(ssl_connect_3 == connssl->connecting_state) {
    connssl->connecting_state = ssl_connect_done;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    connssl->handshake_done = *Curl_pgrs_now(data);
    *done = TRUE;
  }

  return CURLE_OK;
}

/* --- Data Send / Receive --- */

static CURLcode gmssl_send_plain(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  const void *mem, size_t len,
                                  size_t *pnwritten)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;
  size_t sentlen;
  int ret;

  DEBUGASSERT(backend);
  *pnwritten = 0;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  ret = tls_send(&backend->conn, (const uint8_t *)mem, len, &sentlen);

  if(ret == 1) {
    /* tls_send wrote encrypted data to socks[0]; drain from socks[1]
     * and send through cfilter chain. */
    CURLcode result = gmssl_bridge_drain_send(cf, data, backend);
    if(result == CURLE_AGAIN) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
      return CURLE_AGAIN;
    }
    if(result) {
      *pnwritten = sentlen;
      return result;
    }
    *pnwritten = sentlen;
    return CURLE_OK;
  }
  else if(ret == TLS_ERROR_RECV_AGAIN) {
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    return CURLE_AGAIN;
  }
  else if(ret == TLS_ERROR_SEND_AGAIN) {
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
    return CURLE_AGAIN;
  }
  else {
    CURL_TRC_CF(data, cf, "GmSSL: tls_send error %d", ret);
    return CURLE_SEND_ERROR;
  }
}

static CURLcode gmssl_recv_plain(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  char *buf, size_t buffersize,
                                  size_t *pnread)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;
  size_t recvlen;
  int ret;

  DEBUGASSERT(backend);
  *pnread = 0;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  /* First, try to feed any available network data to GmSSL */
  {
    unsigned char netbuf[16384];
    size_t nread = 0;
    CURLcode result = Curl_conn_cf_recv(cf->next, data, (char *)netbuf,
                                         sizeof(netbuf), &nread);
    if(result == CURLE_OK && nread > 0) {
      gmssl_bridge_feed_recv(cf, data, backend, netbuf, nread);
    }
  }

  /* Try to read decrypted data from GmSSL */
  ret = tls_recv(&backend->conn, (uint8_t *)buf, buffersize, &recvlen);

  if(ret == 1) {
    *pnread = recvlen;
    if(recvlen == 0) {
      CURL_TRC_CF(data, cf, "GmSSL: tls_recv returned 0 bytes (EOF)");
      connssl->peer_closed = TRUE;
      return CURLE_OK;
    }
    return CURLE_OK;
  }
  else if(ret == 0) {
    CURL_TRC_CF(data, cf, "GmSSL: tls_recv returned close_notify");
    connssl->peer_closed = TRUE;
    return CURLE_OK;
  }
  else if(ret == TLS_ERROR_RECV_AGAIN) {
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    return CURLE_AGAIN;
  }
  else if(ret == TLS_ERROR_SEND_AGAIN) {
    /* GmSSL wants to send (e.g., new session ticket).
     * Drain the outgoing bridge data. */
    CURLcode result = gmssl_bridge_drain_send(cf, data, backend);
    if(result == CURLE_AGAIN) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
      return CURLE_AGAIN;
    }
    if(result)
      return result;
    return CURLE_AGAIN;
  }
  else if(ret == TLS_ERROR_TCP_CLOSED) {
    CURL_TRC_CF(data, cf, "GmSSL: peer closed connection");
    connssl->peer_closed = TRUE;
    return CURLE_OK;
  }
  else {
    CURL_TRC_CF(data, cf, "GmSSL: tls_recv error %d", ret);
    return CURLE_RECV_ERROR;
  }
}

/* --- Shutdown --- */

static CURLcode gmssl_shutdown(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;

  DEBUGASSERT(backend);

  if(!backend->initialized || cf->shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  *done = FALSE;

  if(send_shutdown) {
    int ret = tls_shutdown(&backend->conn);

    if(ret == 1 || ret == 0) {
      gmssl_bridge_drain_send(cf, data, backend);
      *done = TRUE;
    }
    else if(ret == TLS_ERROR_RECV_AGAIN) {
      connssl->io_need = CURL_SSL_IO_NEED_RECV;
    }
    else if(ret == TLS_ERROR_SEND_AGAIN) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
    }
    else {
      CURL_TRC_CF(data, cf, "GmSSL: shutdown error %d", ret);
      *done = TRUE;
    }
  }
  else {
    *done = TRUE;
  }

  cf->shutdown = (*done);
  return CURLE_OK;
}

/* --- Close / Cleanup --- */

static void gmssl_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;

  (void)data;

  if(!backend)
    return;

  if(backend->initialized) {
    tls_cleanup(&backend->conn);
    backend->initialized = FALSE;
  }

  if(backend->ctx_initialized) {
    tls_ctx_cleanup(&backend->ctx);
    backend->ctx_initialized = FALSE;
  }

  if(backend->sockpair_created) {
    if(backend->socks[0] >= 0) {
      sclose(backend->socks[0]);
      backend->socks[0] = -1;
    }
    if(backend->socks[1] >= 0) {
      sclose(backend->socks[1]);
      backend->socks[1] = -1;
    }
    backend->sockpair_created = FALSE;
  }

  curlx_free(backend->ciphersuites);
  backend->ciphersuites = NULL;
  backend->ciphersuites_cnt = 0;
}

/* --- Other Required Functions --- */

static int gmssl_init(void)
{
  return 1;
}

static void gmssl_cleanup(void)
{
}

static size_t gmssl_version(char *buffer, size_t size)
{
  return curl_msnprintf(buffer, size, "GmSSL/%s", GMSSL_VERSION_STR);
}

static bool gmssl_data_pending(struct Curl_cfilter *cf,
                                const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gmssl_ssl_backend_data *backend;

  (void)data;

  if(!connssl || !connssl->backend)
    return FALSE;

  backend = (struct gmssl_ssl_backend_data *)connssl->backend;

  if(backend && backend->sockpair_created) {
    int available = 0;
    if(ioctl(backend->socks[1], FIONREAD, &available) == 0 && available > 0)
      return TRUE;
  }
  return FALSE;
}

static CURLcode gmssl_random(struct Curl_easy *data,
                              unsigned char *entropy, size_t length)
{
  (void)data;
  if(rand_bytes(entropy, length) != 1)
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static CURLcode gmssl_sha256sum(const unsigned char *input, size_t inputlen,
                                 unsigned char *sha256sum, size_t sha256sumlen)
{
  (void)sha256sumlen;
  return Curl_sha256it(sha256sum, input, inputlen);
}

static void *gmssl_get_internals(struct ssl_connect_data *connssl,
                                  CURLINFO info)
{
  struct gmssl_ssl_backend_data *backend =
    (struct gmssl_ssl_backend_data *)connssl->backend;
  (void)info;
  DEBUGASSERT(backend);
  return &backend->conn;
}

/* --- Backend Registration --- */

const struct Curl_ssl Curl_ssl_gmssl = {
  { CURLSSLBACKEND_GMSSL, "gmssl" }, /* info */

  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST |
  SSLSUPP_TLS13_CIPHERSUITES |
  0,

  sizeof(struct gmssl_ssl_backend_data),

  gmssl_init,                /* init */
  gmssl_cleanup,             /* cleanup */
  gmssl_version,             /* version */
  gmssl_shutdown,            /* shutdown */
  gmssl_data_pending,        /* data_pending */
  gmssl_random,              /* random */
  NULL,                      /* cert_status_request */
  gmssl_connect,             /* connect */
  Curl_ssl_adjust_pollset,   /* adjust_pollset */
  gmssl_get_internals,       /* get_internals */
  gmssl_close,               /* close_one */
  NULL,                      /* close_all */
  NULL,                      /* set_engine */
  NULL,                      /* set_engine_default */
  NULL,                      /* engines_list */
  gmssl_sha256sum,           /* sha256sum */
  gmssl_recv_plain,          /* recv decrypted data */
  gmssl_send_plain,          /* send data to encrypt */
  NULL,                      /* get_channel_binding */
};

#endif /* USE_GMSSL */
