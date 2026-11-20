// HTTP request/response parser (src/mongoose.c) as wxhelper's EventHandler / HttpDispatch
// use it (src/http_server_callback.cc): mg_http_parse, URI glob match, header/var getters,
// url-decode, multipart iteration over the body.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mongoose.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = (char *) malloc(size ? size : 1);
  if (size) memcpy(buf, data, size);
  struct mg_http_message hm;
  memset(&hm, 0, sizeof(hm));
  int n = mg_http_parse(buf, size, &hm);
  if (n > 0) {
    char tmp[256];
    (void) mg_http_match_uri(&hm, "/api/*");
    (void) mg_http_match_uri(&hm, "/websocket");
    (void) mg_vcasecmp(&hm.method, "GET");
    (void) mg_vcasecmp(&hm.method, "POST");
    struct mg_str *ct = mg_http_get_header(&hm, "Content-Type");
    if (ct != NULL) {
      struct mg_str b = mg_http_get_header_var(*ct, mg_str("boundary"));
      (void) b;
    }
    struct mg_str *cookie = mg_http_get_header(&hm, "Cookie");
    if (cookie != NULL) (void) mg_http_get_header_var(*cookie, mg_str("session"));
    (void) mg_http_get_var(&hm.query, "id", tmp, sizeof(tmp));
    // mg_http_parse sets body.len from Content-Length without checking it against len;
    // its caller (http_cb) only hands the message on once header + body are buffered.
    // Same precondition here before touching the body.
    int have_body = hm.message.len <= size;
    if (have_body) (void) mg_http_get_var(&hm.body, "port", tmp, sizeof(tmp));
    (void) mg_url_decode(hm.uri.ptr, hm.uri.len, tmp, sizeof(tmp), 0);
    (void) mg_url_decode(hm.query.ptr, hm.query.len, tmp, sizeof(tmp), 1);
    struct mg_http_part part;
    size_t ofs = 0, next;
    for (int i = 0; have_body && i < 1024; i++) {
      next = mg_http_next_multipart(hm.body, ofs, &part);
      if (next == 0 || next <= ofs) break;
      ofs = next;
    }
  }
  free(buf);
  return 0;
}
