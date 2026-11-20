// URL / address helpers (src/mongoose.c) applied to the hookSyncMsg url/ip parameters:
// mg_url_host/port/uri/user/pass/is_ssl, mg_aton, mg_url_decode.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mongoose.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *url = (char *) malloc(size + 1);
  if (size) memcpy(url, data, size);
  url[size] = '\0';
  struct mg_str host = mg_url_host(url);
  (void) mg_url_port(url);
  (void) mg_url_uri(url);
  (void) mg_url_user(url);
  (void) mg_url_pass(url);
  (void) mg_url_is_ssl(url);
  struct mg_addr addr;
  memset(&addr, 0, sizeof(addr));
  (void) mg_aton(host, &addr);
  memset(&addr, 0, sizeof(addr));
  (void) mg_aton(mg_str_n(url, size), &addr);
  char out[512];
  (void) mg_url_decode(url, size, out, sizeof(out), 1);
  free(url);
  return 0;
}
