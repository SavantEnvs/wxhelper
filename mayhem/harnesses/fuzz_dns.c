// DNS response parser (src/mongoose.c mg_dns_parse / mg_dns_parse_rr), reached by the
// resolver behind HttpClient's mg_http_connect.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mongoose.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *buf = (uint8_t *) malloc(size ? size : 1);
  if (size) memcpy(buf, data, size);
  struct mg_dns_message dm;
  memset(&dm, 0, sizeof(dm));
  (void) mg_dns_parse(buf, size, &dm);
  // walk every record after the 12-byte header, as mg_dns_parse does internally
  struct mg_dns_rr rr;
  size_t ofs = sizeof(struct mg_dns_header);
  for (int i = 0; i < 256 && ofs < size; i++) {
    memset(&rr, 0, sizeof(rr));
    size_t n = mg_dns_parse_rr(buf, size, ofs, i == 0, &rr);
    if (n == 0) break;
    ofs += n;
  }
  free(buf);
  return 0;
}
