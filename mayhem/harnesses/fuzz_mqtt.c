// MQTT packet parser (src/mongoose.c mg_mqtt_parse + mg_mqtt_next_prop), the code
// changed by upstream 335a4771 ("fixed mqtt variable length header issue").
// Byte 0 selects the protocol version (4 = MQTT 3.1.1, 5 = MQTT 5); the rest is the packet.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mongoose.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  uint8_t version = (data[0] & 1) ? 5 : 4;
  size_t n = size - 1;
  // exact-size heap copy so ASan sees any over-read past the packet
  uint8_t *buf = (uint8_t *) malloc(n ? n : 1);
  if (n) memcpy(buf, data + 1, n);
  struct mg_mqtt_message mm;
  memset(&mm, 0, sizeof(mm));
  int rc = mg_mqtt_parse(buf, n, version, &mm);
  if (rc == MQTT_OK && version == 5) {
    struct mg_mqtt_prop prop;
    size_t ofs = 0;
    for (int i = 0; i < 4096; i++) {
      memset(&prop, 0, sizeof(prop));
      size_t next = mg_mqtt_next_prop(&mm, &prop, ofs);
      if (next == 0 || next <= ofs) break;
      ofs = next;
    }
  }
  free(buf);
  return 0;
}
