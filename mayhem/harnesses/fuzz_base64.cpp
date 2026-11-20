// base64 codec (src/base64.cpp) used on DB compress-content and image payloads.
// Byte 0 picks remove_linebreaks; decode, then check encode/decode round-trips.
#include <stdint.h>
#include <stddef.h>
#include <stdexcept>
#include <string>
#include <cstdlib>
#include "base64.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  bool lb = data[0] & 1;
  std::string in(reinterpret_cast<const char *>(data) + 1, size - 1);
  try {
    std::string dec = base64_decode(in, lb);
    (void) dec;
  } catch (const std::exception &) {
  }
  std::string enc = base64_encode(in, data[0] & 2);
  std::string pem = base64_encode_pem(in);
  std::string mime = base64_encode_mime(in);
  if (base64_decode(enc) != in) abort();
  if (base64_decode(pem, true) != in) abort();
  if (base64_decode(mime, true) != in) abort();
  return 0;
}
