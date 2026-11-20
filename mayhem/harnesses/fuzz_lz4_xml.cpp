// Public-message compress-content chain from Manager::ForwardPublicMsgByMsgId
// (src/manager.cc): LZ4_decompress_safe_partial into a len<<8 buffer, then tinyxml2 Parse.
// The raw LZ4 block is the input (the base64 layer has its own target, fuzz_base64).
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "lz4.h"
#include "tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // manager.cc allocates len<<8; bound it so the allocation stays sane (64 KiB << 8 = 16 MiB).
  if (size == 0 || size > 65536) return -1;
  char *src = new char[size];
  memcpy(src, data, size);
  int dst_len = static_cast<int>(size << 8);
  char *dst = new char[dst_len];
  int n = LZ4_decompress_safe_partial(src, dst, static_cast<int>(size), dst_len, dst_len);
  if (n > 0) {
    tinyxml2::XMLDocument doc;
    if (doc.Parse(dst, n - 1) == tinyxml2::XML_SUCCESS) {
      tinyxml2::XMLElement *msg = doc.FirstChildElement("msg");
      tinyxml2::XMLElement *app = msg ? msg->FirstChildElement("appmsg") : nullptr;
      tinyxml2::XMLElement *title = app ? app->FirstChildElement("title") : nullptr;
      if (title) (void) title->GetText();
    }
  }
  (void) LZ4_decompress_safe(src, dst, static_cast<int>(size), dst_len);
  delete[] dst;
  delete[] src;
  return 0;
}
