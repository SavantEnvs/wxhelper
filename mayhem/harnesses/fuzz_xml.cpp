// tinyxml2 parser (src/tinyxml2.cpp) over message XML, walked the way
// Manager::ForwardPublicMsgByMsgId reads msg/appmsg/title, then re-printed.
#include <stdint.h>
#include <stddef.h>
#include "tinyxml2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  tinyxml2::XMLDocument doc;
  if (doc.Parse(reinterpret_cast<const char *>(data), size) == tinyxml2::XML_SUCCESS) {
    tinyxml2::XMLElement *msg = doc.FirstChildElement("msg");
    if (msg) {
      tinyxml2::XMLElement *app = msg->FirstChildElement("appmsg");
      if (app) {
        tinyxml2::XMLElement *title = app->FirstChildElement("title");
        if (title) (void) title->GetText();
        (void) app->Attribute("appid");
        (void) app->IntAttribute("sdkver");
      }
    }
    tinyxml2::XMLPrinter printer;
    doc.Print(&printer);
    tinyxml2::XMLDocument again;
    (void) again.Parse(printer.CStr(), printer.CStrSize() ? printer.CStrSize() - 1 : 0);
  }
  return 0;
}
