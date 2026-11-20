// Known-answer checks for the vendored parsers wxhelper ships in src/ (upstream has no tests).
// Prints "PASS <name>" or "FAIL <name>" per check; mayhem/test.sh counts them.
#include <cstdio>
#include <cstring>
#include <string>
#include <stdexcept>
extern "C" {
#include "mongoose.h"
}
#include "lz4.h"
#include "tinyxml2.h"
#include "base64.h"

static void check(const char *name, bool ok) { printf("%s %s\n", ok ? "PASS" : "FAIL", name); }

static bool streq(struct mg_str s, const char *v) {
  return s.len == strlen(v) && memcmp(s.ptr, v, s.len) == 0;
}

int main() {
  // base64
  check("base64_encode", base64_encode(std::string("hello world")) == "aGVsbG8gd29ybGQ=");
  check("base64_decode", base64_decode(std::string("V2VDaGF0SGVscGVy")) == "WeChatHelper");
  check("base64_url", base64_encode(std::string("\xfb\xff", 2), true) == "-_8.");
  bool threw = false;
  try { base64_decode(std::string("ab$d")); } catch (const std::exception &) { threw = true; }
  check("base64_reject", threw);

  // lz4 round trip of an XML message, then tinyxml2 walk as manager.cc does
  const char *xml = "<msg><appmsg appid=\"wx42\"><title>Hello &amp; welcome</title></appmsg></msg>";
  int xl = (int) strlen(xml) + 1;  // manager.cc parses decompress_len - 1 (stored with NUL)
  char comp[512], dec[512];
  int cl = LZ4_compress_default(xml, comp, xl, sizeof(comp));
  int dl = LZ4_decompress_safe_partial(comp, dec, cl, sizeof(dec), sizeof(dec));
  check("lz4_roundtrip", cl > 0 && dl == xl && memcmp(dec, xml, xl) == 0);
  check("lz4_reject", LZ4_decompress_safe("\xff\xff\xff", dec, 3, sizeof(dec)) < 0);
  tinyxml2::XMLDocument doc;
  bool parsed = doc.Parse(dec, dl - 1) == tinyxml2::XML_SUCCESS;
  const char *title = parsed ? doc.FirstChildElement("msg")->FirstChildElement("appmsg")
                                   ->FirstChildElement("title")->GetText() : nullptr;
  check("xml_title", title && strcmp(title, "Hello & welcome") == 0);
  const char *appid = parsed ? doc.FirstChildElement("msg")->FirstChildElement("appmsg")->Attribute("appid") : nullptr;
  check("xml_attr", appid && strcmp(appid, "wx42") == 0);
  tinyxml2::XMLDocument bad;
  check("xml_reject", bad.Parse("<msg><a></msg>") != tinyxml2::XML_SUCCESS);

  // mongoose HTTP
  const char *req = "POST /api/sendTextMsg?id=7&x=a%20b HTTP/1.1\r\nHost: x\r\n"
                    "Content-Type: application/json\r\nContent-Length: 4\r\n\r\nport=19088";
  struct mg_http_message hm;
  int hl = mg_http_parse(req, strlen(req), &hm);
  char v[64] = {0};
  check("http_parse", hl > 0 && streq(hm.method, "POST") && streq(hm.uri, "/api/sendTextMsg") &&
                          hm.body.len == 4);
  check("http_match_uri", mg_http_match_uri(&hm, "/api/*") && !mg_http_match_uri(&hm, "/websocket"));
  struct mg_str *ct = mg_http_get_header(&hm, "content-type");
  check("http_header", ct != NULL && streq(*ct, "application/json"));
  check("http_query_var", mg_http_get_var(&hm.query, "x", v, sizeof(v)) == 3 && strcmp(v, "a b") == 0);
  check("http_incomplete", mg_http_parse("GET / HTTP/1.1\r\nHost", 20, &hm) == 0);

  // mongoose MQTT v5 PUBLISH with a variable-int property (subscription id = 300)
  const uint8_t pub[] = {0x30, 0x0b, 0x00, 0x03, 'a', '/', 'b', 0x03, 0x0b, 0xac, 0x02, 'h', 'i'};
  struct mg_mqtt_message mm;
  int mr = mg_mqtt_parse(pub, sizeof(pub), 5, &mm);
  struct mg_mqtt_prop prop;
  memset(&prop, 0, sizeof(prop));
  size_t np = mr == MQTT_OK ? mg_mqtt_next_prop(&mm, &prop, 0) : 0;
  check("mqtt_parse", mr == MQTT_OK && mm.cmd == MQTT_CMD_PUBLISH && streq(mm.topic, "a/b") &&
                          streq(mm.data, "hi"));
  check("mqtt_prop_varint", np > 0 && prop.id == 0x0b && prop.iv == 300);
  check("mqtt_incomplete", mg_mqtt_parse(pub, 5, 5, &mm) == MQTT_INCOMPLETE);

  // mongoose URL + address helpers
  const char *url = "http://user:pw@127.0.0.1:19099/api/hook";
  check("url_host", streq(mg_url_host(url), "127.0.0.1"));
  check("url_port", mg_url_port(url) == 19099 && mg_url_port("https://a") == 443);
  check("url_user_pass", streq(mg_url_user(url), "user") && streq(mg_url_pass(url), "pw"));
  check("url_uri", strcmp(mg_url_uri(url), "/api/hook") == 0);
  struct mg_addr a;
  memset(&a, 0, sizeof(a));
  check("aton_ipv4", mg_aton(mg_str("10.1.2.3"), &a) && a.ip == mg_htonl(0x0a010203));
  check("aton_reject", !mg_aton(mg_str("10.1.2.300"), &a));

  // mongoose DNS: response for a.b A 1.2.3.4
  const uint8_t dns[] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
                         1, 'a', 1, 'b', 0, 0, 1, 0, 1,
                         0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4};
  struct mg_dns_message dm;
  memset(&dm, 0, sizeof(dm));
  bool dok = mg_dns_parse(dns, sizeof(dns), &dm);
  check("dns_parse", dok && dm.txnid == 0x1234 && dm.resolved && strcmp(dm.name, "a.b") == 0 &&
                         dm.addr.ip == mg_htonl(0x01020304));
  return 0;
}
