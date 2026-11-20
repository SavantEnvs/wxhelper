// mongoose server connection state machine over a real loopback socket, with an event
// handler mirroring wxhelper's EventHandler (src/http_server_callback.cc): upgrade on
// /websocket and echo WebSocket frames, reply to /api/* and anything else with JSON.
// Each input is the byte stream one client sends; it reaches http_cb (request framing,
// pipelining, chunked bodies), mg_ws_upgrade (sha1/base64 handshake) and the WS frame parser.
//
// State kept across inputs: the mgr and its listening socket only. Every input gets a
// fresh client connection, and the harness polls until the server side of it is closed.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "mongoose.h"

static struct mg_mgr mgr;
static struct mg_connection *listener;

static void handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (mg_http_match_uri(hm, "/websocket")) {
      mg_ws_upgrade(c, hm, NULL);
    } else if (mg_http_match_uri(hm, "/api/*")) {
      struct mg_str *ct = mg_http_get_header(hm, "Content-Type");
      mg_http_reply(c, 200, "Content-Type: application/json\r\n",
                    "{\"code\":200,\"method\":\"%.*s\",\"ct\":%d,\"len\":%d}\n",
                    (int) hm->method.len, hm->method.ptr, ct != NULL,
                    (int) hm->body.len);
    } else {
      mg_http_reply(c, 200, "Content-Type: application/json\r\n",
                    "{\"code\":400,\"msg\":\"invalid url, please check url\"}\n");
    }
  } else if (ev == MG_EV_WS_MSG) {
    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
    mg_ws_send(c, wm->data.ptr, wm->data.len, WEBSOCKET_OP_TEXT);
  }
  (void) fn_data;
}

static size_t nconns(void) {
  size_t n = 0;
  for (struct mg_connection *c = mgr.conns; c != NULL; c = c->next) n++;
  return n;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void) argc;
  (void) argv;
  mg_log_set(MG_LL_NONE);
  mg_mgr_init(&mgr);
  listener = mg_http_listen(&mgr, "http://127.0.0.1:0", handler, NULL);
  if (listener == NULL) abort();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) abort();
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = listener->loc.port;  // network byte order, filled by getsockname
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) != 0) abort();
  // accept the connection before sending
  for (int i = 0; i < 100 && nconns() < 2; i++) mg_mgr_poll(&mgr, 1);
  size_t off = 0;
  while (off < size) {
    ssize_t w = send(fd, data + off, size - off, MSG_NOSIGNAL);
    if (w <= 0) break;
    off += (size_t) w;
    mg_mgr_poll(&mgr, 0);
  }
  // let the server consume everything, then hang up and wait for it to close its side
  for (int i = 0; i < 8; i++) mg_mgr_poll(&mgr, 1);
  shutdown(fd, SHUT_WR);
  char sink[4096];
  for (int i = 0; i < 200 && nconns() > 1; i++) {
    mg_mgr_poll(&mgr, 1);
    while (recv(fd, sink, sizeof(sink), MSG_DONTWAIT) > 0) {
    }
  }
  close(fd);
  for (int i = 0; i < 200 && nconns() > 1; i++) mg_mgr_poll(&mgr, 1);
  return 0;
}
