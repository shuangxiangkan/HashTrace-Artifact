// Negative, flip of P01 on C4 (cleanup): request-controlled default-hash keys,
// but the table is cleared at the start of every request, so nothing accumulates
// across requests and each request's table is bounded by that request's size --
// here the harness feeds small requests, and the parser clears first.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct Handler {
  std::unordered_map<std::string, std::string> scratch;   // reused, cleared per request
  void handle(const char *buf, std::size_t len) {
    scratch.clear();                                       // wiped before each request
    std::size_t i = 0, count = 0;
    while (i < len && count < 8) {                         // small per-request working set
      std::size_t e = i;
      while (e < len && buf[e] != '\n') ++e;
      std::string k(buf + i, e - i);
      scratch.emplace(k, std::string());                   // BENCH-TARGET
      ++count;
      i = e + 1;
    }
  }
};

static Handler g_handler;

void bench_process(const char *buf, std::size_t len) {
  g_handler.handle(buf, len);

}







