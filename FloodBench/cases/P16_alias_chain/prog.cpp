// Default-hash string map reached only through a using-alias chain, keyed by a
// request field. Tests alias resolution in operation recovery.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

using StrMap = std::unordered_map<std::string, std::string>;
using HeaderMap = StrMap;                                   // alias of an alias

struct Request {
  HeaderMap headers;                                        // declared via alias chain
  void add(const char *buf, std::size_t len) {
    std::size_t i = 0;
    while (i < len) {
      std::size_t e = i;
      while (e < len && buf[e] != '\n') ++e;
      std::string name(buf + i, e - i);
      headers.emplace(name, std::string());                // BENCH-TARGET
      i = e + 1;
    }
  }
};

static Request g_req;

void bench_process(const char *buf, std::size_t len) {
  g_req.add(buf, len);

}








