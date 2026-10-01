// The hash container is wrapped in a user template; the key reaches it through
// the wrapper's insert. Tests operation recovery through a template wrapper.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
template <class V> struct Dict {
  std::unordered_map<std::string, V> m;
  void put(const std::string &k, V v) { m.emplace(k, v); }   // BENCH-TARGET
};
struct Server {
  Dict<int> headers;
  void handle(const char *buf, std::size_t len) {
    std::size_t i = 0;
    while (i < len) {
      std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
      std::string name(buf + i, e - i);
      headers.put(name, 1);
      i = e + 1;
    }
  }
};
static Server g_s;







