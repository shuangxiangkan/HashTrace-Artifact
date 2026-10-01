// A route table keyed by request path, using a classic DJB string hash as the
// container's Hash functor -- the kind of textbook hash Harm-DoS models.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct DJBHash {
  std::size_t operator()(const std::string &s) const {
    unsigned h = 5381;
    for (char c : s) h = ((h << 5) + h) + (unsigned char)c;
    return h;
  }
};

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int, DJBHash> routes;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string path(buf + i, e - i);
    routes.emplace(path, 1);                                  // BENCH-TARGET
    i = e + 1;
  }

}







