// Negative, flip-C1: the map is populated with compile-time string literals; the
// request only decides how many times, never the key content.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> caps;
  for (std::size_t i = 0; i < len; ++i) {
    caps["max_conn"] += 1;                               // BENCH-TARGET  literal keys only
    caps["max_body"] += 1;
    caps["timeout"] += 1;
  }

}





