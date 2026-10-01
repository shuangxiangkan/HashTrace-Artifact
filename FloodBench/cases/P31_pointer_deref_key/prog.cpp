// Vulnerable: a local pointer aliases an input-derived name used as the key.
// Tests provenance through a simple address-taken alias.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> index;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    std::string name(buf + i, e - i);
    std::string *p = &name;                              // key reached via pointer
    index.emplace(*p, 1);                                // BENCH-TARGET  key = *p
    i = e + 1;
  }

}





