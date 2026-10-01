// Negative, flip-C4: each key is inserted, used, then erased before the next, so
// at most one entry is ever live. Distilled from request-scoped scratch lookups.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> scratch;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    std::string k(buf + i, e - i);
    scratch.emplace(k, 1);                               // BENCH-TARGET
    scratch.erase(k);                                    // erased immediately -> never accumulates
    i = e + 1;
  }

}





