// Negative, flip-C4: a bounded cache that refuses new keys once full (literal
// cap 32). Attacker keys, default hash, but the table never exceeds 32 entries.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> cache;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    std::string k(buf + i, e - i);
    if (cache.size() < 32) cache.emplace(k, 1);          // BENCH-TARGET  literal cap 32
    i = e + 1;
  }

}





