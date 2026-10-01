// Negative, flip-C4: a counted loop with a constant trip count inserts at most 16
// entries regardless of input length. Distilled from fixed-slot tables.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> slots;
  std::size_t i = 0;
  for (int k = 0; k < 16; ++k) {                        // constant trip count
    if (i >= len) break;
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    std::string key(buf + i, e - i);
    slots.emplace(key, k);                               // BENCH-TARGET
    i = e + 1;
  }

}





