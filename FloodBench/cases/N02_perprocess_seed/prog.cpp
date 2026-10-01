// Negative, flip of P01 on C2: same request-controlled std::string keys and
// unbounded map, but the hasher is seeded once per process from a random source,
// so an attacker cannot predict buckets offline. This is the fix Apache Arrow
// shipped for its field-name index (arrow #51389).
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <cstdint>
#include <random>
#include <string>
#include <unordered_map>

struct SeededHash {
  std::size_t seed;
  SeededHash() { std::random_device rd; seed = (std::size_t(rd()) << 32) ^ rd(); }
  std::size_t operator()(const std::string &s) const {
    std::size_t h = seed;                              // per-process random seed
    for (char c : s) h = (h ^ (unsigned char)c) * 1099511628211ull;
    return h;
  }
};

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int, SeededHash> queries;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string key(buf + i, e - i);
    queries.emplace(key, 1);                            // BENCH-TARGET
    i = e + 1;
  }

}







