// Negative, flip-C2: a keyed hash seeded from a per-process random key (SipHash
// spirit). Buckets are unpredictable offline; no offline collision set exists.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <cstdint>
#include <random>
#include <string>
#include <unordered_map>
struct KeyedHash {
  std::uint64_t k0, k1;
  KeyedHash(){ std::random_device r; k0=((std::uint64_t)r()<<32)^r(); k1=((std::uint64_t)r()<<32)^r(); }
  std::size_t operator()(const std::string &s) const {
    std::uint64_t h = k0;
    for (char c : s) h = (h ^ (unsigned char)c) * (k1 | 1) + 0x9e3779b97f4a7c15ull;
    return (std::size_t)h;
  }
};
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int, KeyedHash> m;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    std::string k(buf + i, e - i);
    m.emplace(k, 1);                                     // BENCH-TARGET
    i = e + 1;
  }

}





