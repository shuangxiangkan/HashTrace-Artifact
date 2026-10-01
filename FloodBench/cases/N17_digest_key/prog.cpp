// Negative, flip on constructibility: the key is a fixed-length hex digest of the
// request bytes (a stand-in for SHA-256), not the raw bytes. To force a bucket
// collision the attacker would need to invert the digest, which is infeasible.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <cstdint>
#include <string>
#include <unordered_map>
static std::string digest(const char *p, std::size_t n) {
  // 16 mixing rounds over the input -> 32 hex chars; one-way in practice.
  std::uint64_t a = 0x243f6a8885a308d3ull, b = 0x13198a2e03707344ull;
  for (std::size_t i = 0; i < n; ++i) { a = (a ^ (unsigned char)p[i]) * 0x100000001b3ull; b = (b + a) ^ (b << 7); }
  static const char *h = "0123456789abcdef";
  std::string out(32, '0');
  for (int i = 0; i < 16; ++i) { out[i] = h[(a >> (i*4)) & 15]; out[16+i] = h[(b >> (i*4)) & 15]; }
  return out;
}
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> by_digest;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    std::string key = digest(buf + i, e - i);            // BENCH-TARGET  key = digest(input)
    by_digest.emplace(key, 1);
    i = e + 1;
  }

}





