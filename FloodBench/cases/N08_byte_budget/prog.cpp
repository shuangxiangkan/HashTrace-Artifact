// Negative, flip on C4: default-hash attacker keys, but a hard total byte budget
// caps how much input is processed, and each key costs >= a fixed minimum, so at
// most a handful of entries can exist. Distilled from small fixed read buffers.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

static const std::size_t kMaxBytes = 4096;   // total request budget
static const std::size_t kMinKey   = 64;     // each entry consumes >= 64 bytes

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> m;
  std::size_t used = 0, i = 0;
  while (i < len && used + kMinKey <= kMaxBytes) {  // budget bounds entries to <= 64
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string k(buf + i, e - i);
    m.emplace(k, 1);                                // BENCH-TARGET
    used += kMinKey;
    i = e + 1;
  }

}







