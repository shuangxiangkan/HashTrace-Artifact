// A set of seen request ids (uint32) taken from the wire; identity int hash.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <cstdint>
#include <cstring>
#include <unordered_set>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_set<uint32_t> seen;
  std::size_t i = 0;
  while (i + 4 <= len) {
    uint32_t id;
    std::memcpy(&id, buf + i, 4);
    seen.insert(id);                                        // BENCH-TARGET
    i += 4;
  }

}







