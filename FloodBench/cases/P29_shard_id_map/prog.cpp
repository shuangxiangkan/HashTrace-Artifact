// Distilled from cluster/shard tables keyed by a client-influenced slot id (int).
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <cstdint>
#include <cstring>
#include <unordered_map>
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<int, int> shard_of;
  std::size_t i = 0;
  while (i + 4 <= len) {
    int slot; std::memcpy(&slot, buf + i, 4);
    shard_of[slot] = 0;                                  // BENCH-TARGET
    i += 4;
  }

}





