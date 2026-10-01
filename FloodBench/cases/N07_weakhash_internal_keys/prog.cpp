// Negative: uses a textbook-weak DJB hash (which Harm-DoS flags), but the keys
// are a fixed set of internal opcode names -- the request supplies only values.
// Discriminates key-provenance-aware detection (HashTrace: safe) from pure
// weak-hash matching (Harm-DoS: will flag the DJB function).
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include "hashers.h"
#include <string>
#include <unordered_map>

static const char *kOps[] = {"GET","SET","DEL","INCR","DECR","EXPIRE","TTL","KEYS"};

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, std::string, DJBHash_bench> counters;
  std::size_t i = 0, idx = 0;
  const std::size_t n = sizeof(kOps)/sizeof(*kOps);
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string value(buf + i, e - i);
    counters[kOps[idx % n]] = value;                       // BENCH-TARGET  key is internal
    ++idx; i = e + 1;
  }

}







