// Distilled from tables with a hand-rolled RS string hash (Harm-DoS models RS)
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include "hashers.h"
#include <string>
#include <unordered_map>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int, RSHash_bench> table;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string key(buf + i, e - i);
    table.emplace(key, 1);                               // BENCH-TARGET
    i = e + 1;
  }

}





