// Distilled from Crow ci_hash / Simple-Web-Server CaseInsensitiveHash: a header
// map that folds case then mixes with fixed FNV-style constants.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include "hashers.h"
#include <string>
#include <unordered_map>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, std::string, CIHash> headers;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string name(buf + i, e - i);
    headers[name] = "v";                                      // BENCH-TARGET
    i = e + 1;
  }

}







