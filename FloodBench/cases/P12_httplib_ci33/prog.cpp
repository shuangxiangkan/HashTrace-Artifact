// Distilled from cpp-httplib's case-ignore header hash (h = h*33 ^ c), keyed by
// the attacker-supplied header name.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include "hashers.h"
#include <string>
#include <unordered_map>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, std::string, Httplib33Hash> headers;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string name(buf + i, e - i);
    headers.emplace(name, std::string());                     // BENCH-TARGET
    i = e + 1;
  }

}







