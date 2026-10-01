// Distilled from Crow / Simple-Web-Server connection maps that key on a
// boost-style combined hash (0x9e3779b9). Key is a client-supplied token.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include "hashers.h"
#include <string>
#include <unordered_map>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int, CombineHash> connections;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string token(buf + i, e - i);
    connections.emplace(token, 1);                            // BENCH-TARGET
    i = e + 1;
  }

}







