// Header table using the BKDR string hash (another algorithm in Harm-DoS's
// catalog), keyed by attacker-supplied header names.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct BKDRHash {
  std::size_t operator()(const std::string &s) const {
    unsigned seed = 131, h = 0;
    for (char c : s) h = h * seed + (unsigned char)c;
    return h;
  }
};

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, std::string, BKDRHash> headers;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string name(buf + i, e - i);
    headers.emplace(name, std::string());                    // BENCH-TARGET
    i = e + 1;
  }

}







