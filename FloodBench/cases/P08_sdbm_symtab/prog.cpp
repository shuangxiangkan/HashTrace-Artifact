// Reference-label table using the SDBM string hash (the algorithm Harm-DoS
// found in Reddit's Snudown). Labels come straight from the parsed document.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct SDBMHash {
  std::size_t operator()(const std::string &s) const {
    unsigned h = 0;
    for (char c : s) h = (unsigned char)c + (h << 6) + (h << 16) - h;
    return h;
  }
};

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int, SDBMHash> refs;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string label(buf + i, e - i);
    refs[label] = 1;                                          // BENCH-TARGET
    i = e + 1;
  }

}







