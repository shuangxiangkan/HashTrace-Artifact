// Vulnerable: an input-derived name is stored as another map's value before
// becoming the key of the target map. Tests mapped-value provenance.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<int, std::string> staged;
  std::size_t i = 0; int n = 0;
  while (i < len) {
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    staged[n++] = std::string(buf + i, e - i);
    i = e + 1;
  }
  std::unordered_map<std::string, int> index;
  for (int k = 0; k < n; ++k)
    index.emplace(staged[k], 1);                         // BENCH-TARGET  key = other map's value

}





