// Vulnerable: input-derived names are stored in vector elements and later
// used as keys. Tests local container-element value provenance.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
#include <vector>

void bench_process(const char *buf, std::size_t len) {
  std::vector<std::string> storage;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    storage.emplace_back(buf + i, e - i);
    i = e + 1;
  }
  std::unordered_map<std::string, int> table;
  for (std::size_t k = 0; k < storage.size(); ++k)
    table.emplace(storage[k], 1);                          // BENCH-TARGET  key = vector element

}







