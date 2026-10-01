// Vulnerable: an input-derived name is stored in an object field before it
// becomes the key. Tests field-sensitive value provenance.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct Field { std::string name; int tag; };

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> index;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    Field field;
    field.name = std::string(buf + i, e - i);              // taint enters an object field
    index.emplace(field.name, field.tag);                  // BENCH-TARGET  key = field.name
    i = e + 1;
  }

}







