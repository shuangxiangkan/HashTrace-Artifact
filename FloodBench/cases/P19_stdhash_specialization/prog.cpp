// A custom key type with a user std::hash specialization that mixes with fixed
// constants. The map uses the default Hash (which resolves to that specialization).
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <cstddef>
#include <string>
#include <unordered_map>

struct Name { std::string v; bool operator==(const Name &o) const { return v == o.v; } };

namespace std {
template <> struct hash<Name> {
  std::size_t operator()(const Name &n) const {
    std::size_t h = 1469598103934665603ull;                // fixed FNV offset basis
    for (char c : n.v) h = (h ^ (unsigned char)c) * 1099511628211ull;
    return h;
  }
};
}

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<Name, int> table;                     // default Hash == std::hash<Name>
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    Name key{std::string(buf + i, e - i)};
    table.emplace(key, 1);                                 // BENCH-TARGET
    i = e + 1;
  }

}







