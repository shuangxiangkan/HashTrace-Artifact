// Member map disambiguated with this->, plus a shadowing local of the same name.
// Tests receiver/scope resolution: this->cache is the member, not the local.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct Cache {
  std::unordered_map<std::string, int> cache;              // member
  void insert_all(const char *buf, std::size_t len) {
    int cache = 0;                                          // shadowing local (not the map)
    (void)cache;
    std::size_t i = 0;
    while (i < len) {
      std::size_t e = i;
      while (e < len && buf[e] != '\n') ++e;
      std::string key(buf + i, e - i);
      this->cache.emplace(key, 1);                         // BENCH-TARGET  member via this->
      i = e + 1;
    }
  }
};

static Cache g_cache;

void bench_process(const char *buf, std::size_t len) {
  g_cache.insert_all(buf, len);

}








