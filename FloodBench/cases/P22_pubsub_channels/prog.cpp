// Distilled from kvrocks/redis pub-sub channel maps keyed by client-supplied channel name
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct Holder {
  std::unordered_map<std::string, std::string> channels;   // persistent
  void subscribe(const char *buf, std::size_t len) {
    std::size_t i = 0;
    while (i < len) {
      std::size_t e = i;
      while (e < len && buf[e] != '\n') ++e;
      std::string key(buf + i, e - i);
      channels.emplace(key, std::string());                // BENCH-TARGET
      i = e + 1;
    }
  }
};
static Holder g_h;







