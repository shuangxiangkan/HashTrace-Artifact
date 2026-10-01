// Distilled from brpc RedisServiceImpl::_db_map (repo/brpc/example/redis_c++/redis_server.cpp:59):
// a persistent key-value store; the map key is the client's Redis key.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct RedisServiceImpl {
  std::unordered_map<std::string, std::string> _db_map;      // persistent store
  void set(const char *buf, std::size_t len) {
    std::size_t i = 0;
    while (i < len) {
      std::size_t e = i;
      while (e < len && buf[e] != '\n') ++e;
      std::string key(buf + i, e - i);
      _db_map[key] = "v";                                    // BENCH-TARGET
      i = e + 1;
    }
  }
};

static RedisServiceImpl g_impl;

void bench_process(const char *buf, std::size_t len) {
  g_impl.set(buf, len);

}








