// Distilled from cinatra coro_http_request::params_ (repo/cinatra/include/cinatra/coro_http_request.hpp:300)
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, std::string> params_;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string key(buf + i, e - i);
    params_.emplace(key, std::string());                  // BENCH-TARGET
    i = e + 1;
  }

}





