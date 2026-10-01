// Distilled from brpc RedisServiceImpl::_user_password (repo/brpc/example/redis_c++/redis_server.cpp:66):
// a persistent auth map keyed by a client-supplied user name.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
struct Auth {
  std::unordered_map<std::string, std::string> _user_password;   // persistent
  void reg(const char *buf, std::size_t len) {
    std::size_t i = 0;
    while (i < len) {
      std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
      std::string user(buf + i, e - i);
      _user_password[user] = "x";                        // BENCH-TARGET
      i = e + 1;
    }
  }
};
static Auth g_auth;







