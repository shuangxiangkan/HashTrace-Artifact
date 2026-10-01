// Distilled from cinatra session_manager::map_ (repo/cinatra/include/cinatra/session_manager.hpp):
// a process-wide session table keyed by the client-supplied session id from a cookie.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct SessionManager {
  std::unordered_map<std::string, int> map_;                 // persistent, process-wide
  void touch(const char *buf, std::size_t len) {
    std::size_t i = 0;
    while (i < len) {
      std::size_t e = i;
      while (e < len && buf[e] != '\n') ++e;
      std::string sid(buf + i, e - i);                       // session id from cookie
      map_[sid] += 1;                                        // BENCH-TARGET
      i = e + 1;
    }
  }
};

static SessionManager g_sessions;                            // outlives every request

void bench_process(const char *buf, std::size_t len) {
  g_sessions.touch(buf, len);

}








