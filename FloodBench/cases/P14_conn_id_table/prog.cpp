// Distilled from swoole streams / pikiwidb blocked_conn_to_keys_ : a persistent
// table keyed by a client-chosen connection id (int). libstdc++ std::hash<int>
// is identity, so id % bucket_count picks the bucket.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <cstdint>
#include <cstring>
#include <unordered_map>

struct Dispatcher {
  std::unordered_map<int, int> conn_state;                 // persistent
  void on_frame(const char *buf, std::size_t len) {
    std::size_t i = 0;
    while (i + 4 <= len) {
      int id;
      std::memcpy(&id, buf + i, 4);                        // client-chosen conn id
      conn_state[id] += 1;                                 // BENCH-TARGET
      i += 4;
    }
  }
};

static Dispatcher g_disp;

void bench_process(const char *buf, std::size_t len) {
  g_disp.on_frame(buf, len);

}








