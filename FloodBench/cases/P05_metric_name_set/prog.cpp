// Distilled from brpc metric_name_set (repo/brpc, test/brpc_prometheus_metrics_unittest.cpp:130):
// an unordered_set of metric names taken from an exposition-format payload.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_set>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_set<std::string> metric_name_set;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string name(buf + i, e - i);
    metric_name_set.insert(name);                            // BENCH-TARGET  set: element is the key
    i = e + 1;
  }

}







