// Negative, flip of P01 on C1 only: same std::string/default-hash map, same
// unbounded insertion, but the keys are a fixed set of developer-defined option
// names, not request data. The request only supplies *values*. Distilled from
// config/option tables (e.g. server .ini handling): attacker cannot choose keys.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

static const char *kOptionNames[] = {
    "listen", "port", "root", "workers", "timeout", "keepalive",
    "loglevel", "tls_cert", "tls_key", "gzip", "max_body", "charset"};

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, std::string> config;
  std::size_t i = 0, idx = 0;
  const std::size_t n = sizeof(kOptionNames) / sizeof(*kOptionNames);
  while (i < len) {                                   // each line is a value for the next fixed key
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string val(buf + i, e - i);
    config[kOptionNames[idx % n]] = val;              // BENCH-TARGET  key is internal, not from input
    ++idx;
    i = e + 1;
  }

}







