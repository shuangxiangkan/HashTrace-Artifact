// Negative, flip-C1: the request payload becomes the stored VALUE; the key is a
// monotonically increasing server sequence number. Attacker influences values,
// never keys.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<long, std::string> log;
  long seq = 0;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    std::string val(buf + i, e - i);
    log[seq++] = val;                                    // BENCH-TARGET  key = server seq
    i = e + 1;
  }

}





