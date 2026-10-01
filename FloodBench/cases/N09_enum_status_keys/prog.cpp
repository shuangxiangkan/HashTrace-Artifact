// Negative, flip on C1: default-hash map keyed by a fixed status-name set chosen
// by the server from a parsed integer code; the attacker influences which code,
// but not the key strings, and there are only a few of them.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

static const char *kStatus[] = {"ok","error","timeout","refused","reset","again"};

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> tally;
  for (std::size_t i = 0; i < len; ++i) {
    unsigned code = (unsigned char)buf[i] % 6;          // attacker picks the code...
    tally[kStatus[code]] += 1;                          // BENCH-TARGET  ...but keys are fixed
  }

}







