// Negative, flip on C3/C4: keys are single bytes (a 1-byte opcode), so the key
// domain has only 256 distinct values -- far below any DoS-scale bucket. Even
// with default hash and attacker control, at most 256 distinct keys can exist.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> by_opcode;
  for (std::size_t i = 0; i < len; ++i) {
    std::string opcode(1, buf[i]);                      // 1-byte key: 256 possible values
    by_opcode[opcode] += 1;                              // BENCH-TARGET
  }

}







