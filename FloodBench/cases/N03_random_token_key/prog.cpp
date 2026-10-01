// Negative, flip on key predictability: default std::hash and an unbounded map,
// but the key is a server-generated random token, not attacker-chosen. The
// client supplies nothing that becomes the key.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <random>
#include <string>
#include <unordered_map>

static std::string random_token() {
  static std::mt19937_64 rng{std::random_device{}()};
  static const char d[] = "0123456789abcdef";
  std::string s(16, '0');
  for (char &c : s) c = d[rng() & 15];
  return s;
}

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, int> issued;
  for (std::size_t i = 0; i < len; ++i) {              // one token issued per input byte
    std::string tok = random_token();
    issued.emplace(tok, 1);                             // BENCH-TARGET  key is server-random
  }

}







