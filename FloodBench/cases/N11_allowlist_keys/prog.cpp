// Negative, flip-C1: keys come from the request but only names on a fixed
// allowlist are ever inserted, so the key set is bounded to the allowlist.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>
static bool allowed(const std::string &s) {
  static const char *ok[] = {"host","accept","cookie","referer","origin"};
  for (auto *a : ok) if (s == a) return true;
  return false;
}
void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, std::string> headers;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i; while (e < len && buf[e] != '\n') ++e;
    std::string name(buf + i, e - i);
    if (allowed(name)) headers.emplace(name, std::string()); // BENCH-TARGET  only allowlisted
    i = e + 1;
  }

}





