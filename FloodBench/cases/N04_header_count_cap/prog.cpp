// Negative, flip of P01 on C4 only: request-controlled std::string keys in a
// default-hash map, but a hard count cap stops insertion. Distilled from
// cpp-httplib CPPHTTPLIB_HEADER_MAX_COUNT = 100 (repo/cpp-httplib/httplib.h:118),
// a macro that expands to the literal 100 the compiler (and any analyzer working
// on preprocessed code) actually sees.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<std::string, std::string> headers;
  std::size_t i = 0;
  while (i < len) {
    if (headers.size() >= 100) return;   // BENCH-TARGET  cap dominates the insert
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    std::string field(buf + i, e - i);
    std::size_t colon = field.find(':');
    std::string key = colon == std::string::npos ? field : field.substr(0, colon);
    headers.emplace(key, colon == std::string::npos ? std::string() : field.substr(colon + 1));
    i = e + 1;
  }

}







