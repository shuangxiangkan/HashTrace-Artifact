// Distilled from cinatra http_parser::queries_ (repo/cinatra, http_parser.hpp):
// a per-request query-string map, a member keyed by std::string, filled from the
// raw request bytes. In cinatra the map is a member of the parser object, so it
// outlives one call and accumulates every parsed field name.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string>
#include <unordered_map>

struct HttpParser {
  std::unordered_map<std::string, std::string> queries_;

  void parse(const char *buf, std::size_t len) {
    std::size_t i = 0;
    while (i < len) {                                 // one "key=value" pair per line
      std::size_t e = i;
      while (e < len && buf[e] != '\n') ++e;
      std::string field(buf + i, e - i);
      std::size_t eq = field.find('=');
      std::string key = eq == std::string::npos ? field : field.substr(0, eq);
      std::string val = eq == std::string::npos ? std::string() : field.substr(eq + 1);
      queries_.emplace(key, val);                     // BENCH-TARGET
      i = e + 1;
    }
  }
};

void bench_process(const char *buf, std::size_t len) {
  HttpParser p;
  p.parse(buf, len);

}







