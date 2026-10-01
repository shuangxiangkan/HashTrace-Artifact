// The Arrow schema-index shape isolated: emplace_hint(find(name), name, i) on an
// unordered_multimap<string_view,int>, with reserve() first. The key is sliced
// directly over the attacker buffer, so this exercises operation recovery (nested
// find as its own lookup; key = emplace_hint's SECOND argument) without a
// container-element taint hop.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <string_view>
#include <unordered_map>
#include <vector>

void bench_process(const char *buf, std::size_t len) {
  // count lines to size the reserve, then index name views over buf
  std::vector<std::pair<std::size_t, std::size_t>> spans;
  std::size_t i = 0;
  while (i < len) {
    std::size_t e = i;
    while (e < len && buf[e] != '\n') ++e;
    spans.emplace_back(i, e - i);
    i = e + 1;
  }
  std::unordered_multimap<std::string_view, int> idx;
  idx.reserve(spans.size());
  for (std::size_t k = 0; k < spans.size(); ++k) {
    std::string_view name(buf + spans[k].first, spans[k].second);   // view over attacker bytes
    idx.emplace_hint(idx.find(name), name, (int)k);                 // BENCH-TARGET
  }

}







