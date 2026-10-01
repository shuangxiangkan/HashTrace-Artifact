// Distilled from swoole HTTP/2 stream tables (repo/swoole, ext-src/php_swoole_http.h:347,
// swoole_http2_client_coro.cc): a map keyed by the client-chosen 32-bit stream id.
// std::hash<uint32_t> in libstdc++ is the identity, so the bucket is id % bucket_count.
#include <cstddef>
#define BENCH_OBSERVE(c) ((void)0)
void bench_process(const char*, std::size_t);
#include <cstdint>
#include <cstring>
#include <unordered_map>

struct Stream { uint32_t id; };

void bench_process(const char *buf, std::size_t len) {
  std::unordered_map<uint32_t, Stream> streams;
  std::size_t i = 0;
  while (i + 4 <= len) {                              // 4 bytes per client-supplied stream id
    uint32_t id;
    std::memcpy(&id, buf + i, 4);
    streams.emplace(id, Stream{id});                  // BENCH-TARGET
    i += 4;
  }

}







