// Custom hash functors shared verbatim by the cases that use them and by the
// custom-key oracle, so the oracle builds collisions against the exact functor
// a case hashes with (no reimplementation, no drift). Each is a fixed-seed,
// deployment-independent function of the key -- reproducible offline.
#pragma once
#include <cstddef>
#include <string>

// boost hash_combine (0x9e3779b9), as Crow / Simple-Web-Server use.
struct CombineHash {
  std::size_t operator()(const std::string &s) const {
    std::size_t h = 0;
    for (char c : s) h ^= (std::size_t)(unsigned char)c + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
  }
};

// Java-style 31*h + c, as oatpp uses for its string keys.
struct Java31Hash {
  std::size_t operator()(const std::string &s) const {
    std::size_t h = 0;
    for (char c : s) h = 31 * h + (unsigned char)c;
    return h;
  }
};

// cpp-httplib case_ignore hash: h = h * 33 ^ c (djb-adjacent, tail form).
struct Httplib33Hash {
  std::size_t operator()(const std::string &s) const {
    std::size_t h = 0;
    for (char c : s) h = h * 33 ^ (unsigned char)c;
    return h;
  }
};

// Case-insensitive header hash (Crow ci_hash / SWS CaseInsensitiveHash): folds
// case, then FNV-1a-like mixing with fixed constants.
struct CIHash {
  std::size_t operator()(const std::string &s) const {
    std::size_t h = 2166136261u;
    for (char c : s) {
      char lc = (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
      h = (h ^ (unsigned char)lc) * 16777619u;
    }
    return h;
  }
};

// Plain 64-bit FNV-1a over raw bytes, e.g. a user std::hash<T> specialization.
struct Fnv1a64 {
  std::size_t operator()(const std::string &s) const {
    std::size_t h = 1469598103934665603ull;
    for (char c : s) h = (h ^ (unsigned char)c) * 1099511628211ull;
    return h;
  }
};

// DJB string hash as a named functor (textbook weak; Harm-DoS models DJB).
struct DJBHash_bench {
  std::size_t operator()(const std::string &s) const {
    unsigned h = 5381;
    for (char c : s) h = ((h << 5) + h) + (unsigned char)c;
    return h;
  }
};

// RS string hash (Arash Partow; Harm-DoS models RS).
struct RSHash_bench {
  std::size_t operator()(const std::string &s) const {
    unsigned b=378551,a=63689,h=0;
    for(char c:s){ h=h*a+(unsigned char)c; a*=b; }
    return h;
  }
};

// ELF string hash (Harm-DoS models ELF).
struct ELFHash_bench {
  std::size_t operator()(const std::string &s) const {
    unsigned h=0,x=0;
    for(char c:s){ h=(h<<4)+(unsigned char)c; if((x=h&0xF0000000u)) h^=(x>>24); h&=~x; }
    return h;
  }
};

// Crow ci_hash exactly: ASCII-uppercase each char, then boost hash_combine.
struct CrowCiHash {
  static void mix(std::size_t &seed, char v) {
    seed ^= (std::size_t)std::hash<char>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  }
  std::size_t operator()(const std::string &key) const {
    std::size_t seed = 0;
    for (char c : key) { char u = (c>='a'&&c<='z') ? char(c-'a'+'A') : c; mix(seed, u); }
    return seed;
  }
};

// cpp-httplib detail::case_ignore::hash exactly: h*33 ^ tolower(c), high 6 bits
// masked each step (matches httplib.h).
struct HttplibCiHash {
  std::size_t operator()(const std::string &key) const {
    std::size_t h = 0;
    for (char c : key) {
      char lc = (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
      h = (((std::size_t)-1 >> 6) & (h * 33)) ^ (unsigned char)lc;
    }
    return h;
  }
};

// reSIProcate rutil Data::rawHash exactly: 4-byte Pearson over a fixed
// permutation table (verbatim from rutil/Data.cxx), then ntohl. Deterministic,
// so predictable/attackable. Used for the SdpContents mAttributes HashMap.
struct ResipPearson {
  static const unsigned char perm[256];
  std::size_t operator()(const std::string &k) const {
    unsigned char b[4] = {perm[0], perm[1], perm[2], perm[3]};
    for (unsigned char c : k) { b[0]=perm[c^b[0]]; b[1]=perm[c^b[1]]; b[2]=perm[c^b[2]]; b[3]=perm[c^b[3]]; }
    return ((std::size_t)b[0]<<24)|((std::size_t)b[1]<<16)|((std::size_t)b[2]<<8)|(std::size_t)b[3];
  }
};
inline const unsigned char ResipPearson::perm[256] = {44,9,46,184,21,30,92,231,79,7,166,237,173,72,91,123,212,183,16,99,85,45,190,130,118,107,169,119,100,179,251,177,23,125,12,101,121,246,61,38,156,114,159,57,181,145,198,182,58,215,174,225,82,178,150,161,63,103,32,203,68,151,139,55,143,2,36,110,209,154,204,89,62,17,187,226,31,105,195,208,49,56,238,172,37,3,234,206,134,233,19,148,64,4,10,224,144,88,93,191,20,131,138,199,243,244,39,50,214,87,6,84,185,112,171,75,192,193,239,69,106,43,194,1,78,67,116,200,83,70,213,25,59,137,52,13,153,42,232,0,133,210,76,33,255,236,124,104,65,201,53,155,140,254,54,196,120,146,216,29,28,86,245,90,98,26,81,115,180,66,102,136,167,51,109,132,77,175,14,202,222,48,223,188,40,242,157,5,128,229,71,127,164,207,247,8,80,149,94,160,47,117,135,176,129,142,189,97,11,250,221,218,96,220,35,197,152,126,219,74,170,252,163,41,95,27,34,22,205,230,241,186,168,228,253,249,113,108,111,211,235,217,165,122,15,141,158,147,240,24,162,18,60,73,227,248};

// Seastar case_insensitive_hash: lowercase, then std::hash<string> (sstring hash
// is the same libstdc++ byte hash). Rough reproduction of the real functor.
struct StdCiHash {
  std::size_t operator()(const std::string &k) const {
    std::string s(k);
    for (char &c : s) if (c>='A'&&c<='Z') c=char(c-'A'+'a');
    return std::hash<std::string>{}(s);
  }
};

