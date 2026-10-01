"""Dynamic validation: generate + run a local collision probe per candidate.

Turns a static HashDoS *candidate* into evidence. For a candidate whose hashing
is reproducible in isolation, we emit a self-contained C++ probe that rebuilds an
isomorphic container, feeds it N sequential keys vs N keys pre-selected to share a
bucket (``hash(k) % bucket_count``), and measures the insert / failed-lookup time
and max bucket size. A large colliding/sequential ratio confirms the O(n^2)
degradation the static analysis predicted.

v1 scope: **string-keyed containers using the default ``std::hash``** — the bulk
of real findings (session maps, query/header/cookie maps). Custom fixed-seed
hashers (whose functor source would have to be embedded) and non-string keys are
reported as "not auto-verifiable" rather than guessed at.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .model import HashDoSCandidate

_STRING_KEY_RE = re.compile(
    r"\b(?:basic_string|basic_sstring|sstring|string|string_view)\b"
)
# Integral keys wide enough (>=32 bit) to have a meaningful key space. char/short
# are excluded (a HashDoS on a 256/65536-value domain is meaningless); pointers
# are excluded (an attacker does not choose addresses).
_INTEGRAL_KEY_RE = re.compile(
    r"^(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:std::)?"
    r"(?:int|unsigned|long|long\s+long|unsigned\s+long|unsigned\s+long\s+long"
    r"|size_t|ptrdiff_t|u?int32_t|u?int64_t)$"
)


# Custom-functor risks whose behaviour is reproducible offline (a fixed algorithm
# with no per-process randomness). "randomized" is deliberately excluded — those
# are the *defended* hashers and not findings.
_VERIFIABLE_CUSTOM_RISKS = frozenset({"fixed-seed", "deterministic", "weak"})


def _key_kind(key_type: str | None) -> str | None:
    """'string' | 'integral' | None (pointer / structured / unknown)."""
    if not key_type:
        return None
    clean = " ".join(key_type.split())
    if "*" in clean:
        return None
    if _STRING_KEY_RE.search(clean):
        return "string"
    if _INTEGRAL_KEY_RE.match(clean):
        return "integral"
    return None


def _is_string_key(key_type: str | None) -> bool:
    return _key_kind(key_type) == "string"


def _extract_hasher_definition(hasher) -> str | None:
    """Best-effort: read the hasher's ``struct``/``class`` source so it can be
    embedded in a standalone probe. Returns None when it can't be located
    (no path / out-of-line operator / unbalanced) — the caller then skips it."""
    if hasher is None or not hasher.path or not hasher.line:
        return None
    try:
        text = Path(hasher.path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines(keepends=True)
    if hasher.line > len(lines):
        return None
    rest = text[sum(len(line) for line in lines[: hasher.line - 1]) :]
    # Tolerate a leading ``template<...>`` on the same line as the struct/class,
    # which is how a ``std::hash<T>`` specialization is often written.
    if not re.match(r"\s*(?:template\s*<[^>]*>\s*)?(?:struct|class)\b", rest):
        return None
    brace = rest.find("{")
    if brace < 0:
        return None
    depth = 0
    for i in range(brace, len(rest)):
        if rest[i] == "{":
            depth += 1
        elif rest[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                if rest[end : end + 1] == ";":
                    end += 1
                return rest[:end]
    return None


def _hasher_terminal(hasher) -> str:
    return (hasher.definition or hasher.hasher_type or "").rsplit("::", 1)[-1]


_STD_HASH_SPEC_NAME_RE = re.compile(r"^(?:std::)?hash<.+>$")


def _is_std_hash_specialization(hasher) -> bool:
    """True when the hasher is a *user-provided* ``std::hash<T>`` specialization
    (e.g. oatpp's ``std::hash<StringKeyLabel>``) rather than a named functor or
    the standard default hash. The default also renders as ``std::hash<Key>``, so
    it is distinguished by risk: a user specialization carries a custom risk
    (deterministic / fixed-seed / weak) from analysing its body."""
    if hasher is None or hasher.risk == "default":
        return False
    name = "".join((hasher.hasher_type or hasher.definition or "").split()).lstrip(":")
    return bool(_STD_HASH_SPEC_NAME_RE.match(name))


def _specialization_byte_polynomial(hasher) -> tuple[int, bool] | None:
    """Parse a ``std::hash<T>`` specialization body as a string-byte polynomial.

    Recognises the ``acc = M*acc + byte`` / ``acc = (acc<<S) ... + byte`` family
    (oatpp's ``31*result + c``, Java-style hashes, most case-insensitive string
    hashers). Returns ``(multiplier, folds_case)`` when the body is a byte-wise
    polynomial over the key, or None otherwise — so a key type wrapping a string
    (whose bytes a std::string reproduces exactly) becomes verifiable with a
    synthesized, behaviourally identical hasher. Non-string specializations
    (enums, structs) don't match and stay not-auto-verifiable."""
    body = _extract_hasher_definition(hasher)
    if body is None:
        return None
    compact = body
    mult: int | None = None
    # acc = M * acc   /   acc = acc * M  (same accumulator on both sides)
    m = re.search(r"([A-Za-z_]\w*)\s*=\s*\(?\s*(\d+)\s*\*\s*\1\b", compact) or re.search(
        r"([A-Za-z_]\w*)\s*=\s*\(?\s*\1\s*\*\s*(\d+)\b", compact
    )
    if m is not None:
        mult = int(m.group(2))
    else:
        shift = re.search(r"([A-Za-z_]\w*)\s*=\s*\(?\s*\1\s*<<\s*(\d+)", compact) or \
            re.search(r"([A-Za-z_]\w*)\s*=\s*\(?\s*\(\s*\1\s*<<\s*(\d+)", compact)
        if shift is not None:
            mult = 1 << int(shift.group(2))
    if mult is None or not (2 <= mult <= 1_000_000):
        return None
    # must actually fold a per-byte value into the accumulator (a loop over bytes)
    if not re.search(r"\bfor\b", compact):
        return None
    folds_case = bool(
        re.search(r"\|\s*(?:32|0x20)\b", compact)
        or "tolower" in compact
        or "toupper" in compact
    )
    return mult, folds_case


def _specialization_delegates_to_std_hash(hasher) -> bool:
    """Whether a ``std::hash<T>`` specialization just delegates to ``std::hash``.

    The common string-wrapper idiom: ``std::hash<seastar::sstring>`` /
    ``std::hash<nonstd::string_view>`` whose body is ``return
    std::hash<std::string_view>()(s);``. On libstdc++/libc++ the string and
    string_view hashes agree byte-for-byte, so such a container's bucket
    behaviour is identical to the default ``std::hash<std::string>`` — the probe
    can use the default hash (faithful), rather than embedding the spec (which is
    uncompilable standalone as a bare ``struct hash<T>``)."""
    body = _extract_hasher_definition(hasher)
    if body is None:
        return False
    if _specialization_byte_polynomial(hasher) is not None:
        return False  # a polynomial is reproduced separately, not delegated
    compact = "".join(body.split())
    # Require a *call* to std::hash (``std::hash<...>``) — not merely the
    # specialization's own ``struct hash<Key>`` header, which always contains
    # ``hash<``. A spec that computes from the key arithmetically (e.g.
    # ``return (size_t)s.value;``) has no such delegation and is not reproducible.
    if "std::hash<" not in compact:
        return False
    # A pure delegation has no combine arithmetic (xor / shift mixing of hashes).
    if re.search(r"\^|<<|>>", compact):
        return False
    return "return" in body


def can_generate(candidate: HashDoSCandidate) -> bool:
    """True when a faithful probe can be built for this candidate.

    String keys: the default ``std::hash`` or a custom fixed-seed/deterministic
    functor whose source can be extracted and embedded. Integral keys (>=32-bit):
    the default ``std::hash`` only — collisions are generated arithmetically
    against the standard-library integer hash (identity on libstdc++/libc++).
    """
    hasher = candidate.hasher
    if hasher is None:
        return False
    kind = _key_kind(candidate.container.key_type)
    # A user ``std::hash<T>`` specialization (string-wrapper keys like oatpp
    # StringKeyLabel / seastar sstring / nonstd::string_view) is reproducible when
    # its body is a byte-polynomial (synthesized) or delegates to std::hash (use
    # the default hash). A spec we can't reproduce is NOT embeddable standalone
    # (a bare ``struct hash<T>`` won't compile), so it's simply not generatable.
    if _is_std_hash_specialization(hasher):
        if hasher.risk not in _VERIFIABLE_CUSTOM_RISKS:
            return False
        reproducible = (
            _specialization_byte_polynomial(hasher) is not None
            or _specialization_delegates_to_std_hash(hasher)
        )
        return reproducible and kind in ("string", None)
    if kind == "string":
        if hasher.risk == "default":
            return True
        return bool(
            hasher.risk in _VERIFIABLE_CUSTOM_RISKS
            and _extract_hasher_definition(hasher)
        )
    if kind == "integral":
        return hasher.risk == "default"
    return False


def probe_fingerprint(candidate: HashDoSCandidate) -> str:
    identity = ":".join(
        (
            candidate.relative_path or candidate.path or "buffer",
            candidate.function,
            str(candidate.line),
            candidate.container.qualified_name,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]


# The container is rebuilt as ``std::unordered_map<std::string,int,Hasher>`` with
# the finding's actual hasher (the default ``std::hash`` or an embedded custom
# functor) so libstdc++/libc++ bucket behaviour matches.
_PROBE_TEMPLATE = r"""// Auto-generated by HashTrace (dynamic validation).
// Finding: {location}
//   container {container} ({container_type})
//   op={operation} key={key!r}  hasher={hasher_type}
// Rebuilds the container and compares sequential vs. same-bucket keys.
//   g++ -std=c++17 -O2 {basename} -o /tmp/probe && /tmp/probe {n} {n}
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <locale>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>
{hasher_prelude}
namespace {{
using Clock = std::chrono::steady_clock;
using Hasher = {hasher_type};
using Map = std::unordered_map<std::string, int, Hasher>;

std::uint64_t us_since(Clock::time_point t) {{
    return (std::uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
        Clock::now() - t).count();
}}

std::size_t planned_buckets(std::size_t n) {{
    Map tmp;
    for (std::size_t i = 0; i < n; ++i) tmp.emplace("seed_" + std::to_string(i), 0);
    return tmp.bucket_count();
}}

std::vector<std::string> sequential_keys(std::size_t n) {{
    std::vector<std::string> v; v.reserve(n);
    for (std::size_t i = 0; i < n; ++i) v.push_back("k_" + std::to_string(i));
    return v;
}}

std::vector<std::string> colliding_keys(std::size_t n, std::size_t buckets, std::size_t bucket) {{
    std::vector<std::string> v; std::unordered_set<std::string> seen;
    Hasher h;
    for (std::uint64_t i = 0; v.size() < n; ++i) {{
        std::string c = "evil_" + std::to_string(i);
        if ((h(c) % buckets) == bucket && seen.insert(c).second) v.push_back(std::move(c));
    }}
    return v;
}}

std::string missing_key(std::size_t buckets, std::size_t bucket, const std::unordered_set<std::string>& e) {{
    Hasher h;
    for (std::uint64_t i = 0;; ++i) {{
        std::string c = "miss_" + std::to_string(i);
        if ((h(c) % buckets) == bucket && !e.count(c)) return c;
    }}
}}

std::size_t max_bucket(const Map& m) {{
    std::size_t r = 0;
    for (std::size_t i = 0; i < m.bucket_count(); ++i) r = std::max(r, m.bucket_size(i));
    return r;
}}

struct R {{ std::uint64_t ins, look; std::size_t maxb; }};

R run(const std::vector<std::string>& keys, std::size_t bucket, std::size_t rounds) {{
    Map m;
    auto t0 = Clock::now();
    for (const auto& k : keys) {{ auto it = m.find(k); if (it == m.end()) m.emplace(k, 1); }}
    auto ins = us_since(t0);
    std::unordered_set<std::string> ex(keys.begin(), keys.end());
    std::string miss = missing_key(m.bucket_count(), bucket, ex);
    volatile std::size_t sink = 0;
    auto t1 = Clock::now();
    for (std::size_t i = 0; i < rounds; ++i) sink += (m.find(miss) == m.end()) ? 0 : 1;
    auto look = us_since(t1); (void)sink;
    return R{{ins, look, max_bucket(m)}};
}}
}}  // namespace

int main(int argc, char** argv) {{
    std::size_t n = argc > 1 ? std::stoul(argv[1]) : {n};
    std::size_t rounds = argc > 2 ? std::stoul(argv[2]) : n;
    std::size_t bucket = 0, buckets = planned_buckets(n);
    R s = run(sequential_keys(n), bucket, rounds);
    R c = run(colliding_keys(n, buckets, bucket), bucket, rounds);
    std::cout << "n=" << n << " buckets=" << buckets << "\n";
    std::cout << "sequential insert_us=" << s.ins << " lookup_us=" << s.look << " max_bucket=" << s.maxb << "\n";
    std::cout << "colliding  insert_us=" << c.ins << " lookup_us=" << c.look << " max_bucket=" << c.maxb << "\n";
    double ir = s.ins ? (double)c.ins / (double)s.ins : 0.0;
    double lr = s.look ? (double)c.look / (double)s.look : 0.0;
    std::cout << "ratio insert=" << ir << "x lookup=" << lr << "x\n";
    return 0;
}}
"""


# Integral-key probe: std::hash<integer> is identity on libstdc++/libc++, so keys
# ``bucket + j*bucket_count`` all land in one bucket. (If a stdlib were not
# identity the probe simply reports a low ratio — no false confirmation.)
_INTEGRAL_PROBE_TEMPLATE = r"""// Auto-generated by HashTrace (dynamic validation).
// Finding: {location}
//   container {container} ({container_type})
//   op={operation} key={key!r}  key_type={key_type}
// Integral key: colliding values are bucket + j*bucket_count (std::hash identity).
//   g++ -std=c++17 -O2 {basename} -o /tmp/probe && /tmp/probe {n} {n}
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {{
using Clock = std::chrono::steady_clock;
using Key = {key_type};
using Map = std::unordered_map<Key, int>;

std::uint64_t us_since(Clock::time_point t) {{
    return (std::uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
        Clock::now() - t).count();
}}

std::size_t planned_buckets(std::size_t n) {{
    Map tmp;
    for (std::size_t i = 0; i < n; ++i) tmp.emplace((Key)i, 0);
    return tmp.bucket_count();
}}

std::vector<Key> sequential_keys(std::size_t n) {{
    std::vector<Key> v; v.reserve(n);
    for (std::size_t i = 0; i < n; ++i) v.push_back((Key)i);
    return v;
}}

std::vector<Key> colliding_keys(std::size_t n, std::size_t buckets, std::size_t bucket) {{
    std::vector<Key> v; v.reserve(n);
    for (std::uint64_t j = 1; v.size() < n; ++j)
        v.push_back((Key)(bucket + j * (std::uint64_t)buckets));
    return v;
}}

Key missing_key(std::size_t buckets, std::size_t bucket, const std::unordered_set<Key>& e) {{
    for (std::uint64_t j = 1;; ++j) {{
        Key k = (Key)(bucket + j * (std::uint64_t)buckets);
        if (!e.count(k)) return k;
    }}
}}

std::size_t max_bucket(const Map& m) {{
    std::size_t r = 0;
    for (std::size_t i = 0; i < m.bucket_count(); ++i) r = std::max(r, m.bucket_size(i));
    return r;
}}

struct R {{ std::uint64_t ins, look; std::size_t maxb; }};

R run(const std::vector<Key>& keys, std::size_t bucket, std::size_t rounds) {{
    Map m;
    auto t0 = Clock::now();
    for (Key k : keys) {{ auto it = m.find(k); if (it == m.end()) m.emplace(k, 1); }}
    auto ins = us_since(t0);
    std::unordered_set<Key> ex(keys.begin(), keys.end());
    Key miss = missing_key(m.bucket_count(), bucket, ex);
    volatile std::size_t sink = 0;
    auto t1 = Clock::now();
    for (std::size_t i = 0; i < rounds; ++i) sink += (m.find(miss) == m.end()) ? 0 : 1;
    auto look = us_since(t1); (void)sink;
    return R{{ins, look, max_bucket(m)}};
}}
}}  // namespace

int main(int argc, char** argv) {{
    std::size_t n = argc > 1 ? std::stoul(argv[1]) : {n};
    std::size_t rounds = argc > 2 ? std::stoul(argv[2]) : n;
    std::size_t bucket = 0, buckets = planned_buckets(n);
    R s = run(sequential_keys(n), bucket, rounds);
    R c = run(colliding_keys(n, buckets, bucket), bucket, rounds);
    std::cout << "n=" << n << " buckets=" << buckets << "\n";
    std::cout << "sequential insert_us=" << s.ins << " lookup_us=" << s.look << " max_bucket=" << s.maxb << "\n";
    std::cout << "colliding  insert_us=" << c.ins << " lookup_us=" << c.look << " max_bucket=" << c.maxb << "\n";
    double ir = s.ins ? (double)c.ins / (double)s.ins : 0.0;
    double lr = s.look ? (double)c.look / (double)s.look : 0.0;
    std::cout << "ratio insert=" << ir << "x lookup=" << lr << "x\n";
    return 0;
}}
"""


def _normalized_key_type(key_type: str) -> str:
    return " ".join(key_type.replace("const", "").split())


def generate_probe(candidate: HashDoSCandidate, *, n: int = 20000) -> str | None:
    """Return C++ probe source for ``candidate``, or None if not auto-verifiable."""
    if not can_generate(candidate):
        return None
    common = dict(
        location=f"{candidate.relative_path or candidate.path or '<buffer>'}:{candidate.line}",
        container=candidate.container.qualified_name,
        container_type=candidate.container.type_text,
        operation=candidate.operation.operation,
        key=candidate.operation.key_expr,
        basename=f"{probe_fingerprint(candidate)}_probe.cpp",
        n=n,
    )
    if _key_kind(candidate.container.key_type) == "integral":
        return _INTEGRAL_PROBE_TEMPLATE.format(
            key_type=_normalized_key_type(candidate.container.key_type or "int"),
            **common,
        )
    hasher = candidate.hasher
    is_spec = hasher is not None and _is_std_hash_specialization(hasher)
    polynomial = _specialization_byte_polynomial(hasher) if is_spec else None
    if hasher is not None and hasher.risk == "default":
        hasher_prelude = ""
        hasher_type = "std::hash<std::string>"
    elif is_spec and polynomial is None:
        # std::hash<T> specialization: either it delegates to std::hash (use the
        # default hash — faithful on libstdc++/libc++) or we can't reproduce it
        # standalone (a bare ``struct hash<T>`` won't compile) -> skip.
        if _specialization_delegates_to_std_hash(hasher):
            hasher_prelude = ""
            hasher_type = "std::hash<std::string>"
        else:
            return None
    elif polynomial is not None:
        # Synthesize a std::string hasher reproducing the std::hash<T>
        # specialization's byte-polynomial (a string-wrapper key's bytes are
        # identical to the std::string's, so bucket behaviour matches exactly).
        mult, folds_case = polynomial
        fold = " | 32" if folds_case else ""
        hasher_prelude = (
            "\nstruct SpecHash {\n"
            "  std::size_t operator()(const std::string& s) const noexcept {\n"
            "    std::uint64_t r = 0;\n"
            f"    for (unsigned char c : s) r = {mult}ull * r + "
            f"(std::uint64_t)(c{fold});\n"
            "    return (std::size_t)r;\n"
            "  }\n"
            "};\n"
        )
        hasher_type = "SpecHash"
    elif (
        hasher is not None
        and hasher.risk in _VERIFIABLE_CUSTOM_RISKS
        and _specialization_delegates_to_std_hash(hasher)
    ):
        # Named functor hasher that merely delegates to std::hash, optionally after
        # an order-preserving key transform (e.g. seastar's ``string_view_hash`` =>
        # ``std::hash<std::string_view>``; ``case_insensitive_hash`` => tolower then
        # ``std::hash<sstring>``). Embedding the functor fails to compile standalone
        # (it references framework string types like ``sstring``), but its bucket
        # behaviour on libstdc++/libc++ is the default ``std::hash<std::string>`` —
        # synthesize that faithfully instead of embedding.
        hasher_prelude = ""
        hasher_type = "std::hash<std::string>"
    else:  # custom fixed-seed/deterministic — embed its extracted source
        definition = _extract_hasher_definition(hasher)
        if definition is None:
            return None
        hasher_prelude = "\n" + definition + "\n"
        hasher_type = _hasher_terminal(hasher)
    return _PROBE_TEMPLATE.format(
        hasher_type=hasher_type,
        hasher_prelude=hasher_prelude,
        **common,
    )


@dataclass(frozen=True)
class ProbeResult:
    fingerprint: str
    location: str
    container: str
    probe_path: str
    generated: bool
    ran: bool = False
    insert_ratio: float | None = None
    lookup_ratio: float | None = None
    max_bucket: int | None = None
    confirmed: bool | None = None
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "location": self.location,
            "container": self.container,
            "probe_path": self.probe_path,
            "generated": self.generated,
            "ran": self.ran,
            "insert_ratio": self.insert_ratio,
            "lookup_ratio": self.lookup_ratio,
            "max_bucket": self.max_bucket,
            "confirmed": self.confirmed,
            "detail": self.detail,
        }


_RATIO_RE = re.compile(r"ratio insert=([\d.eE+]+)x lookup=([\d.eE+]+)x")
_MAXB_RE = re.compile(r"colliding.*max_bucket=(\d+)")
# A run confirms the finding when same-bucket work blows up vs. sequential.
_CONFIRM_RATIO = 8.0


def _find_compiler() -> str | None:
    for cc in ("g++", "clang++", "c++"):
        if shutil.which(cc):
            return cc
    return None


def verify_candidates(
    candidates: list[HashDoSCandidate],
    out_dir: str | Path,
    *,
    run: bool = False,
    n: int = 20000,
    min_score: float = 8.0,
    compiler: str | None = None,
) -> list[ProbeResult]:
    """Generate (and optionally compile+run) a probe for each eligible candidate."""
    out = Path(out_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    compiler = compiler or (_find_compiler() if run else None)
    results: list[ProbeResult] = []
    seen: set[str] = set()

    for candidate in candidates:
        # Static analysis already ruled out mitigated candidates (randomized hash
        # or key, guaranteed erase, small per-call operation cap); skip them.
        if candidate.status == "mitigated":
            continue
        if candidate.score < min_score or not can_generate(candidate):
            continue
        fp = probe_fingerprint(candidate)
        if fp in seen:
            continue
        seen.add(fp)
        source = generate_probe(candidate, n=n)
        if source is None:
            continue
        location = (
            f"{candidate.relative_path or candidate.path or '<buffer>'}:{candidate.line}"
        )
        probe_path = out / f"{fp}_probe.cpp"
        probe_path.write_text(source, encoding="utf-8")
        result = ProbeResult(
            fingerprint=fp,
            location=location,
            container=candidate.container.qualified_name,
            probe_path=str(probe_path),
            generated=True,
        )
        if run and compiler:
            result = _compile_and_run(result, probe_path, compiler, n)
        elif run and not compiler:
            result = ProbeResult(**{**result.to_dict(), "detail": "no C++ compiler found"})  # type: ignore[arg-type]
        results.append(result)
    return results


def _compile_and_run(
    result: ProbeResult, probe_path: Path, compiler: str, n: int
) -> ProbeResult:
    fields = result.to_dict()
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "probe"
        compile_proc = subprocess.run(
            [compiler, "-std=c++17", "-O2", str(probe_path), "-o", str(binary)],
            capture_output=True,
            text=True,
        )
        if compile_proc.returncode != 0:
            fields["detail"] = "compile failed: " + compile_proc.stderr.strip()[:200]
            return ProbeResult(**fields)
        try:
            run_proc = subprocess.run(
                [str(binary), str(n), str(n)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            fields["ran"] = True
            fields["detail"] = "probe timed out (likely severe degradation)"
            fields["confirmed"] = True
            return ProbeResult(**fields)
        output = run_proc.stdout
        ratio = _RATIO_RE.search(output)
        maxb = _MAXB_RE.search(output)
        fields["ran"] = True
        if ratio:
            fields["insert_ratio"] = float(ratio.group(1))
            fields["lookup_ratio"] = float(ratio.group(2))
            worst = max(fields["insert_ratio"] or 0.0, fields["lookup_ratio"] or 0.0)
            fields["confirmed"] = worst >= _CONFIRM_RATIO
        if maxb:
            fields["max_bucket"] = int(maxb.group(1))
        fields["detail"] = output.strip().replace("\n", " | ")
        return ProbeResult(**fields)


__all__ = [
    "ProbeResult",
    "can_generate",
    "generate_probe",
    "probe_fingerprint",
    "verify_candidates",
]
