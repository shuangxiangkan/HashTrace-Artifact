"""Recognise keys whose value is server-generated / random, not attacker-chosen.

If the hashed key derives from a random-id or CSPRNG generator, an attacker
cannot pick colliding keys, so the HashDoS candidate is a strong down-weight
(mirrors the hasher-randomization signal, applied to the *key* provenance).

This is an **intra-function** heuristic: it expands the key expression over the
function's single-assignment definitions (``code_scan.ssa``) and looks for a call
to a known random generator. A key that is assigned both a random *and* a tainted
value is ``ambiguous`` in the SSA digest and therefore left un-expanded — so this
never fires on it, which is the safe direction (never mask a real attacker key).
"""

from __future__ import annotations

import re

from code_scan import ssa

from .model import KeySourceFact

# Terminal call names that produce unpredictable, server-side values. Matched as
# a call (``name(``) so a variable merely *named* ``uuid`` does not qualify; a
# leading ``::`` / ``.`` is allowed so ``drogon::utils::getUuid()`` matches too.
_RANDOM_KEY_APIS = (
    # random id / uuid / token helpers (framework and app conventions)
    "random_alphanum", "random_string", "randomString", "randomStr",
    "genRandomString", "genRandomStr", "generateRandomString", "randomHex",
    "randomBytes", "generateToken", "genToken",
    "getUuid", "get_uuid", "generateUuid", "generateUUID", "genUuid",
    "uuid_generate", "uuid_generate_random", "newUuid",
    # CSPRNG primitives
    "getrandom", "getentropy", "RAND_bytes", "RAND_priv_bytes",
    "arc4random", "arc4random_buf", "arc4random_uniform",
    "BCryptGenRandom", "CCRandomGenerateBytes",
)

_RANDOM_CALL_RE = re.compile(
    r"(?<![\w])(" + "|".join(re.escape(name) for name in _RANDOM_KEY_APIS) + r")\s*\("
)

# Applied when the key is proven server-random: decisive enough to mitigate the
# candidate on its own (status/confidence are also forced in the detector).
_RANDOM_KEY_ADJUSTMENT = -5.0


def analyze_key_source(
    key_expr: str, definitions: ssa.Defs
) -> KeySourceFact | None:
    """Return a randomized-key fact when the key derives from a random generator.

    ``None`` means "no evidence of randomization" — the conservative default that
    leaves the candidate unchanged.
    """
    if not key_expr:
        return None
    expanded = ssa.expand(key_expr, definitions)
    match = _RANDOM_CALL_RE.search(expanded)
    if match is None:
        return None
    generator = match.group(1)
    return KeySourceFact(
        randomized=True,
        generator=generator,
        score_adjustment=_RANDOM_KEY_ADJUSTMENT,
        evidence=(
            f"key derives from server-generated random source {generator}(); "
            "an attacker cannot choose colliding keys",
        ),
    )


__all__ = ["analyze_key_source"]
