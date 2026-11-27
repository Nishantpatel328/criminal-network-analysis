"""Pseudonymization — the Z3 → Z4 boundary.

Runs inside the exporter (Z2), which is the only component holding the
pseudonymization key. The analytics tier receives surrogates and cannot invert
them; the crosswalk that permits re-identification never leaves Z2.

KEY DESIGN CHOICE: PER-SNAPSHOT KEYS
Surrogates are derived from a key that is itself derived per snapshot:

    K_snapshot = HKDF-SHA256(master, salt=snapshot_id, info="cna-surrogate-v1")
    surrogate  = base32(HMAC-SHA256(K_snapshot, entity_uuid)[:16])

The consequence is that the same person gets a different surrogate in every
snapshot. That is the point: an adversary who obtains two snapshots cannot
correlate them to track an individual over time, which is the main residual risk
of a globally-stable pseudonym.

The cost is that we lose trivial cross-snapshot diffing, and "did this cluster
change since last week?" is a question analysts legitimately ask. So the exporter
also emits an encrypted crosswalk, retained in Z2 only, that lets the API align
consecutive snapshots on demand. The capability still exists; it just requires
going through the tier that enforces authorization.

Truncation to 128 bits keeps the projection small. Collision probability at
national tier (5e8 vertices) is about 4e-22 by the birthday bound, which is
negligible; `SurrogateMap` asserts on collision anyway, because a silent
collision would merge two people into one vertex and that is exactly the kind of
error that would be invisible in the output and catastrophic in effect.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, Mapping, Optional, Tuple

from .env_guard import assert_production_safe

SURROGATE_BYTES = 16          # 128 bits
INFO = b"cna-surrogate-v1"


def hkdf_sha256(master: bytes, salt: bytes, info: bytes,
                length: int = 32) -> bytes:
    """RFC 5869 HKDF. Standard-library only, so it is auditable in place.

    In production the extract step happens inside the HSM and `master` never
    enters this process; this implementation is what the HsmKeyProvider shim
    mirrors for local development.
    """
    if length > 255 * 32:
        raise ValueError("requested key material too long")
    prk = hmac.new(salt, master, hashlib.sha256).digest()
    okm, previous, counter = b"", b"", 1
    while len(okm) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        okm += previous
        counter += 1
    return okm[:length]


class KeyProvider:
    """Interface to the HSM/KMS. Production: PKCS#11 or cloud KMS."""

    def snapshot_key(self, snapshot_id: str) -> bytes:  # pragma: no cover
        raise NotImplementedError


class LocalKeyProvider(KeyProvider):
    """Development and test only.

    Holds the master key in process memory, which defeats the purpose of the HSM
    boundary. `env_guard.assert_production_safe()` in the constructor refuses to
    instantiate this class outside a development or test environment.

    The check is in `__init__` rather than in a factory on purpose. A factory is
    bypassed by importing the class directly, and the person most likely to do
    that is someone debugging a production incident at 3am.
    """

    def __init__(self, master: Optional[bytes] = None,
                 env: Optional[Mapping[str, str]] = None) -> None:
        assert_production_safe("LocalKeyProvider", env)
        self._master = master or os.urandom(32)
        if len(self._master) < 32:
            raise ValueError("master key must be at least 256 bits")

    def snapshot_key(self, snapshot_id: str) -> bytes:
        return hkdf_sha256(self._master, snapshot_id.encode("utf-8"), INFO)


def surrogate_for(entity_uuid: str, snapshot_key: bytes) -> str:
    """One surrogate. base32 without padding: case-insensitive, URL-safe,
    and unambiguous in logs — unlike base64, which puts '/' and '+' into
    identifiers that then end up in URL paths and file names."""
    mac = hmac.new(snapshot_key, entity_uuid.encode("utf-8"), hashlib.sha256)
    return base64.b32encode(mac.digest()[:SURROGATE_BYTES]).decode("ascii").rstrip("=")


@dataclass
class SurrogateMap:
    """Bidirectional map for one snapshot. NEVER leaves Z2.

    Serialized only as the envelope-encrypted crosswalk blob. If this object is
    written to disk in plaintext, the pseudonymity boundary is gone — so the
    class deliberately has no to_json / __str__ that would emit the mapping, and
    __repr__ reports sizes only.
    """
    snapshot_id: str
    _forward: Dict[str, str] = field(default_factory=dict, repr=False)
    _reverse: Dict[str, str] = field(default_factory=dict, repr=False)

    def add(self, entity_uuid: str, surrogate: str) -> None:
        existing = self._reverse.get(surrogate)
        if existing is not None and existing != entity_uuid:
            # A truncation collision would silently merge two people into one
            # graph vertex, producing a community assignment that is wrong in a
            # way nobody could see downstream. Fail the export instead.
            raise RuntimeError(
                f"surrogate collision in snapshot {self.snapshot_id}: "
                f"two distinct entities map to the same surrogate. "
                f"Increase SURROGATE_BYTES and re-export."
            )
        self._forward[entity_uuid] = surrogate
        self._reverse[surrogate] = entity_uuid

    def to_surrogate(self, entity_uuid: str) -> Optional[str]:
        return self._forward.get(entity_uuid)

    def to_entity(self, surrogate: str) -> Optional[str]:
        """Re-identification. Called only from the API tier, only after a PDP
        permit, and always followed by a REIDENTIFIED_SURROGATE audit event."""
        return self._reverse.get(surrogate)

    def __len__(self) -> int:
        return len(self._forward)

    def __repr__(self) -> str:
        return (f"SurrogateMap(snapshot_id={self.snapshot_id!r}, "
                f"entries={len(self._forward)})")


@dataclass(frozen=True)
class PseudonymEdge:
    """An edge as the analytics tier sees it. No identities, no descriptions.

    Note what is absent: names, phone numbers, dates, locations, case IDs, free
    text. Everything modularity optimisation needs and nothing else.

    `weight_ci` is the relative uncertainty on the weight, needed by the
    stability bootstrap in Z4. We pass the collapsed scalar rather than the raw
    5x5x5 grades: the grades are what the UI renders, and the UI is served from
    Z3 through the API, so Z4 has no need of them. One number instead of three
    is the minimal thing that crosses the boundary and still supports the
    perturbation model.
    """
    src: str
    dst: str
    weight: float
    rel_type: str
    weight_ci: float = 0.2


class Pseudonymizer:
    def __init__(self, key_provider: KeyProvider, snapshot_id: str) -> None:
        self._key = key_provider.snapshot_key(snapshot_id)
        self.snapshot_id = snapshot_id
        self.mapping = SurrogateMap(snapshot_id)

    def _surrogate(self, entity_uuid: str) -> str:
        existing = self.mapping.to_surrogate(entity_uuid)
        if existing is not None:
            return existing
        s = surrogate_for(entity_uuid, self._key)
        self.mapping.add(entity_uuid, s)
        return s

    def transform(self, rows: Iterable[dict]) -> Iterator[PseudonymEdge]:
        """Convert exporter rows into pseudonymous edges.

        Expects rows shaped like graph/registry.py Q_EXPORT_PROJECTION output:
        src, dst, rel_type, weight, source_eval, intel_assessment.
        """
        from .weighting import confidence_interval, confidence_weight

        for row in rows:
            src_uuid, dst_uuid = row["src"], row["dst"]
            if src_uuid == dst_uuid:
                continue  # self-loops carry no community information
            source_eval = int(row.get("source_eval", 5))
            intel_assessment = int(row.get("intel_assessment", 4))
            w = confidence_weight(
                base_weight=float(row.get("weight", 1.0)),
                source_eval=source_eval,
                intel_assessment=intel_assessment,
            )
            if w <= 0.0:
                continue  # excluded by the confidence floor
            yield PseudonymEdge(
                src=self._surrogate(src_uuid),
                dst=self._surrogate(dst_uuid),
                weight=w,
                rel_type=str(row["rel_type"]),
                weight_ci=confidence_interval(source_eval, intel_assessment),
            )

    def assert_no_identities(self, edges: Iterable[PseudonymEdge]) -> None:
        """Startup/export-time assertion that nothing identifying leaked into
        the projection.

        Surrogates are base32 of a fixed length; anything else in a vertex slot
        means a code path bypassed `_surrogate`, which is precisely the bug that
        would quietly send real UUIDs (and thus a joinable identifier) into Z4.
        """
        expected_len = len(base64.b32encode(b"\x00" * SURROGATE_BYTES)
                          .decode().rstrip("="))
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        for e in edges:
            for v in (e.src, e.dst):
                if len(v) != expected_len or not set(v) <= allowed:
                    raise RuntimeError(
                        "non-surrogate value found in analytics projection — "
                        "pseudonymity boundary violated"
                    )
