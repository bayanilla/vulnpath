"""Behaviour detection: scanning, brute force and firewall IPS verdicts, per source, in fixed time windows.

Every rule is deterministic and explains itself in the detection's `detail` text. Detection runs on the
traffic before any vulnerability data is considered; the join to Nessus happens afterwards (correlate.py).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from .model import Connection, EvidenceRef

SET_CAP = 4096            # distinct hosts or ports remembered per source and window
SAMPLE_CAP = 3            # evidence lines kept per window key
SHORT_SESSION_SECONDS = 10.0
LONG_SESSION_SECONDS = 300.0
LONG_SESSION_BYTES = 100_000
SPRAY_MIN_USERS = 5

KIND_LABEL = {
    "ips-exploit": "IPS exploit detection",
    "auth-brute-force": "Failed logins (authentication logs)",
    "ips-brute-force": "IPS brute-force detection",
    "brute-force": "Brute-force connection pattern",
    "vertical-scan": "Port scan of this host",
    "horizontal-scan": "Sweep across hosts",
    "ips-scan": "Firewall scan detection",
}
CREDENTIAL_KINDS = {"auth-brute-force", "ips-brute-force", "brute-force"}


@dataclass
class Detection:
    kind: str
    src: str
    scope: tuple                       # what the rule grouped on, e.g. (port, proto) for a sweep
    first: float
    last: float
    windows: int = 0
    attempts: int = 0
    failed: int = 0
    established: int = 0
    targets: set = field(default_factory=set)       # {(dst, port, proto)}
    n_targets: int = 0                              # may exceed len(targets) when capped
    detail: str = ""
    evidence: list = field(default_factory=list)    # EvidenceRef
    # brute force / authentication
    success: bool = False
    success_at: float | None = None
    success_detail: str = ""
    success_evidence: list = field(default_factory=list)
    users: set = field(default_factory=set)
    # IPS
    blocked: int = 0
    not_blocked: int = 0
    cves: set = field(default_factory=set)
    signatures: dict = field(default_factory=dict)
    routine: bool = False
    routine_reason: str = ""

    @property
    def label(self) -> str:
        return KIND_LABEL[self.kind]


def _sample(lst: list, ref: EvidenceRef | None, cap: int = SAMPLE_CAP) -> None:
    if ref is not None and len(lst) < cap:
        lst.append(ref)


class Behaviour:
    """Accumulates per-window state while the traffic streams past, then evaluates the rules once."""

    def __init__(self, settings):
        self.s = settings
        self.win = max(int(settings.window_minutes * 60), 60)
        self.auth_ports = set(settings.auth_ports)
        # (src, port, proto, bucket) -> [dsts, failed, total, first, last, samples]
        self.sweep: dict[tuple, list] = {}
        # (src, dst, proto, bucket) -> [ports, failed, total, first, last, samples]
        self.portscan: dict[tuple, list] = {}
        # (src, dst, port, proto, bucket) -> [n, short, failed, sum_bytes, sumsq_bytes, first, last, samples]
        self.brute: dict[tuple, list] = {}
        # (src, dst, port, proto) -> [(ts, seconds, bytes, ref)] long sessions on an auth port
        self.long: dict[tuple, list] = {}
        # (src, dst, port, proto, service, bucket) -> [failures, successes, users, first, last, samples]
        self.auth: dict[tuple, list] = {}
        # (src, dst, port, proto, service) -> [(ts, user, ref)] successful logins
        self.auth_ok: dict[tuple, list] = {}
        # (src, dst, port, proto, kind) -> Detection, built directly (IPS verdicts need no threshold)
        self.ips: dict[tuple, Detection] = {}
        self.ips_other = 0

    # ---- intake -------------------------------------------------------------------------------------
    def add_conn(self, c: Connection) -> None:
        b = int(c.ts // self.win)
        failed = c.outcome != "established"
        ref = c.evidence
        k = (c.src, c.dst_port, c.proto, b)
        st = self.sweep.get(k)
        if st is None:
            st = self.sweep[k] = [set(), 0, 0, c.ts, c.ts, []]
        if len(st[0]) < SET_CAP:
            st[0].add(c.dst)
        st[1] += failed
        st[2] += 1
        st[3], st[4] = min(st[3], c.ts), max(st[4], c.ts)
        if failed:
            _sample(st[5], ref)

        k = (c.src, c.dst, c.proto, b)
        st = self.portscan.get(k)
        if st is None:
            st = self.portscan[k] = [set(), 0, 0, c.ts, c.ts, []]
        if len(st[0]) < SET_CAP:
            st[0].add(c.dst_port)
        st[1] += failed
        st[2] += 1
        st[3], st[4] = min(st[3], c.ts), max(st[4], c.ts)
        if failed:
            _sample(st[5], ref)

        if c.dst_port in self.auth_ports and c.proto == "tcp":
            size = c.orig_bytes
            long_session = (c.duration or 0) >= LONG_SESSION_SECONDS or c.orig_bytes + c.resp_bytes >= LONG_SESSION_BYTES
            if long_session and not failed:
                lst = self.long.setdefault((c.src, c.dst, c.dst_port, c.proto), [])
                if len(lst) < 5:
                    lst.append((c.ts, c.duration, c.orig_bytes + c.resp_bytes, ref))
            short = failed or (c.duration is not None and c.duration < SHORT_SESSION_SECONDS)
            k = (c.src, c.dst, c.dst_port, c.proto, b)
            st = self.brute.get(k)
            if st is None:
                st = self.brute[k] = [0, 0, 0, 0, 0, c.ts, c.ts, []]
            st[0] += 1
            st[1] += short
            st[2] += failed
            st[3] += size
            st[4] += size * size
            st[5], st[6] = min(st[5], c.ts), max(st[6], c.ts)
            _sample(st[7], ref)

    def add_auth(self, c: Connection) -> None:
        a = c.auth
        if a.success:
            lst = self.auth_ok.setdefault((c.src, c.dst, c.dst_port, c.proto, a.service), [])
            if len(lst) < 5:
                lst.append((c.ts, a.user, c.evidence))
        if not a.failures:
            return
        k = (c.src, c.dst, c.dst_port, c.proto, a.service, int(c.ts // self.win))
        st = self.auth.get(k)
        if st is None:
            st = self.auth[k] = [0, 0, set(), c.ts, c.ts, []]
        st[0] += a.failures
        if a.user and len(st[2]) < 1000:
            st[2].add(a.user)
        st[3], st[4] = min(st[3], c.ts), max(st[4], c.ts)
        _sample(st[5], c.evidence)

    def add_threat(self, c: Connection) -> None:
        th = c.threat
        if th.subtype == "scan":
            kind = "ips-scan"
        elif th.subtype == "vulnerability":
            kind = "ips-brute-force" if th.is_brute_force else "ips-exploit"
        else:
            self.ips_other += 1   # spyware, virus, url, file...: not an attack on the listening service
            return
        k = (c.src, c.dst, c.dst_port, c.proto, kind)
        d = self.ips.get(k)
        if d is None:
            d = self.ips[k] = Detection(kind, c.src, (c.dst, c.dst_port, c.proto), c.ts, c.ts,
                                        targets={(c.dst, c.dst_port, c.proto)}, n_targets=1)
        d.first, d.last = min(d.first, c.ts), max(d.last, c.ts)
        d.attempts += th.repeat
        if th.blocked:
            d.blocked += th.repeat
        else:
            d.not_blocked += th.repeat
        d.cves.update(th.cves)
        if len(d.signatures) < 20 or th.name in d.signatures:
            d.signatures[th.name] = d.signatures.get(th.name, 0) + th.repeat
        _sample(d.evidence, c.evidence, 5)

    # ---- evaluation ---------------------------------------------------------------------------------
    def evaluate(self) -> list[Detection]:
        s = self.s
        mins = self.s.window_minutes
        out: dict[tuple, Detection] = {}

        def merge(kind, src, scope, st_first, st_last, attempts, failed, targets, n_targets, samples):
            k = (kind, src, scope)
            d = out.get(k)
            if d is None:
                d = out[k] = Detection(kind, src, scope, st_first, st_last)
            d.first, d.last = min(d.first, st_first), max(d.last, st_last)
            d.windows += 1
            d.attempts += attempts
            d.failed += failed
            d.established += attempts - failed
            for t in targets:
                if len(d.targets) < SET_CAP:
                    d.targets.add(t)
            d.n_targets = max(d.n_targets, n_targets, len(d.targets))
            for r in samples:
                _sample(d.evidence, r, 5)
            return d

        for (src, port, proto, _), (dsts, failed, total, first, last, smp) in self.sweep.items():
            if len(dsts) >= s.sweep_min_hosts and failed / total >= s.scan_min_failed:
                merge("horizontal-scan", src, (port, proto), first, last, total, failed,
                      [(d, port, proto) for d in dsts], len(dsts), smp)
        for (src, dst, proto, _), (ports, failed, total, first, last, smp) in self.portscan.items():
            if len(ports) >= s.portscan_min_ports and failed / total >= s.scan_min_failed:
                merge("vertical-scan", src, (dst, proto), first, last, total, failed,
                      [(dst, p, proto) for p in ports], len(ports), smp)
        for (src, dst, port, proto, _), (n, short, failed, sb, ssb, first, last, smp) in self.brute.items():
            if n < s.brute_min_attempts or short / n < 0.8:
                continue
            mean = sb / n
            cv = math.sqrt(max(ssb / n - mean * mean, 0)) / mean if mean else 0.0
            if failed / n >= s.scan_min_failed or cv <= 0.25:
                merge("brute-force", src, (dst, port, proto), first, last, n, failed, [(dst, port, proto)], 1, smp)
        for (src, dst, port, proto, svc, _), (fails, _ok, users, first, last, smp) in self.auth.items():
            if fails >= s.auth_min_failures:
                d = merge("auth-brute-force", src, (dst, port, proto, svc), first, last, fails, fails,
                          [(dst, port, proto)], 1, smp)
                d.users.update(list(users)[:1000 - len(d.users)])

        for d in out.values():
            self._describe(d, mins)
        dets = list(out.values()) + list(self.ips.values())
        for d in self.ips.values():
            self._describe_ips(d)
        self._suppress_routine(dets)
        dets.sort(key=lambda d: (d.src, d.kind, d.scope))
        return dets

    def _describe(self, d: Detection, mins: float) -> None:
        win = f"{d.windows} window(s) of {mins:g} min"
        if d.kind == "horizontal-scan":
            port, proto = d.scope
            d.detail = (f"contacted {d.n_targets} hosts on {proto}/{port}; {d.failed} of {d.attempts} connections "
                        f"failed or were denied ({win})")
        elif d.kind == "vertical-scan":
            dst, proto = d.scope
            d.detail = (f"tried {d.n_targets} {proto} ports on {dst}; {d.failed} of {d.attempts} connections failed "
                        f"or were denied ({win})")
        elif d.kind == "brute-force":
            dst, port, proto = d.scope
            d.detail = (f"{d.attempts} short, repetitive connections to {dst} {proto}/{port}, "
                        f"{d.failed} failed ({win})")
            for ts, secs, size, ref in sorted(self.long.get((d.src, dst, port, proto), []), key=lambda x: x[0]):
                if ts >= d.first:
                    d.success, d.success_at = True, ts
                    d.success_detail = (f"a long session followed the attempts ({secs or 0:.0f} s, {size:,} bytes): "
                                        "possible successful login")
                    d.success_evidence = [ref] if ref else []
                    break
        elif d.kind == "auth-brute-force":
            dst, port, proto, svc = d.scope
            d.detail = f"{d.failed} failed {svc} logins against {dst} {proto}/{port} ({win})"
            if len(d.users) >= SPRAY_MIN_USERS:
                d.detail += f"; {len(d.users)} different user names (password-spraying pattern)"
            for ts, user, ref in sorted(self.auth_ok.get((d.src, dst, port, proto, svc), []), key=lambda x: x[0]):
                if ts >= d.first:
                    d.success, d.success_at = True, ts
                    d.success_detail = (f"a successful {svc} login{' as ' + user if user else ''} followed the "
                                        "failures")
                    d.success_evidence = [ref] if ref else []
                    break

    @staticmethod
    def _describe_ips(d: Detection) -> None:
        dst, port, proto = d.scope
        what = {"ips-exploit": "exploit", "ips-brute-force": "brute-force", "ips-scan": "scan"}[d.kind]
        d.detail = (f"{d.attempts} firewall {what} detection(s) against {dst} {proto}/{port}: "
                    f"{d.not_blocked} not blocked, {d.blocked} blocked")
        d.failed = d.blocked
        d.windows = 1

    def _suppress_routine(self, dets: list[Detection]) -> None:
        """Peer baseline for the connection-pattern brute-force rule.

        Many internal clients legitimately open short, similar connections to the same server (SMB, SQL).
        When at least `peer_min_sources` internal sources match the rule against one service, the ones whose
        attempt count is within 3x the median are marked routine. External sources are never suppressed.
        """
        by_target: dict[tuple, list[Detection]] = {}
        for d in dets:
            if d.kind == "brute-force" and self.s.is_internal(d.src):
                by_target.setdefault(d.scope, []).append(d)
        for scope, group in by_target.items():
            if len(group) < self.s.peer_min_sources:
                continue
            counts = sorted(d.attempts for d in group)
            median = counts[len(counts) // 2]
            for d in group:
                if d.attempts <= 3 * median and not d.success:
                    d.routine = True
                    d.routine_reason = (f"{len(group)} internal sources show the same pattern against this service "
                                        f"(median {median} connections); treated as normal use")
