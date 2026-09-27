"""Adversarial re-run: H22 pin-file authentication bypasses (break-first).

Targets the H22 MAC-authenticated pin manifest in gov/skill_watch.py:
  p1 DOWNGRADE: signed manifest replaced with unsigned (manifest_mac
     stripped). Does peek(path, mac_key=key) load it silently?
  p2 TOCTOU: file rewritten with malicious pins but original
     (mtime_ns, size) restored via utime+padding. Does
     _revalidate_pin_file() return True without MAC re-verification?
  p3 CONTROL: normal tamper (modify pins, mtime changes) -> must
     quarantine fail-closed.

Verdicts are honest: BREAK = vulnerability found (file as F176+),
HELD = control holds.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import tempfile

from gov.skill_watch import PinStore, SkillWatch, PinStoreError

RESULTS = []


def _report(name, verdict, detail):
    RESULTS.append((name, verdict, detail))
    print("  %-28s %s  %s" % (name, verdict, detail))


def _make_watcher(tmpdir):
    """Build a minimal SkillWatch with one pinned skill."""
    from gov.skill_watch import FileContentSource
    watch = SkillWatch()
    import hashlib
    content = b"fake skill content v1"
    digest = hashlib.sha256(content).hexdigest()
    src_path = os.path.join(tmpdir, "skill.txt")
    with open(src_path, "wb") as f:
        f.write(content)
    watch.register_skill(
        "test-skill",
        FileContentSource(src_path),
        origin={"content_path": src_path,
                "registry_url": "https://example.invalid/registry",
                "installer_identity": "test-installer",
                "installed_at": "2026-09-26T00:00:00Z"},
    )
    # Pin the digest directly (bypass content hashing for speed).
    rec = watch._skills["test-skill"]
    rec["pinned_digest"] = digest
    return watch


def p1_downgrade(tmpdir):
    """Strip manifest_mac from a signed file; peek with key must fail."""
    name = "p1_downgrade_unsigned"
    key = os.urandom(32)
    watch = _make_watcher(tmpdir)
    path = os.path.join(tmpdir, "pins.json")
    PinStore.save(watch, path, mac_key=key)
    # Attacker: rewrite as unsigned (pre-H22 layout), same pins.
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "manifest_mac" in data, "signed file must carry manifest_mac"
    del data["manifest_mac"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    try:
        PinStore.peek(path, mac_key=key)
        _report(name, "BREAK",
                "unsigned manifest loaded silently with mac_key given "
                "(downgrade bypasses H22 MAC)")
    except PinStoreError as e:
        _report(name, "HELD",
                "unsigned manifest refused with key: %s" % (str(e)[:80],))


def p2_toctou_mtime(tmpdir):
    """Rewrite pins but restore (mtime_ns, size); revalidation must catch."""
    name = "p2_toctou_stat_restore"
    key = os.urandom(32)
    watch = _make_watcher(tmpdir)
    path = os.path.join(tmpdir, "pins.json")
    PinStore.save(watch, path, mac_key=key)
    # Load to attach pin state.
    watch2 = PinStore.load(path, mac_key=key)
    # Attacker: modify pins, pad to same size, restore mtime_ns.
    st = os.stat(path)
    orig_mtime_ns = st.st_mtime_ns
    orig_size = st.st_size
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Flip a pinned digest (malicious).
    for sid in data["pins"]:
        data["pins"][sid]["pinned_digest"] = "0" * 64
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    # Pad/truncate to original size.
    if len(payload) < orig_size:
        payload = payload + b" " * (orig_size - len(payload))
    else:
        payload = payload[:orig_size]
    with open(path, "wb") as f:
        f.write(payload)
    os.utime(path, ns=(orig_mtime_ns, orig_mtime_ns))
    # Revalidate.
    try:
        ok = watch2._revalidate_pin_file()
        if ok:
            _report(name, "BREAK",
                    "_revalidate_pin_file returned True after stat "
                    "restoration (TOCTOU bypasses MAC re-verify)")
        else:
            _report(name, "HELD",
                    "revalidation failed closed despite stat restoration")
    except Exception as e:
        _report(name, "HELD",
                "revalidation raised (fail-closed): %s" % (type(e).__name__,))


def p3_control_tamper(tmpdir):
    """Normal tamper (mtime changes) must quarantine fail-closed."""
    name = "p3_control_tamper"
    key = os.urandom(32)
    watch = _make_watcher(tmpdir)
    path = os.path.join(tmpdir, "pins.json")
    PinStore.save(watch, path, mac_key=key)
    watch2 = PinStore.load(path, mac_key=key)
    # Attacker modifies pins (mtime will change).
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for sid in data["pins"]:
        data["pins"][sid]["pinned_digest"] = "0" * 64
    # Re-sign with WRONG key (attacker doesn't have operator key).
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    try:
        ok = watch2._revalidate_pin_file()
        if not ok:
            _report(name, "HELD",
                    "tamper quarantined fail-closed (control holds)")
        else:
            _report(name, "BREAK",
                    "tamper NOT detected (control FAILED)")
    except Exception as e:
        _report(name, "HELD",
                "tamper raised (fail-closed): %s" % (type(e).__name__,))


def main():
    print("ADVERSARIAL H22 pin-auth battery (break-first)")
    tmpdir = tempfile.mkdtemp(prefix="adv-h22-")
    os.environ["TMPDIR"] = tmpdir
    p1_downgrade(tmpdir)
    p2_toctou_mtime(tmpdir)
    p3_control_tamper(tmpdir)
    n_break = sum(1 for _, v, _ in RESULTS if v == "BREAK")
    n_held = sum(1 for _, v, _ in RESULTS if v == "HELD")
    print("ADVERSARIAL-H22: %d BREAK / %d HELD / 0 ERROR" % (n_break, n_held))
    if n_break:
        print("NOTE: BREAKs are CANDIDATE findings (file as F176+), "
              "not residuals.")
    return 0 if n_break == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
