#!/usr/bin/env python3
"""Verify a GrantAi export bundle offline. No GrantAi software, no network.

    python3 grantai-verify-bundle.py bundle.json [--trust-fingerprint <sha256 hex>]

Needs only Python 3 and the `openssl` command (or the `cryptography` package).

What it checks, in order:
  1. The signature over the bundle manifest, with the public key carried in the bundle.
     Compare the printed key fingerprint with the one your collector reports (its /health
     page, `grantai-ctl status`, or the Key Vault secret grantai-export-signing-pub); pass it
     with --trust-fingerprint to make the check mandatory.
  2. The hash chain, walked from genesis: every row's link hash, every prev_hash, every
     tombstone's claim and every delete event's commitment. The recomputed head must equal
     the signed head.
  3. Every exported record: SHA-256 of its verbatim content equals the content hash sealed
     in its chain row, and that row is live.
Exit code 0 when everything verifies, 1 otherwise.
"""
import base64, hashlib, json, os, shutil, subprocess, sys, tempfile

def sha256_hex(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def manifest_of(b: dict) -> bytes:
    recs = sorted(b.get("records", []), key=lambda r: int(r["seq"]))
    lines = ["grantai-bundle-v1", b["install_id"], b["generated_at"], b["chain"]["genesis"],
             b["chain"]["head_hash"], str(b["chain"]["count"])]
    lines += [f'{int(r["seq"])} {r["source"]} {r["content_sha256"]}' for r in recs]
    return ("\n".join(lines) + "\n").encode("utf-8")

def verify_signature(b: dict) -> tuple[bool, str]:
    sig = b["signature"]; pem = sig["public_key_pem"]; data = manifest_of(b); der = base64.b64decode(sig["value"])
    fp = sha256_hex(base64.b64decode("".join(l for l in pem.splitlines() if not l.startswith("-----"))))
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = serialization.load_pem_public_key(pem.encode())
        key.verify(der, data, ec.ECDSA(hashes.SHA256())); return True, fp
    except ImportError:
        pass
    except Exception:
        return False, fp
    if not shutil.which("openssl"): return False, fp + " (neither the cryptography package nor openssl is available)"
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "pub.pem"), "w").write(pem); open(os.path.join(d, "sig.der"), "wb").write(der); open(os.path.join(d, "data"), "wb").write(data)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", os.path.join(d, "pub.pem"), "-signature", os.path.join(d, "sig.der"), os.path.join(d, "data")], capture_output=True, text=True)
        return r.returncode == 0 and "Verified OK" in r.stdout, fp

def walk_chain(rows: list, genesis: str) -> tuple[str, list]:
    """Mirror of the collector's verifyChainRows, minus the store (content is checked per record)."""
    broken = []; prev = genesis
    by_seq = {int(r["seq"]): r for r in rows}
    claimed = {}
    for r in rows:
        if r["kind"] == "teach" and r.get("deleted") and int(r.get("deleted_seq") or 0) > 0:
            claimed.setdefault(int(r["deleted_seq"]), []).append(int(r["seq"]))
    for r in sorted(rows, key=lambda r: int(r["seq"])):
        seq = int(r["seq"])
        def bad(reason, detail=""): broken.append({"seq": seq, "kind": r["kind"], "source": r["source"], "reason": reason, "detail": detail})
        if r["prev_hash"] != prev: bad("prev_hash_mismatch", "row prev_hash does not equal previous row's sha256")
        if r["kind"] == "teach" and r.get("deleted"):
            ds = int(r.get("deleted_seq") or 0)
            if ds <= 0: bad("tombstone_unattributed")
            elif ds not in by_seq: bad("tombstone_dangling", f"names seq {ds}, not in the chain")
            elif ds <= seq: bad("tombstone_not_later", f"names seq {ds}")
            elif by_seq[ds]["source"] != r["source"]: bad("tombstone_wrong_source", f"names seq {ds}")
        elif r["kind"] == "delete":
            commitment = "tombstone:" + r["source"] + "".join(f":{q}" for q in sorted(claimed.get(seq, [])))
            if sha256_hex(commitment.encode()) != r["content_sha256"]: bad("delete_commitment_mismatch", "the rows pointing at this event are not the rows it sealed")
        if sha256_hex((r["prev_hash"] + r["content_sha256"]).encode()) != r["sha256"]: bad("link_mismatch", "sha256 != SHA256(prev_hash || content_sha256)")
        prev = r["sha256"]
    return prev, broken

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"): print(__doc__); sys.exit(2)
    b = json.load(open(sys.argv[1], encoding="utf-8"))
    trust = sys.argv[sys.argv.index("--trust-fingerprint") + 1] if "--trust-fingerprint" in sys.argv else None
    ok = True
    print(f"bundle v{b.get('bundle_version')} from install {b.get('install_id')} generated {b.get('generated_at')} by {b.get('product')} {b.get('server_version')}")
    sig_ok, fp = verify_signature(b)
    print(f"[{'ok' if sig_ok else 'FAIL'}] signature {b['signature'].get('alg')} ; signing key fingerprint sha256:{fp}")
    ok &= sig_ok
    if trust:
        t_ok = trust.lower().replace("sha256:", "") == fp.lower(); ok &= t_ok
        print(f"[{'ok' if t_ok else 'FAIL'}] signing key matches the trusted fingerprint")
    else:
        print("      (compare this fingerprint with the collector's; pass --trust-fingerprint to enforce)")
    rows = b["chain"]["rows"]; head, broken = walk_chain(rows, b["chain"]["genesis"])
    head_ok = (head == b["chain"]["head_hash"]) and (len(rows) == int(b["chain"]["count"])) and not broken
    print(f"[{'ok' if head_ok else 'FAIL'}] chain: {len(rows)} rows from genesis, recomputed head {head[:16]}… {'==' if head == b['chain']['head_hash'] else '!='} signed head {b['chain']['head_hash'][:16]}…, {len(broken)} broken link(s)")
    for x in broken[:10]: print(f"      seq {x['seq']} {x['kind']} {x['source']}: {x['reason']} {x['detail']}")
    ok &= head_ok
    by_seq = {int(r["seq"]): r for r in rows}; n_ok = 0
    for rec in b.get("records", []):
        row = by_seq.get(int(rec["seq"])); h = sha256_hex(rec["content"].encode("utf-8"))
        problems = []
        if row is None: problems.append("no chain row with that seq")
        else:
            if row["kind"] != "teach" or row["source"] != rec["source"]: problems.append("chain row is not a teach row for this source")
            if row.get("deleted"): problems.append("chain row is tombstoned (record was replaced or deleted later)")
            if row["content_sha256"] != rec["content_sha256"]: problems.append("record hash differs from the sealed hash")
        if h != rec["content_sha256"]: problems.append("content does not hash to content_sha256 (content altered)")
        if problems: ok = False; print(f"[FAIL] record seq {rec['seq']} {rec['source']}: " + "; ".join(problems))
        else: n_ok += 1
    print(f"[{'ok' if n_ok == len(b.get('records', [])) else 'FAIL'}] records: {n_ok}/{len(b.get('records', []))} re-hashed to their sealed content hash and bound to live chain rows")
    print("RESULT:", "VERIFIED" if ok else "NOT VERIFIED")
    sys.exit(0 if ok else 1)

if __name__ == "__main__": main()
