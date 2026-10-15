#!/usr/bin/env python3
"""
SecurityKit inbound webhook probes (optional, dynamic, standard library only).

Sends requests a genuine sender would never send, and records whether the receiver accepts them:
  1. no signature at all                         -> must be rejected (WH-SIG-001 / WH-SIG-004)
  2. garbage signatures in common header formats -> must be rejected (WH-SIG-004)
  3. an oversized body                           -> should be rejected (WH-PROC-002)
  4. optional: a captured *old* genuine delivery (--replay-file) sent again
                                                 -> must be rejected once outside the tolerance window (WH-REPLAY-001)

The synthetic payload is an unknown event type (`securitykit.probe`). If the receiver does NOT verify
signatures it may still act on it, so this script requires --confirm-side-effects, which the agent passes
only after the user agrees. Localhost only unless --i-own-this-host.
"""

import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.0"
EXCERPT = 400
PROBE_EVENT = {"id": "evt_securitykit_probe", "type": "securitykit.probe", "created": 0,
               "data": {"object": {"id": "securitykit_probe", "note": "SecurityKit test event; safe to ignore"}}}
BAD_SIGNATURES = {
    "X-Signature": "sha256=" + "0" * 64,
    "X-Hub-Signature-256": "sha256=" + "0" * 64,
    "Stripe-Signature": "t=1700000000,v1=" + "0" * 64,
    "Webhook-Signature": "v1," + "A" * 44,
    "Svix-Signature": "v1," + "A" * 44,
    "X-Webhook-Signature": "0" * 64,
}


def is_local(host):
    host = (host or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def send(url, body, headers, timeout):
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        r = OPENER.open(req, timeout=timeout)
        return r.status, r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(8192).decode("utf-8", "replace") if e.fp else "")
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)


def evidence(url, headers, body, status, text):
    hdrs = "".join(f"\n{k}: {v[:40]}" for k, v in headers.items())
    shown = body[:300].decode("utf-8", "replace") if len(body) < 5000 else f"<{len(body)} bytes>"
    return {"method": "POST", "url": url, "status": status,
            "requestExcerpt": f"POST {url}{hdrs}\n\n{shown}", "responseExcerpt": f"HTTP {status}\n{text[:EXCERPT]}"}


def run(args):
    host = urllib.parse.urlparse(args.url).hostname
    if not host:
        sys.exit(f"error: invalid --url {args.url!r}")
    if not is_local(host) and not args.i_own_this_host:
        sys.exit(f"error: {host} is not localhost. Re-run with --i-own-this-host only after the user explicitly "
                 "confirms they own this system and authorize testing.")
    if not args.confirm_side_effects:
        sys.exit("error: a receiver that does not verify signatures will process the probe event. Ask the user, "
                 "then re-run with --confirm-side-effects.")

    cands, results = [], []
    body = json.dumps(PROBE_EVENT).encode()
    base_headers = {"Content-Type": "application/json", "User-Agent": f"SecurityKit-sk-webhooks/{VERSION}"}

    def record(name, headers, payload, check, title, accept_is_bad=True, reset_means_rejected=False):
        status, text = send(args.url, payload, headers, args.timeout)
        if status == 0 and reset_means_rejected:
            # Servers often answer 413 and close the socket before reading a large body.
            results.append({"probe": name, "status": 0, "note": "connection closed by receiver (rejected)"})
            return 0
        if status == 0:
            raise RuntimeError(f"cannot reach {args.url}: {text}")
        ok = 200 <= status < 300
        results.append({"probe": name, "status": status})
        if ok and accept_is_bad:
            cands.append({"check_id": check, "title": title, "request": evidence(args.url, headers, payload, status, text),
                          "note": "receiver returned 2xx; confirm in code whether it processed the event"})
        return status

    record("unsigned", dict(base_headers), body, "WH-SIG-001", "Unsigned webhook request accepted")
    bad = dict(base_headers)
    bad.update(BAD_SIGNATURES)
    if args.signature_header:
        bad[args.signature_header] = "0" * 64
    record("bad-signature", bad, body, "WH-SIG-004", "Webhook with invalid signature accepted")
    big = json.dumps({**PROBE_EVENT, "padding": "x" * (args.big_body_mb * 1024 * 1024)}).encode()
    record("oversized", dict(base_headers), big, "WH-PROC-002", f"{args.big_body_mb} MB webhook body accepted",
           reset_means_rejected=True)

    if args.replay_file:
        with open(args.replay_file, encoding="utf-8") as fh:
            captured = json.load(fh)
        headers = {k: v for k, v in captured.get("headers", {}).items() if k.lower() not in ("host", "content-length")}
        raw = captured["body"].encode() if isinstance(captured["body"], str) else json.dumps(captured["body"]).encode()
        age = captured.get("captured_at")
        note = f"captured {int(time.time() - age)}s ago" if age else "capture time unknown"
        status = record("replay", headers, raw, "WH-REPLAY-001", f"Old genuine delivery replayed and accepted ({note})")
        results[-1]["note"] = note
        if 200 <= status < 300:
            cands[-1]["note"] = ("a previously captured, genuinely signed delivery was accepted again; if it is older than "
                                 "the tolerance window this proves there is no timestamp/replay check")
    return {"tool": "securitykit-probe-webhook", "version": VERSION, "url": args.url, "probes": results, "candidates": cands}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Safe inbound webhook probes (SecurityKit).")
    ap.add_argument("--url", required=True, help="receiver URL, e.g. http://localhost:3000/webhooks/stripe")
    ap.add_argument("--signature-header", help="the header this receiver expects, if known")
    ap.add_argument("--replay-file", help="JSON {headers, body, captured_at} of a genuine delivery captured earlier")
    ap.add_argument("--big-body-mb", type=int, default=5)
    ap.add_argument("--confirm-side-effects", action="store_true")
    ap.add_argument("--i-own-this-host", action="store_true")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    try:
        result = run(args)
    except RuntimeError as e:
        sys.exit(f"error: {e}")
    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"{len(result['candidates'])} candidates -> {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
