#!/usr/bin/env bash
# =============================================================================
# GrantAi first boot (Azure). Runs as root from the Custom Script Extension, or
# by hand on a prepared VM. Idempotent: every step checks before it acts, so a
# replacement VM re-runs it and reuses the install identity and token kept in
# Key Vault. Nothing on this disk is authoritative.
#
# Inputs: a parameters file (default /etc/grantai/firstboot.env) with
#   KEYVAULT_NAME        vault the VM's managed identity can read and write secrets in
#   PG_HOST PG_DB PG_USER PG_PASSWORD_SECRET   Postgres Flexible Server (private FQDN)
#   STORAGE_ACCOUNT STORAGE_RG COLD_CONTAINER SUBSCRIPTION_ID   cold tier (optional)
#   LICENSE_KEY | TRIAL_EMAIL | LICENSE_JWT_SECRET   one of the three (JWT secret = egress-free)
#   HTTP_PORT (8443)  TLS_CERT_SECRET (optional PFX secret)  PUBLIC_FQDN (optional)
#   PACKAGE_URL PACKAGE_SHA256                 fallback when no image release is present
#   AUTH_ISSUER AUTH_AUDIENCE                  optional (per-caller identity)
#   API_URL                                    optional override of https://solonai.com
# Secret names (overridable): INSTALL_ID_SECRET=grantai-install-id TOKEN_SECRET=grantai-http-token
#
# Status: /opt/grantai/var/firstboot-status.json, echoed at the end. Non-zero exit on any failure.
# =============================================================================
set -euo pipefail

PARAMS="${1:-/etc/grantai/firstboot.env}"
ROOT=/opt/grantai
LOG=/var/log/grantai-firstboot.log
STATUS=$ROOT/var/firstboot-status.json
STEP=start

exec > >(tee -a "$LOG") 2>&1
echo "=== GrantAi first boot $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

status_fail() {
  mkdir -p "$ROOT/var"
  python3 - "$STEP" "$1" > "$STATUS" <<'PY'
import json, sys, datetime
print(json.dumps({"ok": False, "step": sys.argv[1], "message": sys.argv[2],
                  "finished_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}, indent=2))
PY
  echo "FIRST BOOT FAILED at step '$STEP': $1"
  cat "$STATUS"
  exit "${2:-1}"
}
trap 'status_fail "command failed: $BASH_COMMAND" 1' ERR

[ -r "$PARAMS" ] || status_fail "parameters file $PARAMS not found" 1
# Values are taken literally (no shell parsing): PEMs, URLs with '&', passwords.
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|'#'*) continue;; esac
  k="${line%%=*}"; v="${line#*=}"
  [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || status_fail "bad parameter line: ${line%%=*}" 1
  printf -v "$k" '%s' "$v"; export "$k"
done < "$PARAMS"
HTTP_PORT="${HTTP_PORT:-8443}"
INSTALL_ID_SECRET="${INSTALL_ID_SECRET:-grantai-install-id}"
TOKEN_SECRET="${TOKEN_SECRET:-grantai-http-token}"
COLD_CONTAINER="${COLD_CONTAINER:-audit-cold}"
API_URL="${API_URL:-https://solonai.com}"

# ---------------------------------------------------------------- helpers
imds_token() {  # $1 resource
  curl -sS -m 10 -H Metadata:true \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$1" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'
}
kv_get() {  # $1 secret name -> value on stdout, empty if absent
  local code
  code=$(curl -sS -m 20 -o /tmp/kv.json -w '%{http_code}' -H "Authorization: Bearer $KV_TOKEN" \
    "https://$KEYVAULT_NAME.vault.azure.net/secrets/$1?api-version=7.4")
  case "$code" in
    200) python3 -c 'import sys,json; print(json.load(open("/tmp/kv.json"))["value"])' ;;
    404) echo "" ;;
    *) status_fail "Key Vault read of $1 returned HTTP $code" 13 ;;
  esac
}
kv_put() {  # $1 name, $2 value
  python3 -c 'import sys,json; print(json.dumps({"value": sys.argv[1]}))' "$2" > /tmp/kv.put
  local code
  code=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $KV_TOKEN" \
    -H 'Content-Type: application/json' --data @/tmp/kv.put \
    "https://$KEYVAULT_NAME.vault.azure.net/secrets/$1?api-version=7.4")
  rm -f /tmp/kv.put
  [ "$code" = 200 ] || status_fail "Key Vault write of $1 returned HTTP $code" 13
}
urlencode() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

# Cloud-neutral secret store: Key Vault on Azure, Secrets Manager on AWS (instance role, awscli).
CLOUD="${CLOUD:-azure}"
secret_get() {  # $1 name -> value on stdout, empty if absent
  if [ "$CLOUD" = aws ]; then
    aws secretsmanager get-secret-value --region "$AWS_REGION" --secret-id "$1" --query SecretString --output text 2>/dev/null || true
  else kv_get "$1"; fi
}
secret_put() {  # $1 name, $2 value
  if [ "$CLOUD" = aws ]; then
    if aws secretsmanager describe-secret --region "$AWS_REGION" --secret-id "$1" >/dev/null 2>&1; then
      aws secretsmanager put-secret-value --region "$AWS_REGION" --secret-id "$1" --secret-string "$2" >/dev/null
    else
      aws secretsmanager create-secret --region "$AWS_REGION" --name "$1" --secret-string "$2" >/dev/null
    fi
  else kv_put "$1" "$2"; fi
}

# ---------------------------------------------------------------- 1 preflight
STEP=preflight
timedatectl show -p NTPSynchronized --value | grep -q yes || echo "warning: clock not yet NTP-synchronised"
if [ "$CLOUD" = aws ]; then
  command -v aws >/dev/null || {
    echo "installing the AWS CLI"
    if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip curl >/dev/null; fi
    curl -sS -m 120 -o /tmp/awscli.zip "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" && (cd /tmp && unzip -qo awscli.zip && ./aws/install >/dev/null) && rm -rf /tmp/aws /tmp/awscli.zip
  }
  aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1 || status_fail "the instance role cannot call AWS (no instance profile?)" 10
  # Secret names on AWS carry the stack prefix
  INSTALL_ID_SECRET="${SECRET_PREFIX:-grantai}/install-id"; TOKEN_SECRET="${SECRET_PREFIX:-grantai}/http-token"
  SIGN_SECRET="${SECRET_PREFIX:-grantai}/export-signing-key"; SIGN_PUB_SECRET="${SECRET_PREFIX:-grantai}/export-signing-pub"
else
  curl -sS -m 5 -H Metadata:true 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' -o /tmp/imds.json \
    || status_fail "IMDS not reachable; is this an Azure VM with a managed identity?" 10
  KV_TOKEN=$(imds_token https://vault.azure.net) || status_fail "no Key Vault token from the managed identity" 10
  ARM_TOKEN=$(imds_token https://management.azure.com/) || status_fail "no ARM token from the managed identity" 10
fi
VM_FQDN="${PUBLIC_FQDN:-$(hostname -f 2>/dev/null || hostname)}"
VM_IP=$(hostname -I | awk '{print $1}')

# ---------------------------------------------------------------- 2 package (fallback only)
STEP=package
# Install when no release is present, or upgrade when the template names a different package
# (PACKAGE_SHA256 differs from the installed release's recorded hash).
installed_sha() { python3 -c 'import json,sys
for f in sys.argv[1:]:
    try: print(json.load(open(f)).get("package_sha256","")); break
    except Exception: pass' "$ROOT/var/release.json" "$ROOT/var/image.json" 2>/dev/null; }
NEED_INSTALL=0
if [ ! -x "$ROOT/current/bin/grantai-mcp" ]; then NEED_INSTALL=1
elif [ -n "${PACKAGE_URL:-}" ] && [ -n "${PACKAGE_SHA256:-}" ] && [ "$(installed_sha)" != "$PACKAGE_SHA256" ]; then
  echo "release upgrade: installed $(installed_sha | cut -c1-12) -> $PACKAGE_SHA256"; NEED_INSTALL=1
fi
if [ "$NEED_INSTALL" = 1 ]; then
  [ -n "${PACKAGE_URL:-}" ] || status_fail "no release under $ROOT/current and no PACKAGE_URL" 10
  # RHEL images carry a small LVM root (about 2 GB); the release needs ~3 GB during unpack.
  if command -v lvextend >/dev/null && lvs rootvg/rootlv >/dev/null 2>&1; then
    free_kb=$(df -k /opt | awk 'NR==2{print $4}')
    if [ "${free_kb:-0}" -lt 6000000 ]; then
      echo "extending rootvg/rootlv for the release"
      lvextend -r -L +10G /dev/rootvg/rootlv >/dev/null 2>&1 || lvextend -r -l +100%FREE /dev/rootvg/rootlv >/dev/null
    fi
  fi
  mkdir -p "$ROOT/releases"
  ZIP="$ROOT/releases/${PACKAGE_SHA256:-package}.zip"
  if [ ! -s "$ZIP" ]; then
    echo "downloading $PACKAGE_URL"
    if [[ "$PACKAGE_URL" == *.blob.core.windows.net* && "$PACKAGE_URL" != *sig=* ]]; then
      ST=$(imds_token https://storage.azure.com/)
      curl -sS -L -m 900 -H "Authorization: Bearer $ST" -H 'x-ms-version: 2021-06-08' -o "$ZIP" "$PACKAGE_URL"
    else
      curl -sS -L -m 900 -o "$ZIP" "$PACKAGE_URL"
    fi
  fi
  if [ -n "${PACKAGE_SHA256:-}" ]; then
    echo "$PACKAGE_SHA256  $ZIP" | sha256sum -c - >/dev/null || status_fail "package SHA-256 mismatch" 10
  fi
  VER=$(python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); print(next((n.split("/")[0] for n in z.namelist() if "/" in n), "release"))' "$ZIP")
  [ -n "${PACKAGE_SHA256:-}" ] && VER="$VER-${PACKAGE_SHA256:0:8}"
  rm -rf "$ROOT/releases/$VER"; mkdir -p "$ROOT/releases/$VER"
  DEST_DIR="$ROOT/releases/$VER"
python3 - "$ZIP" "$DEST_DIR" <<'PYX'
import os, stat, sys, zipfile
z, dest = zipfile.ZipFile(sys.argv[1]), sys.argv[2]
for zi in z.infolist():
    target = os.path.join(dest, zi.filename)
    if ((zi.external_attr >> 16) & 0o170000) == stat.S_IFLNK:      # symlink entry (lib sonames)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.lexists(target): os.remove(target)
        os.symlink(z.read(zi).decode(), target)
    else:
        z.extract(zi, dest)
PYX
  # the zip may contain a top-level folder; normalise to bin/ lib/ models/
  if [ ! -d "$ROOT/releases/$VER/bin" ]; then
    inner=$(find "$ROOT/releases/$VER" -maxdepth 2 -type d -name bin | head -1)
    [ -n "$inner" ] || status_fail "package has no bin/ directory" 10
    mv "$(dirname "$inner")"/* "$ROOT/releases/$VER/"
  fi
  chmod +x "$ROOT/releases/$VER"/bin/*
  ln -sfn "$ROOT/releases/$VER" "$ROOT/current"
  mkdir -p "$ROOT/var"
  printf '{"release": "%s", "package_sha256": "%s", "installed_at": "%s"}\n' "$VER" "${PACKAGE_SHA256:-}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ROOT/var/release.json"
  rm -f "$ZIP"
fi
# A marketplace base image lacks the runtime libraries the gallery image carries.
if ! ldconfig -p | grep -q 'libpq.so.5'; then
  echo "installing runtime dependencies"
  command -v cloud-init >/dev/null && cloud-init status --wait >/dev/null 2>&1 || true
  if command -v apt-get >/dev/null; then
    for i in 1 2 3 4 5; do DEBIAN_FRONTEND=noninteractive apt-get update -qq && break; echo "apt-get update retry $i"; sleep 15; done
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends libpq5 openssl ca-certificates curl python3 >/dev/null
  else
    dnf install -y -q libpq openssl ca-certificates curl python3 >/dev/null
  fi
fi

# ---------------------------------------------------------------- 3 layout and service user
STEP=layout
id -u grantai >/dev/null 2>&1 || useradd --system --home-dir "$ROOT/home" --shell /usr/sbin/nologin grantai
mkdir -p "$ROOT/etc" "$ROOT/data" "$ROOT/home" "$ROOT/var" "$ROOT/bin"
chown root:grantai "$ROOT/etc"; chmod 0750 "$ROOT/etc"
chown -R grantai:grantai "$ROOT/data" "$ROOT/home" "$ROOT/var"; chmod 0700 "$ROOT/home"
export LD_LIBRARY_PATH="$ROOT/current/lib"
"$ROOT/current/bin/grantai-mcp" --version | tee "$ROOT/var/version.json"

# ---------------------------------------------------------------- 4 licence
STEP=licence
EXISTING_INSTALL_ID=$(secret_get "$INSTALL_ID_SECRET")
ACT=("$ROOT/current/bin/grantai-activate" --server)
[ -n "$EXISTING_INSTALL_ID" ] && ACT+=(--install-id "$EXISTING_INSTALL_ID")
export GRANTAI_API_URL="$API_URL" GRANTAI_HOME="$ROOT/home"
# Egress-free path: a licence JWT handed over as a file and kept as a Key Vault
# secret (LICENSE_JWT_SECRET). Used when the tenant cannot reach solonai.com.
if [ -n "${LICENSE_JWT_SECRET:-}" ]; then
  JWT=$(secret_get "$LICENSE_JWT_SECRET")
  [ -n "$JWT" ] || status_fail "secret $LICENSE_JWT_SECRET is empty" 11
  umask 077; printf '%s\n' "$JWT" > "$ROOT/home/license.jwt"; umask 022
  chown grantai:grantai "$ROOT/home/license.jwt"
fi
if [ -n "${LICENSE_DEV_PUBKEY_PEM:-}" ]; then
  # the parameter carries literal \n sequences (one line); the tools accept either form
  export GRANTAI_LICENSE_DEV_PUBKEY_PEM="$(printf '%b' "$LICENSE_DEV_PUBKEY_PEM")"
  echo "warning: development licence public key in use; never for a customer"
fi
if [ -z "${LICENSE_JWT_SECRET:-}" ] && { [ ! -s "$ROOT/home/license.jwt" ] || [ -n "${FORCE_ACTIVATE:-}" ]; }; then
  if [ -n "${LICENSE_KEY:-}" ]; then
    sudo -u grantai -E "${ACT[@]}" activate "$LICENSE_KEY" "$ROOT/home" || status_fail "activation failed (check the licence key and egress to $API_URL)" 11
  elif [ -n "${TRIAL_EMAIL:-}" ]; then
    sudo -u grantai -E "${ACT[@]}" trial "$TRIAL_EMAIL" "$ROOT/home" || status_fail "trial activation failed" 11
  else
    status_fail "neither LICENSE_KEY nor TRIAL_EMAIL supplied" 11
  fi
fi
LIC=$("$ROOT/current/bin/grantai-activate" verify "$ROOT/home") || status_fail "stored licence does not verify: $LIC" 11
INSTALL_ID=$(echo "$LIC" | python3 -c 'import sys,json; print(json.load(sys.stdin)["install_id"])')
LIC_TIER=$(echo "$LIC" | python3 -c 'import sys,json; print(json.load(sys.stdin)["tier"])')
LIC_EXP=$(echo "$LIC" | python3 -c 'import sys,json; print(json.load(sys.stdin)["expires_at"])')
LIC_STATE=$(echo "$LIC" | python3 -c 'import sys,json; print(json.load(sys.stdin)["state"])')
echo "licence: tier=$LIC_TIER install=$INSTALL_ID state=$LIC_STATE expires=$LIC_EXP"

# ---------------------------------------------------------------- 5 install identity
STEP=install-id
if [ -n "$EXISTING_INSTALL_ID" ]; then
  [ "$EXISTING_INSTALL_ID" = "$INSTALL_ID" ] || status_fail "licence install_id $INSTALL_ID differs from the identity in Key Vault $EXISTING_INSTALL_ID" 12
else
  secret_put "$INSTALL_ID_SECRET" "$INSTALL_ID"
fi

# ---------------------------------------------------------------- 6 bootstrap token
STEP=token
TOKEN=$(secret_get "$TOKEN_SECRET")
if [ -z "$TOKEN" ]; then
  TOKEN=$(openssl rand -hex 32)
  secret_put "$TOKEN_SECRET" "$TOKEN"
fi

# ---------------------------------------------------------------- 6b model endpoint key (AI Query)
STEP=model-key
LLM_API_KEY=""
if [ -n "${LLM_KEY_SECRET:-}" ]; then LLM_API_KEY=$(secret_get "$LLM_KEY_SECRET" || true); fi
[ -z "${LLM_ENDPOINT:-}" ] || echo "model endpoint: ${LLM_PROVIDER:-azure-openai} ${LLM_ENDPOINT} deployment ${LLM_DEPLOYMENT:-?} auth $([ -n "$LLM_API_KEY" ] && echo key || echo managed-identity)"

# ---------------------------------------------------------------- 7 postgres
STEP=postgres
PG_PASSWORD=$(secret_get "$PG_PASSWORD_SECRET")
[ -n "$PG_PASSWORD" ] || status_fail "secret $PG_PASSWORD_SECRET is empty" 13
PG_URL="postgres://$(urlencode "$PG_USER"):$(urlencode "$PG_PASSWORD")@$PG_HOST:5432/$PG_DB?sslmode=require"

# ---------------------------------------------------------------- 8 storage key (cold tier)
STEP=storage
if [ "$CLOUD" = aws ]; then
  STORAGE_KEY=""   # S3 uses the instance role; nothing to fetch
  [ -n "${S3_BUCKET:-}" ] && echo "cold tier: s3://$S3_BUCKET/$COLD_CONTAINER (instance role)"
else
  STORAGE_KEY=""
  if [ -n "${STORAGE_ACCOUNT:-}" ]; then
    code=$(curl -sS -m 30 -o /tmp/keys.json -w '%{http_code}' -X POST -H "Authorization: Bearer $ARM_TOKEN" -H 'Content-Length: 0' \
      "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$STORAGE_RG/providers/Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT/listKeys?api-version=2023-05-01")
    [ "$code" = 200 ] || status_fail "listKeys on $STORAGE_ACCOUNT returned HTTP $code (role: Storage Account Key Operator Service Role)" 14
    STORAGE_KEY=$(python3 -c 'import json; print(json.load(open("/tmp/keys.json"))["keys"][0]["value"])'); rm -f /tmp/keys.json
  fi
fi

# ---------------------------------------------------------------- 8b export signing key
STEP=signing-key
# The key that signs auditor export bundles. Generated here, in the tenant; the private key
# is a Key Vault secret so a replacement VM signs with the same key; the public key is a
# second secret so auditors can obtain the trust anchor without touching the VM.
SIGN_SECRET="${SIGN_SECRET:-grantai-export-signing-key}"
SIGN_PUB_SECRET="${SIGN_PUB_SECRET:-grantai-export-signing-pub}"
if [ ! -s "$ROOT/etc/export-signing.key" ]; then
  EXISTING_KEY=$(secret_get "$SIGN_SECRET" || true)
  umask 077
  if [ -n "$EXISTING_KEY" ]; then
    printf '%s\n' "$EXISTING_KEY" > "$ROOT/etc/export-signing.key"
  else
    openssl ecparam -name prime256v1 -genkey -noout -out "$ROOT/etc/export-signing.key"
    secret_put "$SIGN_SECRET" "$(cat "$ROOT/etc/export-signing.key")"
    secret_put "$SIGN_PUB_SECRET" "$(openssl pkey -in "$ROOT/etc/export-signing.key" -pubout)"
  fi
  umask 022
fi
openssl pkey -in "$ROOT/etc/export-signing.key" -pubout > "$ROOT/var/export-signing.pub"
chown root:grantai "$ROOT/etc/export-signing.key"; chmod 0640 "$ROOT/etc/export-signing.key"
SIGN_FP=$(openssl pkey -in "$ROOT/etc/export-signing.key" -pubout -outform DER | sha256sum | cut -c1-64)
echo "export signing key fingerprint sha256:$SIGN_FP"

# ---------------------------------------------------------------- 9 TLS
STEP=tls
if [ -n "${TLS_CERT_SECRET:-}" ]; then
  secret_get "$TLS_CERT_SECRET" | base64 -d > /tmp/cert.pfx
  openssl pkcs12 -in /tmp/cert.pfx -clcerts -nokeys -passin pass: -out "$ROOT/etc/tls.crt"
  openssl pkcs12 -in /tmp/cert.pfx -nocerts -nodes -passin pass: -out "$ROOT/etc/tls.key"
  rm -f /tmp/cert.pfx
elif [ -n "${ACME_EMAIL:-}" ] && [ -n "${PUBLIC_FQDN:-}" ]; then
  # Publicly trusted certificate from Let's Encrypt for the public name (HTTP-01 on port 80).
  # Platform-hosted agents (Foundry's MCP tool) refuse self-signed certificates.
  if ! command -v certbot >/dev/null; then
    if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null
    else dnf install -y -q https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm >/dev/null 2>&1 || true; dnf install -y -q certbot >/dev/null; fi
  fi
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=80/tcp >/dev/null && firewall-cmd --reload >/dev/null
  fi
  LIVE="/etc/letsencrypt/live/$PUBLIC_FQDN"
  if [ ! -s "$LIVE/fullchain.pem" ]; then
    certbot certonly --standalone --non-interactive --agree-tos -m "$ACME_EMAIL" -d "$PUBLIC_FQDN" \
      --preferred-challenges http >/var/log/grantai-certbot.log 2>&1 || status_fail "certbot could not obtain a certificate for $PUBLIC_FQDN (see /var/log/grantai-certbot.log)" 17
  fi
  install -m 0640 -o root -g grantai "$LIVE/fullchain.pem" "$ROOT/etc/tls.crt"
  install -m 0640 -o root -g grantai "$LIVE/privkey.pem" "$ROOT/etc/tls.key"
  # renewal: certbot's timer renews; this hook installs the new files and restarts the service
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/grantai.sh <<EOF
#!/bin/bash
install -m 0640 -o root -g grantai "$LIVE/fullchain.pem" "$ROOT/etc/tls.crt"
install -m 0640 -o root -g grantai "$LIVE/privkey.pem" "$ROOT/etc/tls.key"
systemctl restart grantai
EOF
  chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/grantai.sh
  echo "tls: Let's Encrypt certificate for $PUBLIC_FQDN"
elif [ ! -s "$ROOT/etc/tls.crt" ] || ! openssl x509 -in "$ROOT/etc/tls.crt" -noout -ext subjectAltName 2>/dev/null | grep -q '127.0.0.1'; then
  # self-signed; 127.0.0.1 is in the SAN so the self-check and grantai-ctl can verify it locally
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
    -subj "/CN=$VM_FQDN" -addext "subjectAltName=DNS:$VM_FQDN,IP:$VM_IP,IP:127.0.0.1" \
    -keyout "$ROOT/etc/tls.key" -out "$ROOT/etc/tls.crt" >/dev/null 2>&1
fi
chown root:grantai "$ROOT/etc/tls.crt" "$ROOT/etc/tls.key"; chmod 0640 "$ROOT/etc/tls.crt" "$ROOT/etc/tls.key"
TLS_FP=$(openssl x509 -in "$ROOT/etc/tls.crt" -noout -fingerprint -sha256 | cut -d= -f2)
# How local components (self-check, tap, reviewer, grantai-ctl) reach the service over TLS:
# self-signed -> 127.0.0.1 pinned to the file; CA-issued -> the public name, system trust store.
if [ -n "${ACME_EMAIL:-}" ] && [ -n "${PUBLIC_FQDN:-}" ]; then
  grep -q " $PUBLIC_FQDN\$" /etc/hosts || echo "127.0.0.1 $PUBLIC_FQDN" >> /etc/hosts
  LOCAL_BASE="https://$PUBLIC_FQDN:$HTTP_PORT"; LOCAL_CACERT=""
else
  LOCAL_BASE="https://127.0.0.1:$HTTP_PORT"; LOCAL_CACERT="$ROOT/etc/tls.crt"
fi
printf 'LOCAL_BASE=%s\nLOCAL_CACERT=%s\n' "$LOCAL_BASE" "$LOCAL_CACERT" > "$ROOT/etc/local-tls.env"
for f in "$ROOT/etc/foundry-tap.env" "$ROOT/etc/reviewer.env"; do
  [ -s "$f" ] || continue
  sed -i -e "s|^GRANTAI_TAP_BASE=.*|GRANTAI_TAP_BASE=$LOCAL_BASE|" -e "s|^GRANTAI_TAP_CACERT=.*|GRANTAI_TAP_CACERT=$LOCAL_CACERT|" \
         -e "s|^GRANTAI_REVIEW_BASE=.*|GRANTAI_REVIEW_BASE=$LOCAL_BASE|" -e "s|^GRANTAI_REVIEW_CACERT=.*|GRANTAI_REVIEW_CACERT=$LOCAL_CACERT|" "$f"
done

# ---------------------------------------------------------------- 10 environment file
STEP=env
umask 077
cat > "$ROOT/etc/grantai.env.new" <<EOF
GRANTAI_HOME=$ROOT/home
GRANTAI_MODELS=$ROOT/current/models
GRANTAI_DATA=$ROOT/data
GRANTAI_DB_BACKEND=postgres
GRANTAI_POSTGRES_URL=$PG_URL
GRANTAI_PG_POOL=8
GRANTAI_INSTALL_ID=$INSTALL_ID
GRANTAI_DATASET=api
GRANTAI_LICENSE_FILE=$ROOT/home/license.jwt
GRANTAI_HTTP_TOKEN=$TOKEN
GRANTAI_EXPORT_SIGNING_KEY=$ROOT/etc/export-signing.key
GRANTAI_LLM_PROVIDER=${LLM_PROVIDER:-}
GRANTAI_LLM_ENDPOINT=${LLM_ENDPOINT:-}
GRANTAI_LLM_DEPLOYMENT=${LLM_DEPLOYMENT:-}
GRANTAI_LLM_API_KEY=$LLM_API_KEY
GRANTAI_HTTP_PORT=$HTTP_PORT
LD_LIBRARY_PATH=$ROOT/current/lib
EOF
if [ -n "$STORAGE_KEY" ]; then cat >> "$ROOT/etc/grantai.env.new" <<EOF
GRANTAI_AZURE_STORAGE_ACCOUNT=$STORAGE_ACCOUNT
GRANTAI_AZURE_STORAGE_KEY=$STORAGE_KEY
GRANTAI_AZURE_STORAGE_CONTAINER=$COLD_CONTAINER
GRANTAI_S3_BUCKET=${S3_BUCKET:-}
GRANTAI_S3_REGION=${AWS_REGION:-}
GRANTAI_S3_PREFIX=$COLD_CONTAINER
EOF
fi
if [ -n "${AUTH_ISSUER:-}" ]; then cat >> "$ROOT/etc/grantai.env.new" <<EOF
GRANTAI_AUTH_ISSUER=$AUTH_ISSUER
GRANTAI_AUTH_AUDIENCE=${AUTH_AUDIENCE:-}
EOF
fi
[ -n "${LICENSE_DEV_PUBKEY_PEM:-}" ] && printf 'GRANTAI_LICENSE_DEV_PUBKEY_PEM="%s"\n' "$LICENSE_DEV_PUBKEY_PEM" >> "$ROOT/etc/grantai.env.new"
# systemd reads it as root; the service user never reads secrets from disk.
chown root:root "$ROOT/etc/grantai.env.new"; chmod 0600 "$ROOT/etc/grantai.env.new"
mv -f "$ROOT/etc/grantai.env.new" "$ROOT/etc/grantai.env"
# the licence must be readable by the service user, nothing else
chown grantai:grantai "$ROOT/home/license.jwt"; chmod 0600 "$ROOT/home/license.jwt"
umask 022

# ---------------------------------------------------------------- 11 service
STEP=service
SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
install -m 0644 "$SRC_DIR/grantai.service" /etc/systemd/system/grantai.service
install -m 0755 "$SRC_DIR/grantai-ctl" "$ROOT/bin/grantai-ctl"
install -m 0755 "$SRC_DIR/grantai-selfcheck.py" "$ROOT/bin/grantai-selfcheck.py"
install -m 0755 "$SRC_DIR/first-boot.sh" "$ROOT/bin/first-boot.sh"
ln -sfn "$ROOT/bin/grantai-ctl" /usr/local/bin/grantai-ctl
# RHEL ships firewalld enabled; the NSG is not enough, the host must admit the port too.
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp" >/dev/null && firewall-cmd --reload >/dev/null
  echo "firewalld: opened ${HTTP_PORT}/tcp"
fi
systemctl daemon-reload
systemctl enable grantai >/dev/null
systemctl restart grantai

# ---------------------------------------------------------------- 11b platform taps
STEP=taps
if [ -n "${FOUNDRY_PROJECT_ENDPOINT:-}" ]; then
  # Mint a per-caller token for the tap (shown once by the API; only its hash is stored) unless one exists.
  install -m 0755 "$SRC_DIR/grantai-foundry-tap.py" "$ROOT/bin/grantai-foundry-tap.py"
  install -m 0644 "$SRC_DIR/grantai-foundry-tap.service" /etc/systemd/system/grantai-foundry-tap.service
  if [ ! -s "$ROOT/etc/foundry-tap.env" ]; then
    for i in $(seq 1 30); do
      curl -sk -m 5 -o /dev/null -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:$HTTP_PORT/health" && break; sleep 2
    done
    MINT=$(curl -sk -m 10 -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d '{"display":"foundry-tap"}' -w '\n%{http_code}' "https://127.0.0.1:$HTTP_PORT/api/callers/static" || true)
    MINT_CODE=$(printf '%s' "$MINT" | tail -1); MINT_BODY=$(printf '%s' "$MINT" | sed '$d')
    [ "$MINT_CODE" = "200" ] || status_fail "could not mint the foundry-tap caller token (HTTP $MINT_CODE; the release must include the caller registry, 2.0.1 build of 2026-10-07 or later)" 15
    TAP_TOKEN=$(printf '%s' "$MINT_BODY" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
    [ -n "$TAP_TOKEN" ] || status_fail "could not mint the foundry-tap caller token" 15
    umask 077
    cat > "$ROOT/etc/foundry-tap.env.new" <<EOF
GRANTAI_FOUNDRY_PROJECT_ENDPOINT=$FOUNDRY_PROJECT_ENDPOINT
GRANTAI_TAP_BASE=$LOCAL_BASE
GRANTAI_TAP_TOKEN=$TAP_TOKEN
GRANTAI_TAP_CACERT=$LOCAL_CACERT
GRANTAI_TAP_INTERVAL=20
GRANTAI_TAP_STATE=$ROOT/var/foundry-tap.state.json
EOF
    mv "$ROOT/etc/foundry-tap.env.new" "$ROOT/etc/foundry-tap.env"
    chown root:grantai "$ROOT/etc/foundry-tap.env"; chmod 0640 "$ROOT/etc/foundry-tap.env"
    umask 022
  fi
  systemctl daemon-reload
  systemctl enable grantai-foundry-tap >/dev/null; systemctl restart grantai-foundry-tap
  echo "foundry tap enabled for $FOUNDRY_PROJECT_ENDPOINT"
fi

# ---------------------------------------------------------------- 11c reviewer (always on)
STEP=reviewer
install -m 0755 "$SRC_DIR/grantai-reviewer.py" "$ROOT/bin/grantai-reviewer.py"
install -m 0644 "$SRC_DIR/grantai-reviewer.service" /etc/systemd/system/grantai-reviewer.service
[ -s "$ROOT/etc/review-policies.json" ] || install -m 0644 -o root -g grantai "$SRC_DIR/review-policies.json" "$ROOT/etc/review-policies.json"
if [ ! -s "$ROOT/etc/reviewer.env" ]; then
  for i in $(seq 1 30); do
    curl -sk -m 5 -o /dev/null -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:$HTTP_PORT/health" && break; sleep 2
  done
  MINT=$(curl -sk -m 10 -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"display":"reviewer"}' -w '\n%{http_code}' "https://127.0.0.1:$HTTP_PORT/api/callers/static" || true)
  MINT_CODE=$(printf '%s' "$MINT" | tail -1); MINT_BODY=$(printf '%s' "$MINT" | sed '$d')
  [ "$MINT_CODE" = "200" ] || status_fail "could not mint the reviewer caller token (HTTP $MINT_CODE)" 16
  REV_TOKEN=$(printf '%s' "$MINT_BODY" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
  umask 077
  cat > "$ROOT/etc/reviewer.env.new" <<EOF
GRANTAI_REVIEW_BASE=$LOCAL_BASE
GRANTAI_REVIEW_TOKEN=$REV_TOKEN
GRANTAI_REVIEW_CACERT=$LOCAL_CACERT
GRANTAI_REVIEW_POLICIES=$ROOT/etc/review-policies.json
GRANTAI_REVIEW_STATE=$ROOT/var/reviewer.state.json
GRANTAI_REVIEW_INTERVAL=60
GRANTAI_REVIEW_WEBHOOK=${REVIEW_WEBHOOK_URL:-}
EOF
  mv "$ROOT/etc/reviewer.env.new" "$ROOT/etc/reviewer.env"
  chown root:grantai "$ROOT/etc/reviewer.env"; chmod 0640 "$ROOT/etc/reviewer.env"
  umask 022
fi
systemctl daemon-reload
systemctl enable grantai-reviewer >/dev/null; systemctl restart grantai-reviewer
echo "reviewer enabled (policies $ROOT/etc/review-policies.json)"

# ---------------------------------------------------------------- 12 self-check
STEP=selfcheck
COLD_FLAG=(); [ -n "$STORAGE_KEY" ] && COLD_FLAG=(--cold)
CACERT_ARGS=(); [ -n "$LOCAL_CACERT" ] && CACERT_ARGS=(--cacert "$LOCAL_CACERT")
python3 "$ROOT/bin/grantai-selfcheck.py" --base "$LOCAL_BASE" --token-file "$ROOT/etc/grantai.env" \
  "${CACERT_ARGS[@]}" --install-id "$INSTALL_ID" --backend postgres "${COLD_FLAG[@]}" \
  --json "$ROOT/var/selfcheck.json" >/dev/null || { rc=$?; status_fail "self-check failed (see $ROOT/var/selfcheck.json and journalctl -u grantai)" "$rc"; }

# ---------------------------------------------------------------- 13 status
STEP=status
python3 - "$ROOT/var/version.json" "$ROOT/var/selfcheck.json" "$INSTALL_ID" "$LIC_TIER" "$LIC_EXP" "$LIC_STATE" "$VM_FQDN" "$HTTP_PORT" "$TLS_FP" > "$STATUS" <<'PY'
import json, sys, datetime
ver = json.load(open(sys.argv[1])); sc = json.load(open(sys.argv[2]))
print(json.dumps({
  "ok": True, "version": ver, "install_id": sys.argv[3],
  "licence": {"tier": sys.argv[4], "expires_at": sys.argv[5], "state": sys.argv[6]},
  "endpoint": f"https://{sys.argv[7]}:{sys.argv[8]}", "tls_sha256": sys.argv[9],
  "selfcheck": sc, "token": "in Key Vault secret grantai-http-token",
  "finished_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}, indent=2))
PY
chmod 0644 "$STATUS"
echo "=== GrantAi first boot complete ==="
cat "$STATUS"
