#!/usr/bin/env bash
# Start a seeded demo: a fake upstream, a dnsy server on high ports, zones, rules, a signed zone
# and a burst of DNS traffic. Used to take the documentation screenshots (scripts/demo/capture.mjs).
#
#   scripts/demo/run.sh <work-dir> [path/to/dnsy]
#
# Writes <work-dir>/env with DNSY_API, DNSY_DNS_PORT and the admin credentials, then stays in the
# foreground until interrupted. Needs python3, curl, dig and jq.
set -euo pipefail

work="$(realpath -m "${1:?usage: run.sh <work-dir> [dnsy-binary]}")"
bin="${2:-${DNSY_BIN:-target/debug/dnsy}}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dns_port=15353
api_port=15380
up_port=15354
password="demo-password-1234"

rm -rf "$work"
mkdir -p "$work/zones" "$work/data"
cat >"$work/dnsy.toml" <<TOML
[server]
data_dir = "$work/data"
[dns]
udp = ["127.0.0.1:$dns_port"]
tcp = ["127.0.0.1:$dns_port"]
[api]
listen = ["127.0.0.1:$api_port"]
[zones]
dir = "$work/zones"
[resolver]
upstreams = ["127.0.0.1:$up_port"]
[dnssec]
validation = "off"
TOML
printf '0.0.0.0 ads.tracker-demo.net\n0.0.0.0 telemetry.adnetwork-demo.com\n0.0.0.0 pixel.badads-demo.org\n' >"$work/blocklist.hosts"

python3 "$here/fake_upstream.py" "$up_port" &
up_pid=$!
dnsy_pid=
trap 'kill $up_pid ${dnsy_pid:-} 2>/dev/null || true' EXIT

DNSY_PASSWORD="$password" "$bin" --config "$work/dnsy.toml" user create admin --role admin >/dev/null
token="$("$bin" --config "$work/dnsy.toml" token create --user admin --name demo --scope admin --scope api:write --scope api:read | grep -o 'dnsy_[A-Za-z0-9_-]*' | head -1)"
DNSY_DNSSEC_PASSPHRASE="demo-key-passphrase" "$bin" --config "$work/dnsy.toml" serve >"$work/serve.log" 2>&1 &
dnsy_pid=$!

api="http://127.0.0.1:$api_port/api/v1"
for _ in $(seq 100); do curl -fs "http://127.0.0.1:$api_port/readyz" >/dev/null && break; sleep 0.1; done
call() { curl -fsS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' "$@" >/dev/null; }

soa() { printf '{"mname":"ns1.%s","rname":"hostmaster.%s","serial":1,"refresh":7200,"retry":3600,"expire":1209600,"minimum":300}' "$1" "$1"; }
call -X POST "$api/zones" -d "{\"name\":\"example.com.\",\"default_ttl\":3600,\"soa\":$(soa example.com.),\"records\":[
 {\"name\":\"@\",\"type\":\"NS\",\"value\":\"ns1.example.com.\"},
 {\"name\":\"ns1\",\"type\":\"A\",\"value\":\"192.0.2.53\"},
 {\"name\":\"@\",\"type\":\"A\",\"value\":\"192.0.2.10\"},
 {\"name\":\"www\",\"type\":\"CNAME\",\"value\":\"example.com.\"},
 {\"name\":\"api\",\"type\":\"A\",\"ttl\":300,\"value\":\"192.0.2.20\"},
 {\"name\":\"@\",\"type\":\"MX\",\"value\":\"10 mail.example.com.\"},
 {\"name\":\"mail\",\"type\":\"A\",\"value\":\"192.0.2.25\"},
 {\"name\":\"@\",\"type\":\"TXT\",\"value\":\"\\\"v=spf1 mx -all\\\"\"}]}"
call -X POST "$api/zones" -d "{\"name\":\"lab.internal.\",\"default_ttl\":600,\"soa\":$(soa lab.internal.),\"records\":[
 {\"name\":\"@\",\"type\":\"NS\",\"value\":\"ns1.lab.internal.\"},
 {\"name\":\"ns1\",\"type\":\"A\",\"value\":\"10.0.0.2\"},
 {\"name\":\"nas\",\"type\":\"A\",\"value\":\"10.0.0.40\"},
 {\"name\":\"printer\",\"type\":\"A\",\"value\":\"10.0.0.50\"}]}"
call -X PUT "$api/zones/example.com./dnssec" -d '{"enabled":true}'
call -X POST "$api/rules" -d '{"kind":"block","domain":"tracker.example.net"}'
call -X POST "$api/blocklists" -d "{\"name\":\"demo-ads\",\"location\":\"$work/blocklist.hosts\",\"format\":\"hosts\",\"allow_private\":true}"
call -X POST "$api/acl" -d '{"action":"allow","cidr":"127.0.0.0/8","comment":"loopback"}'

q() { dig +short +time=2 +tries=1 @127.0.0.1 -p "$dns_port" "$@" >/dev/null || true; }
names=(example.com www.example.com api.example.com mail.example.com nas.lab.internal printer.lab.internal \
  news.demo-site.org cdn.demo-site.org video.stream-demo.net search.demo-engine.io git.code-demo.dev \
  ads.tracker-demo.net telemetry.adnetwork-demo.com pixel.badads-demo.org tracker.example.net nxdomain-demo.invalid nx.demo-site.org)
for round in 1 2 3 4 5 6; do
  for n in "${names[@]}"; do q "$n" A; done
  q example.com AAAA; q example.com MX; q +dnssec example.com A; q news.demo-site.org AAAA
done

cat >"$work/env" <<ENV
DNSY_API=http://127.0.0.1:$api_port
DNSY_DNS_PORT=$dns_port
DNSY_USER=admin
DNSY_PASSWORD=$password
ENV
echo "demo ready: $(cat "$work/env" | head -1) (admin / $password); Ctrl-C to stop"
wait "$dnsy_pid"
