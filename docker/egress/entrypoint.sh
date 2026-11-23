#!/bin/sh
# Egress sidecar: load the nftables policy, generate the dnsmasq allowlist,
# mark the container ready, then run dnsmasq in the foreground.
set -eu

: "${UPSTREAM_DNS:?set UPSTREAM_DNS to the Docker-provided resolver (scripts/run_validation.sh detects it)}"
case "$UPSTREAM_DNS" in
    *[!0-9.]*|"") echo "UPSTREAM_DNS must be an IPv4 literal" >&2; exit 2 ;;
esac

DNSMASQ_UID="$(id -u dnsmasq)"

# 1. Firewall first, so nothing can leave before the policy is in place.
sed -e "s/@UPSTREAM_DNS@/${UPSTREAM_DNS}/g" -e "s/@DNSMASQ_UID@/${DNSMASQ_UID}/g" \
    /etc/egress/ruleset.nft.tmpl > /run/ruleset.nft
nft -f /run/ruleset.nft
echo "egress: nftables policy loaded (upstream DNS ${UPSTREAM_DNS}, dnsmasq uid ${DNSMASQ_UID})"

# 2. DNS allowlist: approved names go upstream and their A records go into the
#    allow set. Every other name is answered NXDOMAIN locally.
{
    cat <<EOF
no-resolv
no-hosts
no-poll
listen-address=127.0.0.1
bind-interfaces
port=53
user=dnsmasq
group=dnsmasq
domain-needed
bogus-priv
filter-AAAA
log-queries=extra
log-facility=-
address=/#/
EOF
    grep -Ev '^[[:space:]]*(#|$)' /etc/egress/allowlist.txt | while read -r name; do
        case "$name" in
            *[!a-zA-Z0-9.-]*) echo "egress: invalid allowlist entry: $name" >&2; exit 2 ;;
        esac
        echo "server=/${name}/${UPSTREAM_DNS}"
        echo "nftset=/${name}/4#inet#egress#allowed4"
    done
} > /run/dnsmasq.conf
echo "egress: approved names:"; grep '^server=' /run/dnsmasq.conf | sed 's/^server=\/\([^/]*\)\/.*/  \1/'

dnsmasq --test --conf-file=/run/dnsmasq.conf
touch /run/egress.ready
exec dnsmasq --keep-in-foreground --conf-file=/run/dnsmasq.conf --pid-file=/run/dnsmasq.pid
