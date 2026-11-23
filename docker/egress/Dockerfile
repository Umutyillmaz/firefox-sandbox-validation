# Egress-policy sidecar (nftables + filtering dnsmasq). Base image pinned by digest.
FROM --platform=linux/amd64 alpine:latest@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# The -nftset variant is the official Alpine build compiled with HAVE_NFTSET;
# the plain `dnsmasq` package lacks it.
RUN apk add --no-cache dnsmasq-dnssec-nftset nftables \
    && dnsmasq --version | head -2 && nft --version

COPY ruleset.nft.tmpl allowlist.txt /etc/egress/
COPY entrypoint.sh /usr/local/bin/egress-entrypoint
RUN chmod 0444 /etc/egress/* && chmod 0555 /usr/local/bin/egress-entrypoint

ENTRYPOINT ["/usr/local/bin/egress-entrypoint"]
