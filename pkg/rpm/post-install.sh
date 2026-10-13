# rpm sets no capability on its own here: nfpm.yaml asks for no %caps,
# so cap_net_raw is set after install, as the deb postinst does. A failed setcap
# leaves mtuspy installed; it then prints its own permission advice when run.
# Permitted only (+p), mtuspy raises it while it opens the raw socket: with +ep
# the kernel refused to exec it in a container without NET_RAW (#5).
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw+p /usr/bin/mtuspy \
        || echo "mtuspy: setcap cap_net_raw failed; run mtuspy with sudo" >&2
fi
exit 0
