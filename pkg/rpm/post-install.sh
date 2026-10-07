# rpm sets no capability on its own here: cargo-generate-rpm writes no %caps,
# so cap_net_raw is set after install, as the deb postinst does. A failed setcap
# leaves mtuspy installed; it then prints its own permission advice when run.
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw+ep /usr/bin/mtuspy \
        || echo "mtuspy: setcap cap_net_raw failed; run mtuspy with sudo" >&2
fi
exit 0
