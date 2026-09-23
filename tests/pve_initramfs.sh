#!/bin/bash
# Build a disposable OpenWrt userspace with the user's exact PVE kernel.
set -euo pipefail
rootfs=$(realpath "$1")
dest=$(realpath -m "$2")
mkdir -p "$dest/kernel" "$dest/root"
cd "$dest"
release=6.8.4-3-pve
repo=http://download.proxmox.com/debian/pve
package=proxmox-kernel-6.8.4-3-pve-signed_6.8.4-3_amd64.deb
digest=458070d301dcafddf66ce2ea46bb39104563e5cb3c55f641050856289c4a31da
# Proxmox serves its public repository over HTTP. Authenticate the signed
# index with the official HTTPS-delivered key before trusting package bytes.
curl -fL --retry 3 https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg -o key.gpg
curl -fL --retry 3 "$repo/dists/bookworm/InRelease" -o InRelease
gpgv --keyring "$dest/key.gpg" InRelease
curl -fL --retry 3 "$repo/dists/bookworm/pve-no-subscription/binary-amd64/Packages.gz" -o Packages.gz
index_hash=$(awk '/^SHA256:/{section=1;next} /^[^ ]/{section=0} section && $3=="pve-no-subscription/binary-amd64/Packages.gz" {print $1}' InRelease)
test -n "$index_hash"
echo "$index_hash  Packages.gz" | sha256sum -c -
gzip -dc Packages.gz > Packages
grep -A20 '^Package: proxmox-kernel-6.8.4-3-pve-signed$' Packages | grep -Fx "SHA256: $digest"
curl -fL --retry 3 "$repo/dists/bookworm/pve-no-subscription/binary-amd64/$package" -o kernel.deb
echo "$digest  kernel.deb" | sha256sum -c -
dpkg-deb -x kernel.deb kernel
tar -xzf "$rootfs" -C root
cp "kernel/boot/vmlinuz-$release" vmlinuz
depmod -b "$dest/kernel" "$release"
for module in virtio_pci virtio_net dummy tun sch_ingress cls_bpf; do
    modprobe -d "$dest/kernel" -S "$release" --show-depends "$module"
done > modules.txt
python3 - "$dest" <<'PY'
from pathlib import Path
import shutil
import subprocess
import sys

dest = Path(sys.argv[1])
commands = []
paths = dict.fromkeys(line.split()[1] for line in (dest / 'modules.txt').read_text().splitlines() if line.startswith('insmod '))
for path in paths:
    source = Path(path)
    relative = source.relative_to(dest / 'kernel')
    output = dest / 'root' / relative
    output.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix in ('.zst', '.xz', '.gz'):
        output = output.with_suffix('')
        tool = {'.zst': 'zstd', '.xz': 'xz', '.gz': 'gzip'}[source.suffix]
        with output.open('wb') as stream:
            subprocess.run([tool, '-dc', str(source)], stdout=stream, check=True)
    else:
        shutil.copy2(source, output)
    commands.append('insmod /' + str(output.relative_to(dest / 'root')))
init = '''#!/bin/sh
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mkdir -p /var/lock /var/run /run
hostname pve-test
''' + '\n'.join(commands) + '''
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2 dev eth0
printf 'nameserver 10.0.2.3\\n' > /etc/resolv.conf
echo __FF_BOOT_READY__
exec /bin/sh
'''
(dest / 'root/init').write_text(init)
(dest / 'root/init').chmod(0o755)
PY
(cd root && find . -print0 | cpio --null -o -H newc --owner=0:0) | gzip -1 > initramfs.gz
