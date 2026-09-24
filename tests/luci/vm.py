#!/usr/bin/env python3
"""Test installed LuCI on real OpenWrt/procd/rpcd, inside a disposable QEMU VM."""
import functools
import http.server
import json
import os
from pathlib import Path
import re
import shlex
import socket
import sys
import tarfile
import tempfile
import threading

import pexpect
from playwright.sync_api import sync_playwright, expect


def main():
    disk, packages = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
    Path('build').mkdir(exist_ok=True)
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='fakeflow-luci-') as folder:
        serving = Path(folder)
        with tarfile.open(serving / 'packages.tar.gz', 'w:gz') as bundle:
            ipks = [*packages.glob('*.ipk'), *Path(os.environ['FF_IPK_CACHE']).rglob('*.ipk')]
            assert len(ipks) > 2
            for ipk in {p.name: p for p in ipks}.values():
                bundle.add(ipk, arcname=ipk.name)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=folder)
        with http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            base = f'http://10.0.2.2:{server.server_port}'
            guest = pexpect.spawn('qemu-system-x86_64', [
                '-accel', 'tcg', '-m', '768', '-smp', '2', '-nographic', '-no-reboot',
                '-nic', f'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{port}-:80',
                '-drive', f'file={disk},format=raw,if=virtio', '-snapshot',
            ], encoding='utf-8', codec_errors='replace', timeout=120)
            log = Path('build/luci-vm.log').open('w', encoding='utf-8')
            guest.logfile_read = log

            def run(command, timeout=60):
                guest.sendline("printf '\\n__FF_BEGIN__\\n'; " + command +
                               "; rc=$?; printf '\\n__FF_RC_%s__\\n' \"$rc\"")
                guest.expect(r'\r*\n__FF_BEGIN__\r*\n', timeout=timeout)
                guest.expect(r'\r*\n__FF_RC_(\d+)__\r*\n', timeout=timeout)
                output = guest.before
                assert guest.match.group(1) == '0', f'{command}\n{output}'
                return output

            def rpc(method, payload=None, ok=True):
                # Download input rather than exceeding the console's canonical line limit.
                (serving / 'request.json').write_text(json.dumps(payload or {}), encoding='utf-8')
                output = run(f'wget -qO /tmp/request.json {base}/request.json && '
                             f'ubus call fakeflow {shlex.quote(method)} "$(cat /tmp/request.json)"')
                result = json.loads(output[output.index('{'):output.rindex('}') + 1])
                assert result['ok'] is ok, result
                return result

            def save(data, **changes):
                payload = dict(config=data['config'], revision=data['revision'], enabled=False,
                               autostart=False, apply=False)
                payload.update(changes)
                return rpc('save', payload)

            try:
                guest.expect('Please press Enter to activate this console')
                guest.sendline('')
                guest.expect(r'root@[^:]+:.*#')
                run('for i in $(seq 1 60); do ip link show br-lan >/dev/null 2>&1 && break; sleep 1; done; '
                    'ip addr add 10.0.2.15/24 dev br-lan && ip route add default via 10.0.2.2 dev br-lan')
                run(f'mkdir -p /packages && wget -qO /tmp/packages.tar.gz {base}/packages.tar.gz && '
                    'tar -xzf /tmp/packages.tar.gz -C /packages && opkg install /packages/*.ipk', timeout=240)
                run("sed -i 's/name = \"eth1\"/name = \"eth0\"/' /etc/fakeflow.toml; "
                    "printf 'Fakeflow-test-24\\nFakeflow-test-24\\n' | passwd root; "
                    '/etc/init.d/rpcd restart; /etc/init.d/uhttpd restart')
                run('for i in $(seq 1 20); do ubus -v list fakeflow && break; sleep 1; done')
                original = rpc('get')
                assert not json.loads(original['status'])['running']
                rpc('validate', {'config': original['config']})
                rpc('validate', {'config': original['config'] + '\nunknown = 1'}, ok=False)
                rpc('action', {'action': 'start; touch /tmp/should-not-exist'}, ok=False)
                run('test ! -e /tmp/should-not-exist')
                rpc('save', dict(config=original['config'], revision='stale',
                                 enabled=True, autostart=True, apply=False), ok=False)
                rpc('save', dict(config=original['config'] + '\nunknown = 1', revision=original['revision'],
                                 enabled=True, autostart=True, apply=True), ok=False)
                rpc('save', dict(config=original['config'], revision=original['revision'],
                                 enabled='1', autostart=True, apply=False), ok=False)
                assert rpc('get')['revision'] == original['revision']
                custom = original['config'].replace('payload = "http"', 'payload = "custom"').replace(
                    'hostname = "www.example.com"', 'payload_file = "/etc/fakehttp/payload.tls"')
                rpc('validate', {'config': custom}, ok=False)  # Missing payload must fail.
                run("mkdir -p /etc/fakehttp; printf 'TEST-CUSTOM-PAYLOAD' > /etc/fakehttp/payload.tls")
                save(original, config=custom)
                current = rpc('get')
                assert current['config'] == custom
                run('test -s /etc/fakeflow.toml.luci-backup')
                save(current, enabled=True, autostart=True, apply=True)
                state = rpc('status')
                assert state['managed'] and state['enabled'] and state['autostart'], state
                assert json.loads(state['status'])['running']
                assert 'fake_submit_ok' in json.loads(state['stats'])
                rpc('action', {'action': 'stop'})
                assert not json.loads(rpc('status')['status'])['running']
                rpc('action', {'action': 'start'})
                rpc('action', {'action': 'restart'})
                rpc('action', {'action': 'stop'})
                # A manually launched instance is never silently taken over.
                run('(fakeflow run --config /etc/fakeflow.toml >/tmp/manual.log 2>&1 &)')
                run('for i in $(seq 1 15); do fakeflow status && break; sleep 1; done')
                rpc('action', {'action': 'restart'}, ok=False)
                run('fakeflow stop; sleep 1')
                assert not json.loads(rpc('status')['status'])['running']
                # Exercise rpcd's actual ACL resolution, not just the ACL JSON structure.
                run("uci set rpcd.viewer=login; uci set rpcd.viewer.username=viewer; "
                    "uci set 'rpcd.viewer.password=$p$root'; "
                    "uci add_list rpcd.viewer.read=luci-app-fakeflow; "
                    "uci commit rpcd; /etc/init.d/rpcd restart; sleep 2")
                out = run("ubus call session login '{\"username\":\"viewer\",\"password\":\"Fakeflow-test-24\"}'")
                session = json.loads(out[out.index('{'):out.rindex('}') + 1])['ubus_rpc_session']
                for method in ['get', 'status', 'save', 'validate', 'action']:
                    request = json.dumps(dict(ubus_rpc_session=session, scope='ubus', object='fakeflow', function=method))
                    out = run('ubus call session access ' + shlex.quote(request))
                    allowed = json.loads(out[out.index('{'):out.rindex('}') + 1])['access']
                    assert allowed is (method in ['get', 'status']), (method, allowed)
                print('RPC validation, stale edit protection, custom payload, procd and manual-instance tests passed.')

                with sync_playwright() as pw:
                    browser = pw.chromium.launch()
                    context = browser.new_context(viewport={'width': 1366, 'height': 1000})
                    context.tracing.start(screenshots=True, snapshots=True)
                    page = context.new_page()
                    errors = []
                    page.on('pageerror', lambda e: errors.append(str(e)))
                    try:
                        page.goto(f'http://127.0.0.1:{port}/cgi-bin/luci/admin/services/fakeflow')
                        page.locator('input[name="luci_username"]').fill('root')
                        page.locator('input[name="luci_password"]').fill('Fakeflow-test-24')
                        page.get_by_role('button', name='Log in', exact=True).click()
                        expect(page.locator('#fakeflow-status')).to_be_visible(timeout=60000)
                        expect(page.locator('#ff-start')).to_be_enabled()

                        def tab(name):
                            page.locator('.cbi-tabmenu').get_by_text(name, exact=True).click()

                        def field(key):
                            return page.locator(f'[id="widget.cbid.json.settings.{key}"]')

                        tab('TCP')
                        expect(field('tcp_payload_file')).to_have_value('/etc/fakehttp/payload.tls')
                        field('tcp_payload').select_option('http')
                        expect(field('tcp_hostname')).to_be_visible()
                        expect(field('tcp_payload_file')).not_to_be_visible()
                        field('tcp_payload').select_option('custom')
                        expect(field('tcp_payload_file')).to_have_value('/etc/fakehttp/payload.tls')
                        page.screenshot(path='build/luci-desktop.png', full_page=True)
                        page.locator('#ff-preview').click()
                        expect(page.locator('.modal pre')).to_contain_text('payload_file = "/etc/fakehttp/payload.tls"')
                        page.get_by_role('button', name='关闭', exact=True).click()
                        tab('UDP')
                        field('udp_trigger').select_option('both')
                        field('udp_initial_packets').fill('6')
                        page.locator('#ff-validate').click()
                        expect(page.get_by_text('Configuration valid;', exact=False)).to_be_visible(timeout=15000)
                        field('udp_initial_packets').fill('5')
                        page.locator('#ff-preview').click()
                        expect(page.locator('.modal pre')).to_contain_text('initial_packets = 5')
                        page.get_by_role('button', name='关闭', exact=True).click()
                        field('udp_initial_packets').fill('6')
                        page.get_by_role('button', name=re.compile(r'^Save & Apply$|^保存并应用$')).click()
                        expect(page.locator('#fakeflow-status')).to_contain_text('procd 托管', timeout=30000)
                        assert 'initial_packets = 6' in rpc('get')['config']
                        assert 'trigger = "both"' in rpc('get')['config']
                        page.locator('#ff-stop').click()
                        expect(page.locator('#fakeflow-status')).to_contain_text('已停止', timeout=30000)
                        page.locator('#ff-start').click()
                        expect(page.locator('#fakeflow-status')).to_contain_text('procd 托管', timeout=30000)
                        # A console edit must not get overwritten by an old browser form.
                        run("printf '\\n# changed externally\\n' >> /etc/fakeflow.toml")
                        page.get_by_role('button', name=re.compile(r'^Save$|^保存$')).click()
                        expect(page.get_by_text('配置已被其他页面或终端修改，请重新加载后再保存。').first).to_be_visible(timeout=15000)
                        assert '# changed externally' in rpc('get')['config']
                        page.reload()
                        expect(page.locator('#fakeflow-status')).to_be_visible(timeout=30000)
                        tab('UDP')
                        expect(field('udp_initial_packets')).to_have_value('6')
                        page.set_viewport_size({'width': 390, 'height': 844})
                        page.screenshot(path='build/luci-mobile.png', full_page=True)
                        assert not errors, errors
                        print('Real LuCI login, form import, preview, validation, save/apply, start/stop and conflict tests passed.')
                    except Exception:
                        page.screenshot(path='build/luci-failure.png', full_page=True)
                        Path('build/luci-failure.html').write_text(page.content(), encoding='utf-8')
                        print('Browser errors:', errors)
                        raise
                    finally:
                        context.tracing.stop(path='build/luci-trace.zip')
                        browser.close()
                rpc('action', {'action': 'stop'})
                run('test -z "$(tc filter show dev eth0 ingress)" && test -z "$(tc filter show dev eth0 egress)"')
            finally:
                guest.close(force=True)
                server.shutdown()
                log.close()
                print(Path('build/luci-vm.log').read_text(encoding='utf-8')[-24000:])


if __name__ == '__main__':
    main()
