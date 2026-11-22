#!/usr/bin/env python3
"""Run the memory-only macOS UI suite in the logged-in user's Aqua session."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]


def command(arguments, **options):
    return subprocess.run(arguments, capture_output=True, text=True, **options)


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def active_ui_processes():
    output = command(['/bin/ps', '-axo', 'uid=,pid=,command=']).stdout
    return [line for line in output.splitlines()
            if line.split(maxsplit=1)[0] == str(os.getuid())
            and '/xcodebuild ' in line and ' -scheme ISCSIPreviewUI ' in line]


def preflight(developer):
    env = dict(os.environ, DEVELOPER_DIR=str(developer))
    first = command(['/usr/bin/xcodebuild', '-checkFirstLaunchStatus'], env=env)
    mode = command(['/usr/bin/automationmodetool'])
    dev = command(['/usr/sbin/DevToolsSecurity', '-status'])
    uid = os.getuid()
    result = dict(uid=uid, consoleUID=os.stat('/dev/console').st_uid,
                  manager=command(['/bin/launchctl', 'managername']).stdout.strip(),
                  developerDirectory=str(developer), firstLaunchExit=first.returncode,
                  automation=mode.stdout.strip(), developerMode=dev.stdout.strip())
    issues = []
    if uid == 0 or result['consoleUID'] != uid:
        issues.append('Use the account currently logged into the Mac desktop.')
    if first.returncode:
        issues.append('Complete Xcode initial setup with xcodebuild -runFirstLaunch first.')
    if mode.returncode or 'DOES NOT REQUIRE user authentication' not in mode.stdout:
        issues.append('UI Automation still requires administrator authentication.')
    if dev.returncode or 'currently enabled' not in dev.stdout:
        issues.append('Developer mode is not enabled.')
    result.update(ready=not issues, issues=issues)
    return result


def worker(config_path):
    config = json.loads(config_path.read_text())
    folder = config_path.parent
    receipt = folder / 'Job.json'
    if receipt.exists():
        raise RuntimeError('This run already has a receipt. Use --resume; it will not restart tests.')
    state = dict(PID=os.getpid(), complete=False, phase='preflight', exit=None)
    write_json(receipt, state)
    try:
        checked = preflight(Path(config['developerDirectory']))
        write_json(folder / 'Preflight.json', checked)
        if not checked['ready'] or checked['manager'] != 'Aqua':
            raise RuntimeError('Aqua-session preflight failed; inspect Preflight.json.')
        lock_path = ROOT / 'build/UITestRuns/Active.lock'
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open('a+') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('Another UI suite is already running.') from None
            try:
                if active_ui_processes():
                    raise RuntimeError('An existing UI test process is still running; no new test started.')
                state.update(phase='running', manager='Aqua', command=config['command'])
                write_json(receipt, state)
                env = dict(os.environ, DEVELOPER_DIR=config['developerDirectory'])
                with (folder / 'Test.stdout').open('x') as out, (folder / 'Test.stderr').open('x') as err:
                    child = subprocess.Popen(config['command'], cwd=ROOT, env=env,
                                             stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                             close_fds=True)
                    state['childPID'] = child.pid
                    write_json(receipt, state)
                    code = child.wait()
                state.update(phase='terminal', complete=True, exit=code)
                write_json(receipt, state)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
    except Exception:
        state.update(phase='failed', complete=True, exit=1, exception=traceback.format_exc())
        write_json(receipt, state)
    return state['exit']


def monitor(folder):
    config = json.loads((folder / 'Config.json').read_text())
    receipt = folder / 'Job.json'
    service = config.get('service')
    missing = 0
    started = time.monotonic()
    while True:
        state = json.loads(receipt.read_text()) if receipt.exists() else None
        if state and state['complete']:
            if service:
                cleanup = folder / 'Cleanup.json'
                if cleanup.exists() and json.loads(cleanup.read_text()).get('serviceAbsent'):
                    absent = command(['/bin/launchctl', 'print', service]).returncode != 0
                else:
                    unloaded = command(['/bin/launchctl', 'bootout', service])
                    absent = command(['/bin/launchctl', 'print', service]).returncode != 0
                    write_json(cleanup, dict(bootoutExit=unloaded.returncode, serviceAbsent=absent))
                if not absent:
                    raise RuntimeError('The completed test agent could not be unloaded.')
            print(f"UI test exit {state['exit']}; logs: {folder}")
            return state['exit']
        if service:
            live = command(['/bin/launchctl', 'print', service])
            # Inspect the same service; a slow observation never restarts the test.
            missing = missing + 1 if live.returncode else 0
            if missing >= 3:
                raise RuntimeError(f'Test agent disappeared; inspect {folder}. No restart performed.')
            if live.returncode == 0 and not re.search(r'^\s*pid = \d+', live.stdout, re.M):
                # A registered, exited job is not evidence of a running worker.
                # An Xcode child may outlive a failed worker; keep observing it.
                if not active_ui_processes() and (state or time.monotonic() - started > 30):
                    # The worker writes its terminal receipt before it exits, possibly after
                    # the receipt was read above. Once it has exited, read the receipt again.
                    if receipt.exists() and json.loads(receipt.read_text())['complete']:
                        continue
                    raise RuntimeError(f'Test agent exited without a terminal receipt; inspect {folder}.')
        time.sleep(1)


def owned_build_path(value):
    path = Path(value).absolute()
    if path != path.resolve() or not path.is_relative_to(ROOT / 'build'):
        raise ValueError('Choose a nonsymlink path inside this project build directory.')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--derived-data', default=str(ROOT / 'build/UITests'))
    parser.add_argument('--result-bundle')
    parser.add_argument('--developer-dir', default=os.environ.get(
        'DEVELOPER_DIR', '/Applications/Xcode.app/Contents/Developer'))
    parser.add_argument('--without-building', action='store_true')
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--resume', type=Path)
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker)
    if args.resume:
        return monitor(owned_build_path(args.resume))
    developer = Path(args.developer_dir).absolute()
    checked = preflight(developer)
    print(json.dumps(checked, indent=2))
    if args.preflight_only:
        return 0 if checked['ready'] else 1
    if not checked['ready']:
        raise RuntimeError('UI preflight failed. No test or launch agent was started.')
    subprocess.run([sys.executable, str(ROOT / 'scripts/check-storage.py'),
                    '--required-gib', '10'], check=True)
    derived = owned_build_path(args.derived_data)
    result = owned_build_path(args.result_bundle or str(
        ROOT / 'build/UITestResults' / (str(time.time_ns()) + '.xcresult')))
    folder = result.with_name(result.stem + '-run')
    if result.exists() or folder.exists():
        raise ValueError('Choose a new result bundle; existing evidence is never overwritten.')
    folder.mkdir(parents=True, mode=0o700)
    result.parent.mkdir(parents=True, exist_ok=True)
    config = dict(developerDirectory=str(developer), command=[
        '/usr/bin/xcodebuild', '-project', 'Kurazuna.xcodeproj', '-scheme', 'ISCSIPreviewUI',
        '-configuration', 'Debug', '-destination', 'platform=macOS,arch=arm64',
        '-derivedDataPath', str(derived), '-resultBundlePath', str(result),
        'CODE_SIGN_STYLE=Manual', 'CODE_SIGN_IDENTITY=-', 'DEVELOPMENT_TEAM=',
        'CODE_SIGNING_ALLOWED=YES', 'OTHER_SWIFT_FLAGS=-disable-sandbox',
        '-parallel-testing-enabled', 'NO', '-test-timeouts-enabled', 'YES',
        '-default-test-execution-time-allowance', '60',
        '-maximum-test-execution-time-allowance', '120',
        'test-without-building' if args.without_building else 'test'])
    # Always detach the worker from the caller so an SSH disconnect or Ctrl-C
    # only stops observation. --resume observes the same job without replaying it.
    label = 'dev.soba.iscsi.UITest.' + uuid.uuid4().hex
    config['service'] = f'gui/{os.getuid()}/{label}'
    write_json(folder / 'Config.json', config)
    agent = folder / 'Agent.plist'
    agent.write_bytes(plistlib.dumps(dict(
        Label=label, ProgramArguments=[sys.executable, str(Path(__file__).resolve()),
                                       '--worker', str(folder / 'Config.json')],
        WorkingDirectory=str(ROOT), RunAtLoad=True, KeepAlive=False,
        LimitLoadToSessionType='Aqua', ProcessType='Interactive',
        StandardOutPath=str(folder / 'Agent.stdout'), StandardErrorPath=str(folder / 'Agent.stderr'))))
    agent.chmod(0o600)
    started = command(['/bin/launchctl', 'bootstrap', f'gui/{os.getuid()}', str(agent)])
    write_json(folder / 'Bootstrap.json', dict(exit=started.returncode, stderr=started.stderr))
    if started.returncode:
        raise RuntimeError(f'Could not start the GUI test agent: {started.stderr}')
    print(f'GUI job: {folder}', flush=True)
    return monitor(folder)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('The GUI test may still be running. Resume observation with --resume RUN_DIRECTORY.',
              file=sys.stderr)
        raise SystemExit(130)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'UI test error: {error}', file=sys.stderr)
        raise SystemExit(1)
