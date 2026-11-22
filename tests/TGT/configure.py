#!/usr/bin/env python3
"""Configure only the new TGT VM owned by scripts/test-lio.py --target tgt.

Calls the installed command-line tools; no TGT implementation is copied or linked.
CHAP values are public, disposable test fixtures.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

from digest_policy import configure_target, parse_policy, verify_target
import geometry_fixture


def main():
    action, name, nonce, *options = sys.argv[1:]
    assert os.geteuid() == 0
    assert re.fullmatch(r"iscsi-fskit-tgt-[0-9a-f]{12}", name)
    assert str(uuid.UUID(nonce)) == nonce
    base = Path("/var/tmp") / name
    staging = Path("/tmp") / name
    assert staging.is_dir() and not staging.is_symlink()
    if not base.exists():
        assert action in ("setup", "setup-geometry")
        base.mkdir(mode=0o700)
        (base / "owner").write_text(name + "\n")
    assert not base.is_symlink() and base.stat().st_uid == 0
    assert (base / "owner").read_text() == name + "\n"
    state = base / "active.json"
    image = base / (nonce + ".img")
    control = base / (nonce + ".socket")
    # The public control-port selector appends .0 to this path prefix.
    socket_path = Path(str(control) + ".0")
    environment = dict(os.environ, TGT_IPC_SOCKET=str(control))
    target = "iqn.2026-10.dev.soba:tgt-" + nonce

    def adm(*arguments):
        result = subprocess.run(["tgtadm", "--lld", "iscsi", *arguments], env=environment,
                                capture_output=True, text=True, check=True, timeout=10)
        return result.stdout

    if action in ("setup", "setup-geometry"):
        digest, chap, block_size, expected_hash = options
        policy = parse_policy(digest, legacy_single=True)
        assert chap in ("yes", "no")
        assert block_size in ("512", "4096")
        assert not state.exists() and not image.exists() and not socket_path.exists()
        incoming = staging / (nonce + ".img")
        assert incoming.is_file() and not incoming.is_symlink()
        if action == "setup-geometry":
            # An OS-created 512 MiB GPT with 4096-byte sectors, served only at 4096 B.
            assert block_size == "4096"
            geometry_fixture.validate(incoming)
        else:
            assert incoming.stat().st_size == 128 * 1048576
        with incoming.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == expected_hash
        shutil.copyfile(incoming, image)
        image.chmod(0o600)
        incoming.unlink()
        state.write_text(json.dumps({"nonce": nonce, "target": target, "chap": chap}))
        with (base / "tgtd.log").open("w") as log:
            daemon = subprocess.Popen(["tgtd", "--foreground", "--iscsi",
                                       "portal=127.0.0.1:3260,nop_interval=5,nop_count=3"],
                                      env=environment, stdin=subprocess.DEVNULL, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 10
        while not socket_path.exists():
            assert daemon.poll() is None, (base / "tgtd.log").read_text()
            assert time.monotonic() < deadline, "TGT private control socket did not appear"
            time.sleep(0.05)
        assert not adm("--mode", "target", "--op", "show").strip()
        adm("--mode", "target", "--op", "new", "--tid", "1", "--targetname", target)
        # TGT keeps its controller at LUN 0. Exercise a real disk at LUN 1.
        adm("--mode", "logicalunit", "--op", "new", "--tid", "1", "--lun", "1",
            "--backing-store", str(image), "--blocksize", block_size, "--bstype", "rdwr")
        configure_target(adm, policy)
        adm("--mode", "target", "--op", "bind", "--tid", "1", "--initiator-address", "127.0.0.1")
        adm("--mode", "target", "--op", "bind", "--tid", "1", "--initiator-name",
            "iqn.2026-10.dev.soba:tgt-probe-" + nonce)
        if chap == "yes":
            adm("--mode", "account", "--op", "new", "--user", "test-user",
                "--password", "correct horse battery staple")
            adm("--mode", "account", "--op", "bind", "--tid", "1", "--user", "test-user")
        parameters = adm("--mode", "target", "--op", "show", "--tid", "1")
        actual_digests = verify_target(parameters, policy)
        summary = adm("--mode", "target", "--op", "show")
        assert "Block size: " + block_size in summary
        # Retain actual daemon settings; no authentication response or payload is logged.
        (base / "settings.txt").write_text(summary + "\n" + parameters)
        print(json.dumps({"target": target, "lun": 1, "headerDigest": actual_digests["header"],
                          "dataDigest": actual_digests["data"], "blockSize": int(block_size), "chap": chap == "yes",
                          "targetNOPInterval": 5}))
    else:
        assert action in ("snapshot", "remove") and not options
        active = json.loads(state.read_text())
        assert active["nonce"] == nonce and active["target"] == target
        if action == "snapshot":
            # Never add a sync: the initiator's flush must already have completed.
            output = staging / (nonce + "-snapshot.img")
            assert not output.exists()
            shutil.copyfile(image, output)
            output.chmod(0o600)
            os.chown(output, staging.stat().st_uid, staging.stat().st_gid)
            print(hashlib.sha256(output.read_bytes()).hexdigest())
        else:
            summary = adm("--mode", "target", "--op", "show")
            targets = re.findall(r"^Target \d+: (.+)$", summary, re.MULTILINE)
            assert targets in ([], [target])
            # Normal deletion refuses an active session; never use --force.
            if targets:
                adm("--mode", "target", "--op", "delete", "--tid", "1")
            if active["chap"] == "yes" and "test-user" in adm("--mode", "account", "--op", "show"):
                adm("--mode", "account", "--op", "delete", "--user", "test-user")
            assert not adm("--mode", "target", "--op", "show").strip()
            adm("--mode", "system", "--op", "delete")
            image.unlink()
            state.unlink()
            print("PASS: disposable TGT target, backstore and daemon removed")


if __name__ == "__main__":
    main()
