#!/usr/bin/env python3
"""Configure only the disposable LIO instance created by scripts/test-lio.py.

Uses the installed rtslib API. No Linux or rtslib implementation is copied here.
The CHAP values are public test fixtures, never production credentials, except with
"mutual-stdin": then both secrets are disposable ones the harness passes on stdin
(scripts/test-lio-recovery.py), which are never printed, stored or put on a command line.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

import large_fixture
import large_filesystem
import geometry_fixture

from rtslib_fb import (RTSRoot, FabricModule, FileIOStorageObject, LUN,
                       MappedLUN, NetworkPortal, NodeACL, Target, TPG)


SUPPLIED_SECRET_BYTES = (12, 255)  # The product's minimum; within LIO's password buffer.


def supplied_secrets(stream, keys):
    """The disposable CHAP secrets `keys` the harness passes as one JSON line on `stream`
    (stdin). No message here ever includes a secret. A terminal would echo them: refused."""
    assert not stream.isatty(), "secrets are never read from a terminal"
    try:
        value = json.loads(stream.readline())
    except ValueError:
        raise AssertionError("the supplied secrets are not one JSON line") from None
    assert isinstance(value, dict) and sorted(value) == sorted(keys), "unexpected secret fields"
    for key in keys:
        secret = value[key]
        assert isinstance(secret, str) and secret.isascii() and secret.isprintable() \
            and SUPPLIED_SECRET_BYTES[0] <= len(secret) <= SUPPLIED_SECRET_BYTES[1], \
            "a supplied secret is not 12 to 255 printable ASCII characters"
    assert len({value[key] for key in keys}) == len(keys), "the supplied secrets must differ"
    return value


def export(image, store_name, target_name, nonce, digest, chap, block_size, supplied=None):
    """`supplied`: the "mutual-stdin" secrets (supplied_secrets). They are not kept anywhere but
    in the ACL, so an export that needs them again (a swap or a restage) is refused."""
    assert (chap == "mutual-stdin") == (supplied is not None), "mutual-stdin needs its secrets"
    store = FileIOStorageObject(store_name, str(image), size=image.stat().st_size, write_back=True)
    store.set_attribute("block_size", int(block_size))
    target = Target(FabricModule("iscsi"), target_name, mode="create")
    tpg = TPG(target, 1, mode="create")
    tpg.set_attribute("generate_node_acls", 0)
    tpg.set_attribute("authentication", int(chap != "no"))
    tpg.set_parameter("HeaderDigest", digest)
    tpg.set_parameter("DataDigest", digest)
    lun = LUN(tpg, 0, store)
    acl = NodeACL(tpg, "iqn.2026-10.dev.soba:lio-probe-" + nonce, mode="create")
    MappedLUN(acl, 0, lun, write_protect=False)
    if chap in ("yes", "mutual"):
        acl.chap_userid = "test-user"
        acl.chap_password = "correct horse battery staple"
    if chap == "mutual":
        acl.chap_mutual_userid = "test-server"
        acl.chap_mutual_password = "independent server password"
    if chap == "mutual-stdin":
        acl.chap_userid = "test-user"
        acl.chap_password = supplied["password"]
        acl.chap_mutual_userid = "test-server"
        acl.chap_mutual_password = supplied["targetPassword"]
    NetworkPortal(tpg, "127.0.0.1", 3260, mode="create")
    tpg.enable = True
    assert int(store.get_attribute("block_size")) == int(block_size)
    print(json.dumps({"kernel": os.uname().release, "target": target_name,
                      "headerDigest": tpg.get_parameter("HeaderDigest"),
                      "dataDigest": tpg.get_parameter("DataDigest"),
                      "blockSize": int(store.get_attribute("block_size")),
                      "writeCache": int(store.get_attribute("emulate_write_cache")),
                      "chap": chap != "no", "mutualCHAP": chap in ("mutual", "mutual-stdin"),
                      "suppliedSecrets": supplied is not None}, sort_keys=True))


def staged_export(stage, root, image, store_name, target_name, nonce, parameters):
    """One step of a configuration restore, as a target service might pass through it:
    a portal without this target (LIO answers 0301, not 0203, observed on Linux 6.12), the
    target without this initiator's ACL (0202), the ACL without CHAP credentials (0201),
    then the complete export. LIO zeroes the ISID of these rejections."""
    placeholder = target_name + "-placeholder"
    fabric = FabricModule("iscsi")
    if stage == "clear":
        for target in list(root.targets):
            target.delete()
        for store in list(root.storage_objects):
            store.delete()
    elif stage == "placeholder":
        assert not list(root.targets) and not list(root.storage_objects)
        tpg = TPG(Target(fabric, placeholder, mode="create"), 1, mode="create")
        tpg.set_attribute("generate_node_acls", 0)
        tpg.set_attribute("authentication", 0)
        NetworkPortal(tpg, "127.0.0.1", 3260, mode="create")
        tpg.enable = True
    elif stage == "no-acl":
        for target in list(root.targets):
            assert target.wwn == placeholder
            target.delete()
        # A restore recreates the same backstore, unit serial included; a new serial (NAA
        # designator) would be another logical unit, which the initiator rightly refuses.
        store = FileIOStorageObject(store_name, str(image), size=image.stat().st_size,
                                    wwn=parameters.get("wwn"), write_back=True)
        store.set_attribute("block_size", int(parameters["blockSize"]))
        tpg = TPG(Target(fabric, target_name, mode="create"), 1, mode="create")
        tpg.set_attribute("generate_node_acls", 0)
        tpg.set_attribute("authentication", int(parameters["chap"] != "no"))
        tpg.set_parameter("HeaderDigest", parameters["digest"])
        tpg.set_parameter("DataDigest", parameters["digest"])
        LUN(tpg, 0, store)
        NetworkPortal(tpg, "127.0.0.1", 3260, mode="create")
        tpg.enable = True
    elif stage in ("no-chap", "full"):
        target = Target(fabric, target_name, mode="lookup")
        tpg = TPG(target, 1, mode="lookup")
        if stage == "no-chap":
            acl = NodeACL(tpg, "iqn.2026-10.dev.soba:lio-probe-" + nonce, mode="create")
            MappedLUN(acl, 0, list(tpg.luns)[0], write_protect=False)
        else:
            acl = NodeACL(tpg, "iqn.2026-10.dev.soba:lio-probe-" + nonce, mode="any")
            if not list(acl.mapped_luns):
                MappedLUN(acl, 0, list(tpg.luns)[0], write_protect=False)
            if parameters["chap"] in ("yes", "mutual"):
                acl.chap_userid = "test-user"
                acl.chap_password = "correct horse battery staple"
            if parameters["chap"] == "mutual":
                acl.chap_mutual_userid = "test-server"
                acl.chap_mutual_password = "independent server password"
    else:
        raise ValueError("Unknown restore stage")


def fixture_status(root, image, swapped):
    """Read-only view of exported state, sessions, write cache and backing hashes."""
    sessions = []
    for target in root.targets:
        for tpg in target.tpgs:
            for acl in tpg.node_acls:
                info = Path(acl.path) / "info"
                text = info.read_text() if info.exists() else ""
                if "No active iSCSI Session" not in text and text.strip():
                    sessions.append(text.strip())
    stores = []
    for store in root.storage_objects:
        stores.append({"name": store.name, "udevPath": store.udev_path, "wwn": store.wwn,
                       "size": int(store.size),
                       "writeCache": int(store.get_attribute("emulate_write_cache"))})
    def digest(path):
        if not path.exists():
            return None
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    return {"targets": [t.wwn for t in root.targets], "stores": stores, "sessions": sessions,
            "imageSHA256": digest(image), "swappedSHA256": digest(swapped),
            "sessionCount": len(list(root.sessions))}


def main():
    action, name, nonce, *options = sys.argv[1:]
    assert os.geteuid() == 0
    assert re.fullmatch(r"iscsi-fskit-lio-[0-9a-f]{12}", name)
    assert str(uuid.UUID(nonce)) == nonce
    base = Path("/var/tmp") / name
    staging = Path("/tmp") / name
    assert staging.is_dir() and not staging.is_symlink()
    if not base.exists():
        assert action in ("setup", "setup-sparse", "setup-filesystem", "setup-geometry")
        base.mkdir(mode=0o700)
        (base / "owner").write_text(name + "\n")
    assert not base.is_symlink() and base.stat().st_uid == 0
    assert (base / "owner").read_text() == name + "\n"
    state = base / "active.json"
    root = RTSRoot()
    target_name = "iqn.2026-10.dev.soba:lio-" + nonce
    store_name = "fixture_" + nonce.replace("-", "")
    image = base / (nonce + ".img")

    sparse_state = base / "sparse.json"
    filesystem_state = base / "large-filesystem.json"
    stable = base / (nonce + "-stable.img")
    original = base / (nonce + "-original.img")
    # Recovery fault-injection state: export parameters, a saved configuration for
    # a controlled restore, and an optional replacement backstore (scripts/test-lio-recovery.py).
    export_state = base / "export.json"
    saved = base / "saveconfig.json"
    autorestore = Path("/etc/rtslib-fb-target/saveconfig.json")
    swapped = base / (nonce + "-swapped.img")
    if action in ("setup", "setup-sparse", "setup-filesystem", "setup-geometry"):
        digest, chap, block_size, expected_hash = options
        assert digest in ("CRC32C", "None") and chap in ("yes", "no", "mutual", "mutual-stdin")
        assert chap != "mutual-stdin" or action == "setup"
        # Read before anything changes, so that a refused input leaves nothing to clean up.
        supplied = (supplied_secrets(sys.stdin, ("password", "targetPassword"))
                    if chap == "mutual-stdin" else None)
        assert block_size in ("512", "4096")
        assert not state.exists() and not image.exists()
        assert not filesystem_state.exists() and not stable.exists() and not original.exists()
        assert not list(root.targets) and not list(root.storage_objects)
        if action == "setup-sparse":
            assert expected_hash == "sparse-3TiB-v1"
            assert not sparse_state.exists()
            large_fixture.create(image, nonce)
            sparse_state.write_text(json.dumps({"nonce": nonce, "byteCount": large_fixture.BYTE_COUNT}))
        elif action == "setup-filesystem":
            assert block_size == "512" and expected_hash in ("apfs", "exfat", "hfsplus")
            assert not sparse_state.exists()
            large_filesystem.blank(image)
            filesystem_state.write_text(json.dumps(dict(nonce=nonce, filesystem=expected_hash,
                                                        stage="live", digest=digest, chap=chap)))
        else:
            assert not sparse_state.exists()
            incoming = staging / (nonce + ".img")
            assert incoming.is_file() and not incoming.is_symlink()
            if action == "setup-geometry":
                assert block_size == "4096"
                geometry_fixture.validate(incoming)
            else:
                assert incoming.stat().st_size == 128 * 1048576
            with incoming.open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == expected_hash
            shutil.copyfile(incoming, image)
            image.chmod(0o600)
            incoming.unlink()
        # Save ownership before touching configfs, so partial setup is recoverable.
        state.write_text(json.dumps({"nonce": nonce, "target": target_name, "store": store_name}))
        export_state.write_text(json.dumps({"digest": digest, "chap": chap, "blockSize": block_size}))
        export(image, store_name, target_name, nonce, digest, chap, block_size, supplied)
        # A later guest crash (scripts/test-lio-recovery.py) must find the image and this
        # ownership state; ext4 may otherwise leave unsynchronized new files empty.
        os.sync()
    else:
        assert action in ("snapshot", "verify-sparse", "snapshot-large", "switch-large",
                          "verify-large-snapshot", "activate-large", "remove", "deactivate",
                          "status", "save", "restore", "swap-serial", "swap-size", "restage",
                          "rekey-mutual")
        if action == "verify-sparse":
            assert options in (["original"], ["written"])
        elif action == "save":
            assert options in (["auto"], ["manual"], ["clear"])
        elif action == "restage":
            assert options in (["clear"], ["placeholder"], ["no-acl"], ["no-chap"], ["full"])
        else:
            assert not options
        assert json.loads(state.read_text()) == {"nonce": nonce, "target": target_name, "store": store_name}
        targets = list(root.targets)
        stores = list(root.storage_objects)
        if action == "restage":
            assert all(t.wwn in (target_name, target_name + "-placeholder") for t in targets)
            parameters = json.loads(export_state.read_text())
            # The supplied secrets aren't kept; a restore would leave the ACL without them.
            assert parameters["chap"] != "mutual-stdin", "restage cannot restore supplied secrets"
            if options == ["clear"] and stores:
                assert len(stores) == 1 and stores[0].name == store_name
                parameters["wwn"] = stores[0].wwn
                export_state.write_text(json.dumps(parameters))
            staged_export(options[0], root, image, store_name, target_name, nonce, parameters)
            os.sync()
            print(json.dumps(fixture_status(RTSRoot(), image, swapped), sort_keys=True))
            return
        assert all(t.wwn == target_name for t in targets)
        assert all(s.name == store_name for s in stores)
        if action == "status":
            print(json.dumps(fixture_status(root, image, swapped), sort_keys=True))
        elif action == "rekey-mutual":
            # Only the target's mutual CHAP secret (scripts/test-lio-recovery.py R4-mutual), read
            # from stdin and never printed. A session already logged in goes on; the next login
            # answers the initiator's challenge with the new secret.
            assert json.loads(export_state.read_text())["chap"] == "mutual-stdin"
            secret = supplied_secrets(sys.stdin, ("targetPassword",))["targetPassword"]
            tpg = TPG(Target(FabricModule("iscsi"), target_name, mode="lookup"), 1, mode="lookup")
            acl = NodeACL(tpg, "iqn.2026-10.dev.soba:lio-probe-" + nonce, mode="lookup")
            assert acl.chap_mutual_userid == "test-server", "the ACL has no mutual CHAP user"
            assert secret != acl.chap_password, "the target's secret must differ from the initiator's"
            acl.chap_mutual_password = secret
            assert acl.chap_mutual_password == secret, "the mutual secret did not change"
            print(json.dumps({"targetSecretChanged": True, "sessionCount": len(list(root.sessions))},
                             sort_keys=True))
        elif action == "save":
            # "auto": the boot/service restore (rtslib-fb-targetctl) will recreate this export.
            # "manual": only an explicit restore will. "clear": no automatic restore.
            autorestore.unlink(missing_ok=True)
            if options == ["clear"]:
                print(json.dumps({"saved": None}))
                return
            assert targets and stores
            path = autorestore if options == ["auto"] else saved
            path.parent.mkdir(mode=0o755, exist_ok=True)
            root.save_to_file(str(path))
            path.chmod(0o600)
            # Make only this configuration durable. A global sync() would also flush the
            # backing file's page cache and hide a missing initiator SYNCHRONIZE CACHE from a
            # crash that follows (scripts/test-lio-recovery.py R5).
            for durable in (path, path.parent, export_state, base):
                descriptor = os.open(durable, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            print(json.dumps({"saved": str(path), "wwn": [s.wwn for s in stores]}))
        elif action == "restore":
            assert not targets and not stores and saved.exists()
            root.restore_from_file(str(saved))
            print(json.dumps(fixture_status(root, image, swapped), sort_keys=True))
        elif action in ("swap-serial", "swap-size"):
            # Replace the backstore under the same target name, ACL and credentials. A new
            # storage object gets a new unit serial; the size variant also changes capacity.
            parameters = json.loads(export_state.read_text())
            for target in targets:
                target.delete()
            for store in stores:
                store.delete()
            source = image
            if action == "swap-size":
                assert not swapped.exists()
                shutil.copyfile(image, swapped)
                swapped.chmod(0o600)
                with swapped.open("r+b") as stream:
                    stream.truncate(image.stat().st_size + 1048576)
                    os.fsync(stream.fileno())
                source = swapped
            export(source, store_name, target_name, nonce, parameters["digest"],
                   parameters["chap"], parameters["blockSize"])
            print(json.dumps(fixture_status(RTSRoot(), image, swapped), sort_keys=True))
        elif action == "snapshot":
            assert not sparse_state.exists() and not filesystem_state.exists()
            assert image.stat().st_size in (128 * 1048576, geometry_fixture.BYTE_COUNT)
            # Do not sync here: it would mask a missing initiator cache flush.
            output = staging / (nonce + "-snapshot.img")
            assert not output.exists()
            shutil.copyfile(image, output)
            output.chmod(0o600)
            os.chown(output, staging.stat().st_uid, staging.stat().st_gid)
            print(hashlib.sha256(output.read_bytes()).hexdigest())
        elif action == "verify-sparse":
            assert json.loads(sparse_state.read_text()) == {"nonce": nonce, "byteCount": large_fixture.BYTE_COUNT}
            print(json.dumps(large_fixture.verify(image, nonce, options == ["written"]), sort_keys=True))
        elif action in ("snapshot-large", "switch-large", "verify-large-snapshot", "activate-large"):
            info = json.loads(filesystem_state.read_text())
            assert info["nonce"] == nonce and info["filesystem"] in ("apfs", "exfat", "hfsplus")
            assert info["digest"] in ("CRC32C", "None") and info["chap"] in ("yes", "no", "mutual")
            if action == "snapshot-large":
                assert info["stage"] == "live" and not stable.exists()
                report = large_filesystem.copy(image, stable)
                stable.chmod(0o400)
                info["snapshot"] = report
                filesystem_state.write_text(json.dumps(info))
                print(json.dumps(report, sort_keys=True))
            else:
                report = large_filesystem.fingerprint(stable)
                assert report["sparseContentSHA256"] == info["snapshot"]["sparseContentSHA256"]
                if action == "activate-large":
                    assert info["stage"] in ("live", "replay")
                    assert not targets and not stores and not list(root.sessions)
                    large_filesystem.validate(image)
                    export(image, store_name, target_name, nonce, info["digest"], info["chap"], "512")
                elif action == "switch-large":
                    assert info["stage"] == "live" and not original.exists()
                    assert not list(root.sessions), "Original LUN is still connected"
                    for target in targets:
                        target.delete()
                    for store in stores:
                        store.delete()
                    image.rename(original)
                    large_filesystem.copy(stable, image)
                    info["stage"] = "replay"
                    filesystem_state.write_text(json.dumps(info))
                    export(image, store_name, target_name, nonce, info["digest"], info["chap"], "512")
                else:
                    assert info["stage"] == "replay"
                    print(json.dumps(report, sort_keys=True))
        else:
            assert not list(root.sessions), "A target session is still active"
            for target in targets:
                target.delete()
            for store in stores:
                store.delete()
            if action == "deactivate":
                print("PASS: disposable LIO exports removed; diagnostic images and ownership state retained")
                return
            image.unlink(missing_ok=True)
            swapped.unlink(missing_ok=True)
            export_state.unlink(missing_ok=True)
            saved.unlink(missing_ok=True)
            autorestore.unlink(missing_ok=True)
            sparse_state.unlink(missing_ok=True)
            filesystem_state.unlink(missing_ok=True)
            stable.unlink(missing_ok=True)
            original.unlink(missing_ok=True)
            state.unlink()
            print("PASS: disposable LIO target, ACL and backstore removed")


if __name__ == "__main__":
    main()
