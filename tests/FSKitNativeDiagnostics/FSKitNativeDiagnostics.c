#include "FSKitNativeDiagnostics.h"
#include <errno.h>
#include <fcntl.h>
#include <hfs/hfs_mount.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <unistd.h>

static ISCSITestDeviceIdentity device_sync_identity(int descriptor, uint64_t expectedBlocks,
                                                    int access, int characterOnly) {
    ISCSITestDeviceIdentity result = {0};
    struct stat node = {0};
    uint32_t blockSize = 0;
    uint64_t blockCount = 0;
    int flags = fcntl(descriptor, F_GETFL);
    if (flags == -1 || fstat(descriptor, &node) != 0) {
        result.error = errno;
        return result;
    }
    if ((characterOnly ? !S_ISCHR(node.st_mode)
                       : (!S_ISCHR(node.st_mode) && !S_ISBLK(node.st_mode))) ||
        (flags & O_ACCMODE) != access) {
        result.error = EPERM;
        return result;
    }
    if (ioctl(descriptor, DKIOCGETBLOCKSIZE, &blockSize) != 0 ||
        ioctl(descriptor, DKIOCGETBLOCKCOUNT, &blockCount) != 0) {
        result.error = errno;
        return result;
    }
    if (blockSize != 512 || blockCount != expectedBlocks) {
        result.error = EINVAL;
        return result;
    }
    result.deviceID = (uint64_t)node.st_rdev;
    return result;
}

static ISCSITestCallResult device_cache_sync(int descriptor, uint64_t approvedDeviceID,
                                             uint64_t expectedBytes, int access,
                                             int characterOnly) {
    ISCSITestCallResult result = {-1, 0};
    struct stat node = {0};
    int flags = fcntl(descriptor, F_GETFL);
    if (flags == -1 || fstat(descriptor, &node) != 0) {
        result.error = errno;
        return result;
    }
    if ((characterOnly ? !S_ISCHR(node.st_mode)
                       : (!S_ISCHR(node.st_mode) && !S_ISBLK(node.st_mode))) ||
        (flags & O_ACCMODE) != access || (uint64_t)node.st_rdev != approvedDeviceID) {
        result.error = EPERM;
        return result;
    }
    dk_synchronize_t request = {0};
    request.length = expectedBytes;
    result.status = ioctl(descriptor, DKIOCSYNCHRONIZE, &request);
    result.error = result.status == -1 ? errno : 0;
    return result;
}

ISCSITestDeviceIdentity iscsi_test_device_sync_identity(int descriptor) {
    return device_sync_identity(descriptor, 2048, O_RDWR, 0);
}

ISCSITestCallResult iscsi_test_device_cache_sync(int descriptor, uint64_t approvedDeviceID) {
    return device_cache_sync(descriptor, approvedDeviceID, 1048576, O_RDWR, 0);
}

ISCSITestDeviceIdentity iscsi_test_hfs_device_sync_identity(int descriptor) {
    return device_sync_identity(descriptor, 262144, O_RDONLY, 1);
}

ISCSITestCallResult iscsi_test_hfs_device_cache_sync(int descriptor, uint64_t approvedDeviceID) {
    return device_cache_sync(descriptor, approvedDeviceID, 134217728, O_RDONLY, 1);
}

ISCSITestCallResult iscsi_test_hfs_device_cache_sync_zero(int descriptor,
                                                          uint64_t approvedDeviceID) {
    return device_cache_sync(descriptor, approvedDeviceID, 0, O_RDONLY, 1);
}

ISCSITestDeviceIdentity iscsi_test_hfs_partition_sync_identity(int descriptor) {
    return device_sync_identity(descriptor, 262064, O_RDONLY, 1);
}

ISCSITestCallResult iscsi_test_hfs_partition_cache_sync_zero(int descriptor,
                                                             uint64_t approvedDeviceID) {
    return device_cache_sync(descriptor, approvedDeviceID, 0, O_RDONLY, 1);
}

ISCSITestDiskFeatures iscsi_test_disk_features(int descriptor) {
    ISCSITestDiskFeatures result = {0};
    if (ioctl(descriptor, DKIOCGETFEATURES, &result.mask) == -1) {
        result.error = errno;
        return result;
    }
    result.barrier = (result.mask & DK_FEATURE_BARRIER) != 0;
    result.queuedFlush = (result.mask & DK_FEATURE_QUEUEDFLUSH) != 0;
    result.unmap = (result.mask & DK_FEATURE_UNMAP) != 0;
    return result;
}

ISCSITestVolumeFeatures iscsi_test_volume_features(const char *path) {
    ISCSITestVolumeFeatures result = {0};
    struct attrlist attributes = {0};
    struct {
        uint32_t length;
        vol_capabilities_attr_t capabilities;
    } response = {0};
    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES;
    if (getattrlist(path, &attributes, &response, sizeof(response), 0) == -1) {
        result.error = errno;
        return result;
    }
    if (response.length != sizeof(response)) {
        result.error = EIO;
        return result;
    }
    result.interfaceCapabilities = response.capabilities.capabilities[VOL_CAPABILITIES_INTERFACES];
    result.validInterfaces = response.capabilities.valid[VOL_CAPABILITIES_INTERFACES];
    result.barrierKnown = (result.validInterfaces & VOL_CAP_INT_BARRIERFSYNC) != 0;
    result.barrierSupported = (result.interfaceCapabilities & VOL_CAP_INT_BARRIERFSYNC) != 0;
    return result;
}

ISCSITestSyncMount iscsi_test_hfs_sync_mount(const char *volume, const char *device) {
    ISCSITestSyncMount result = {0};
    struct statfs before = {0}, after = {0};
    struct stat directory = {0};
    if (!volume || !device || !volume[0] || strncmp(device, "/dev/disk", 9) != 0) {
        result.error = EINVAL;
        return result;
    }
    if (lstat(volume, &directory) != 0 || statfs(volume, &before) != 0) {
        result.error = errno;
        return result;
    }
    result.beforeFlags = result.afterFlags = before.f_flags;
    if (!S_ISDIR(directory.st_mode) || strcmp(before.f_fstypename, "hfs") != 0 ||
        strcmp(before.f_mntonname, volume) != 0 || strcmp(before.f_mntfromname, device) != 0 ||
        before.f_owner != geteuid() || (before.f_flags & (MNT_ROOTFS | MNT_RDONLY)) != 0) {
        result.error = EPERM;
        return result;
    }
    struct hfs_mount_args arguments = {0};
    arguments.fspec = (char *)device;
    arguments.hfs_uid = (uid_t)VNOVAL;
    arguments.hfs_gid = (gid_t)VNOVAL;
    arguments.hfs_mask = (mode_t)VNOVAL;
    arguments.hfs_encoding = (uint32_t)VNOVAL;
    arguments.hfs_timezone.tz_minuteswest = VNOVAL;
    arguments.hfs_timezone.tz_dsttime = VNOVAL;
    arguments.flags = VNOVAL;
    // Retain the existing policy flags; the synchronous and asynchronous flags
    // are mutually exclusive. This never requests remounting a readonly volume RW.
    int flags = (int)(before.f_flags & ~MNT_ASYNC) | MNT_UPDATE | MNT_SYNCHRONOUS;
    result.syscallAttempted = 1;
    if (mount("hfs", volume, flags, &arguments) != 0) {
        result.error = errno;
    }
    if (statfs(volume, &after) != 0) {
        if (result.error == 0) {
            result.error = errno;
        }
        return result;
    }
    result.afterFlags = after.f_flags;
    if (memcmp(&before.f_fsid, &after.f_fsid, sizeof(before.f_fsid)) != 0 ||
        strcmp(before.f_mntfromname, after.f_mntfromname) != 0) {
        result.error = ESTALE;
    } else if (result.error == 0 && (after.f_flags & MNT_SYNCHRONOUS) == 0) {
        result.error = ENOTSUP;
    }
    return result;
}

ISCSITestSyncMount iscsi_test_fskit_sync_mount(const char *volume, const char *source,
                                               const char *fileSystemType) {
    ISCSITestSyncMount result = {0};
    struct statfs before = {0}, after = {0};
    struct stat directory = {0};
    if (!volume || !source || !fileSystemType ||
        (strcmp(fileSystemType, "kurazuna") != 0 && strcmp(fileSystemType, "kurazunadev") != 0) ||
        !volume[0] || strncmp(source, "iscsi-fskit://", 14) != 0 ||
        strlen(source) >= sizeof(before.f_mntfromname)) {
        result.error = EINVAL;
        return result;
    }
    if (lstat(volume, &directory) != 0 || statfs(volume, &before) != 0) {
        result.error = errno;
        return result;
    }
    result.beforeFlags = result.afterFlags = before.f_flags;
    if (!S_ISDIR(directory.st_mode) || strcmp(before.f_fstypename, fileSystemType) != 0 ||
        strcmp(before.f_mntonname, volume) != 0 || strcmp(before.f_mntfromname, source) != 0 ||
        before.f_owner != geteuid() || (before.f_flags & (MNT_ROOTFS | MNT_RDONLY)) != 0) {
        result.error = EPERM;
        return result;
    }
    int flags = (int)(before.f_flags & ~MNT_ASYNC) | MNT_UPDATE | MNT_SYNCHRONOUS;
    result.syscallAttempted = 1;
    if (mount(fileSystemType, volume, flags, NULL) != 0) {
        result.error = errno;
    }
    if (statfs(volume, &after) != 0) {
        if (result.error == 0) {
            result.error = errno;
        }
        return result;
    }
    result.afterFlags = after.f_flags;
    if (memcmp(&before.f_fsid, &after.f_fsid, sizeof(before.f_fsid)) != 0 ||
        strcmp(before.f_fstypename, after.f_fstypename) != 0 ||
        strcmp(before.f_mntonname, after.f_mntonname) != 0 ||
        strcmp(before.f_mntfromname, after.f_mntfromname) != 0 || before.f_owner != after.f_owner) {
        result.error = ESTALE;
    } else if (result.error == 0 && (after.f_flags & MNT_SYNCHRONOUS) == 0) {
        result.error = ENOTSUP;
    }
    return result;
}
