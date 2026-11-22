#ifndef ISCSI_FSKIT_NATIVE_DIAGNOSTICS_H
#define ISCSI_FSKIT_NATIVE_DIAGNOSTICS_H

#include <stdint.h>

typedef struct {
    int error;
    uint32_t mask;
    int barrier;
    int queuedFlush;
    int unmap;
} ISCSITestDiskFeatures;

typedef struct {
    int error;
    uint32_t interfaceCapabilities;
    uint32_t validInterfaces;
    int barrierKnown;
    int barrierSupported;
} ISCSITestVolumeFeatures;

// Read-only queries using the installed SDK's definitions, never numeric ioctls.
ISCSITestDiskFeatures iscsi_test_disk_features(int descriptor);
ISCSITestVolumeFeatures iscsi_test_volume_features(const char *path);

typedef struct {
    int error;
    int syscallAttempted;
    uint32_t beforeFlags;
    uint32_t afterFlags;
} ISCSITestSyncMount;

// Test only: caller first verifies a nonce-scoped DiskImages attachment. Refuse
// root, readonly, foreign-owner or mismatched filesystems before mount(MNT_UPDATE).
ISCSITestSyncMount iscsi_test_hfs_sync_mount(const char *volume, const char *device);

// Test only: update a private, writable, caller-owned FSKit bridge whose full
// mountpoint and resource URL match. No DiskImages attachment is involved.
// The caller selects its edition explicitly; only the two known FSKit types are accepted.
ISCSITestSyncMount iscsi_test_fskit_sync_mount(const char *volume, const char *source,
                                               const char *fileSystemType);

typedef struct {
    int status;
    int error;
} ISCSITestCallResult;

typedef struct {
    int error;
    uint64_t deviceID;
} ISCSITestDeviceIdentity;

// Caller first verifies the nonce-scoped DiskImages attachment. Validate a
// writable 1MiB, 512-byte-sector device before any measured data writes.
ISCSITestDeviceIdentity iscsi_test_device_sync_identity(int descriptor);
// Recheck the approved descriptor's identity without extra driver geometry
// queries between the measured write and cache synchronization.
ISCSITestCallResult iscsi_test_device_cache_sync(int descriptor, uint64_t approvedDeviceID);

// Separate test fixture: read-only raw character descriptor, exactly 128MiB and
// 512-byte sectors. No payload writes. The caller verifies
// the mounted HFS+ partition and its private DiskImages parent before opening.
// The original 1MiB entry points retain their existing capacity requirement.
ISCSITestDeviceIdentity iscsi_test_hfs_device_sync_identity(int descriptor);
ISCSITestCallResult iscsi_test_hfs_device_cache_sync(int descriptor, uint64_t approvedDeviceID);

// Same whole-device identity, with a zero-length synchronization request.
ISCSITestCallResult iscsi_test_hfs_device_cache_sync_zero(int descriptor,
                                                          uint64_t approvedDeviceID);
// Fixed HFS+ partition of the 128MiB GPT fixture: 134176768 bytes, 512B sectors.
ISCSITestDeviceIdentity iscsi_test_hfs_partition_sync_identity(int descriptor);
ISCSITestCallResult iscsi_test_hfs_partition_cache_sync_zero(int descriptor,
                                                             uint64_t approvedDeviceID);

#endif
