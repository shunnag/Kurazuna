#ifndef ISCSI_DISK_ARBITRATION_STATUS_H
#define ISCSI_DISK_ARBITRATION_STATUS_H

#include <DiskArbitration/DADissenter.h>
#include <errno.h>
#include <mach/error.h>
#include <stdbool.h>
#include <stdint.h>

// unix_err is a public SDK function-like macro that Swift cannot import.
static inline bool ISCSIDiskArbitrationStatusIsBusy(int32_t status) {
  return status == kDAReturnBusy || status == EBUSY ||
         status == unix_err(EBUSY);
}

#endif
