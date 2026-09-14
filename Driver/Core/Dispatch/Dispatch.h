#pragma once
#include <ntddk.h>

// Ioctl to ping the driver.
#define IOCTL_AC_TEST CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS )

DRIVER_DISPATCH DispatchCreate;
DRIVER_DISPATCH DispatchClose;
DRIVER_DISPATCH DispatchControl;
