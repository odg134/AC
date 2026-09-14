#pragma once
#include <ntddk.h>

namespace Thread {
    NTSTATUS Start();
    void     Stop();
}
