#pragma once

#include <ntifs.h>
#include "nt_structs.h" // This includes the structures, so you don't need to redefine them here
#include "driver_defs.h"


typedef NTSTATUS(*pfnZwQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,  // These types are now defined by nt_structs.h
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct _SYSCALL_HOOK_ENTRY {
    ULONG_PTR originalFunction;
    ULONG_PTR hookedFunction;
    ULONG syscallNumber;
    ULONG HookId;
} SYSCALL_HOOK_ENTRY, * PSYSCALL_HOOK_ENTRY;

// function prototypes
NTSTATUS install_syscall_hook(PSYSCALL_HOOK_ENTRY hookEntry, PVOID hookFunction, ULONG syscallNumber);
NTSTATUS uninstall_syscall_hook(PSYSCALL_HOOK_ENTRY hookEntry);
NTSTATUS my_hook(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength); // Now correct