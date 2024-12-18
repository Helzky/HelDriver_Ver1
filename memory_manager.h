#pragma once

#include <ntifs.h>
#include "driver_defs.h"
#include <wdm.h>

// function prototypes
PVOID find_pattern(PVOID startAddress, SIZE_T size, PCSTR pattern, PCSTR mask, PULONG patternId);
NTSTATUS read_memory(PEPROCESS targetProcess, PVOID address, PVOID outBuffer, SIZE_T size);
NTSTATUS inject_memory(PEPROCESS targetProcess, PVOID address, PVOID data, SIZE_T size);
NTSTATUS get_module_base_address(PEPROCESS targetProcess, PCSTR moduleName, PULONG_PTR moduleBase);
PVOID allocate_memory(SIZE_T size, ULONG tag);
VOID free_memory(PVOID memory, ULONG tag);
NTSTATUS protect_memory(PVOID address, SIZE_T size);
NTSTATUS unprotect_memory(PVOID address, SIZE_T size);