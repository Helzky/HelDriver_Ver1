#include "memory_manager.h"
#include "logging.h"
#include <intrin.h>
#include <ntddk.h>
#include <wdm.h>
#include <string.h>

#ifndef SystemModuleInformation
#define SystemModuleInformation 5
#endif

// Redefine the SYSTEM_MODULE_INFORMATION structure (corrected)
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


PVOID find_pattern(PVOID startAddress, SIZE_T size, PCSTR pattern, PCSTR mask, PULONG patternId) {
    if (!startAddress || !pattern || !mask || !patternId) {
        log_message("invalid parameters for find_pattern");
        return NULL;
    }

    const unsigned char* pStart = (const unsigned char*)startAddress;
    const size_t patternSize = strlen(mask);

    ULONG id = (ULONG)((ULONG_PTR)startAddress ^ (ULONG_PTR)pattern ^ (ULONG_PTR)mask ^ (ULONG_PTR)KeGetCurrentThread()); //more complex id
    *patternId = id;


    for (SIZE_T i = 0; i < size - patternSize; ++i) {
        int found = 1;
        for (size_t j = 0; j < patternSize; ++j) {
            if (mask[j] == 'x' && pStart[i + j] != (unsigned char)pattern[j]) {
                found = 0;
                break;
            }
        }
        if (found) {
            return (PVOID)(pStart + i);
        }
    }
    return NULL;
}


NTSTATUS read_memory(PEPROCESS targetProcess, PVOID address, PVOID outBuffer, SIZE_T size) {
    if (!targetProcess || !address || !outBuffer || size == 0) {
        log_message("invalid parameters for read_memory");
        return STATUS_INVALID_PARAMETER;
    }

    KAPC_STATE apcState;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T bytesRead = 0;
    MEMORY_BASIC_INFORMATION mbi = { 0 };


    KeStackAttachProcess(targetProcess, &apcState);

    __try {
        status = ZwQueryVirtualMemory(NtCurrentProcess(), address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status)) {
            log_message("ZwQueryVirtualMemory failed: 0x%08X", status);
            __leave;  // Correct use of __leave within __try
        }


        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
            log_message("invalid page protection or memory not committed at 0x%p", address);
            status = STATUS_ACCESS_VIOLATION;
            __leave; // Correct use of __leave within __try
        }

        status = MmCopyVirtualMemory(targetProcess, address, PsGetCurrentProcess(), outBuffer, size, KernelMode, &bytesRead);
        if (!NT_SUCCESS(status)) {
            log_message("MmCopyVirtualMemory failed: 0x%08X", status);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        log_message("Exception caught during read_memory: 0x%08X", status);
    }
    __finally {
        KeUnstackDetachProcess(&apcState);
    }

    return status;
}



NTSTATUS inject_memory(PEPROCESS targetProcess, PVOID address, PVOID data, SIZE_T size) {
    if (!targetProcess || !address || !data || size == 0) {
        log_message("invalid parameters for inject_memory");
        return STATUS_INVALID_PARAMETER;
    }

    //same logic as read memory with error checking and exception handling
    KAPC_STATE apcState;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T bytesWritten = 0;
    MEMORY_BASIC_INFORMATION mbi = { 0 }; //initialize mbi


    KeStackAttachProcess(targetProcess, &apcState);
    __try {

        status = ZwQueryVirtualMemory(NtCurrentProcess(), address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status)) {
            log_message("zwqueryvirtualmemory failed: 0x%08X", status);
            __leave; //leave try block on fail
        }


        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) { // do not attempt to read memory from pages not commited, guarded, or inaccessible
            status = STATUS_ACCESS_VIOLATION;
            log_message("invalid page protection or memory not committed at 0x%p", address);
            __leave;
        }


        status = MmCopyVirtualMemory(PsGetCurrentProcess(), data, targetProcess, address, size, KernelMode, &bytesWritten);
        if (!NT_SUCCESS(status)) {
            log_message("mmcopyvirtualmemory failed: 0x%08X", status);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        log_message("exception caught during inject_memory: 0x%08X", status);

    }
    __finally {
        KeUnstackDetachProcess(&apcState);
    }
    return status;

}


NTSTATUS get_module_base_address(PEPROCESS targetProcess, PCSTR moduleName, PULONG_PTR moduleBase)
{
    if (!targetProcess || !moduleName || !moduleBase) {
        log_message("invalid parameters for get_module_base_address");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    PSYSTEM_MODULE_INFORMATION modules = NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize); //query the required buffer size

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        log_message("zwquerysysteminformation failed 0x%08X", status);
        return status;
    }


    buffer = allocate_memory(bufferSize, POOL_TAG_MEM_C);
    if (!buffer)
        return STATUS_MEMORY_ALLOCATION_FAILED;


    status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize); //query module info

    if (!NT_SUCCESS(status)) {
        log_message("zwquerysysteminformation failed 0x%08X", status);
        free_memory(buffer, POOL_TAG_MEM_C); //free allocated buffer
        return status;
    }



    modules = (PSYSTEM_MODULE_INFORMATION)buffer;
    for (ULONG i = 0; i < modules->Count; i++) {
        if (_stricmp((const char*)modules->Module[i].FullPathName, moduleName) == 0) {
            *moduleBase = (ULONG_PTR)modules->Module[i].ImageBase; // Correct field name

            free_memory(buffer, POOL_TAG_MEM_C); //free allocated buffer
            return STATUS_SUCCESS;
        }
    }

    free_memory(buffer, POOL_TAG_MEM_C); //free allocated buffer

    return STATUS_NOT_FOUND;
}

PVOID allocate_memory(SIZE_T size, ULONG tag) {

    PVOID memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, tag);
    if (!memory) {
        log_message("failed to allocate memory, tag: %c%c%c%c", (tag >> 0) & 0xFF, (tag >> 8) & 0xFF, (tag >> 16) & 0xFF, (tag >> 24) & 0xFF);
        return NULL;
    }
    RtlZeroMemory(memory, size);
    return memory;
}


VOID free_memory(PVOID memory, ULONG tag) {

    if (memory)
        ExFreePoolWithTag(memory, tag);
}

//implement protect_memory and unprotect_memory with the same robust error handling and clean up as before
NTSTATUS protect_memory(PVOID address, SIZE_T size) {
    if (!address || size == 0)
        return STATUS_INVALID_PARAMETER;


    PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    if (!mdl)
        return STATUS_MEMORY_ALLOCATION_FAILED;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); //probe and lock pages before build

        MmBuildMdlForNonPagedPool(mdl); //map pages

        if (!mdl->MappedSystemVa)
        {
            MmUnlockPages(mdl); //unlock before free
            IoFreeMdl(mdl);
            return STATUS_FAILURE;
        }


        MmProtectMdlSystemAddress(mdl, PAGE_READONLY); //set protection

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mdl && mdl->MappedSystemVa) //unlock before freeing mdl
            MmUnlockPages(mdl);

        IoFreeMdl(mdl); //free mdl if exception occurs

        return STATUS_FAILURE;
    }


    if (mdl && mdl->MappedSystemVa) //unlock after we're done using pages
        MmUnlockPages(mdl);

    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}


NTSTATUS unprotect_memory(PVOID address, SIZE_T size) {

    if (!address || size == 0)
        return STATUS_INVALID_PARAMETER;


    PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

    if (!mdl)
        return STATUS_MEMORY_ALLOCATION_FAILED;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); //probe and lock pages before build

        MmBuildMdlForNonPagedPool(mdl); //map pages


        if (!mdl->MappedSystemVa)
        {
            MmUnlockPages(mdl); //unlock before free
            IoFreeMdl(mdl);
            return STATUS_FAILURE;
        }

        MmProtectMdlSystemAddress(mdl, PAGE_READWRITE); //set protection


    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mdl && mdl->MappedSystemVa)
            MmUnlockPages(mdl); //unlock before free

        IoFreeMdl(mdl); //free if exception occurs
        return STATUS_FAILURE;

    }

    if (mdl && mdl->MappedSystemVa)
        MmUnlockPages(mdl);


    IoFreeMdl(mdl);
    return STATUS_SUCCESS;

}