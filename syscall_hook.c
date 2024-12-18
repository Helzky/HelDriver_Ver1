#include "syscall_hook.h"
#include "logging.h"
#include <intrin.h>

// Global array to store hook entries
SYSCALL_HOOK_ENTRY g_hook_table[16]; // Example size, can change
ULONG g_hook_count = 0;

// Installs a syscall hook, with a unique hook id
NTSTATUS install_syscall_hook(PSYSCALL_HOOK_ENTRY hookEntry, PVOID hookFunction, ULONG syscallNumber) {
    if (!hookEntry || !hookFunction) {
        log_message("invalid parameters for install_syscall_hook");
        return STATUS_INVALID_PARAMETER;
    }

    // ... (Check if hook already exists - same as before)


    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation"); //example routine to hook, change as needed
    pfnZwQuerySystemInformation originalZwQuerySystemInformation = (pfnZwQuerySystemInformation)MmGetSystemRoutineAddress(&routineName); //cast to correct function pointer type


    if (!originalZwQuerySystemInformation) {
        log_message("failed to get original function address");
        return STATUS_NOT_FOUND;
    }

    //populate the hook entry structure
    hookEntry->originalFunction = (ULONG_PTR)originalZwQuerySystemInformation;
    hookEntry->hookedFunction = (ULONG_PTR)hookFunction;
    hookEntry->syscallNumber = syscallNumber;
    hookEntry->HookId = g_hook_count;


    //add to table and increment hook count
    g_hook_table[g_hook_count] = *hookEntry;
    g_hook_count++;

    log_message("syscall hook installed successfully, hook id: %d, syscall number: %d", hookEntry->HookId, syscallNumber);
    return STATUS_SUCCESS;

}



NTSTATUS uninstall_syscall_hook(PSYSCALL_HOOK_ENTRY hookEntry) {
    if (!hookEntry)
    {
        log_message("invalid parameter for uninstall_syscall_hook");
        return STATUS_INVALID_PARAMETER;
    }

    //loop through our syscall table to find a matching hook id
    for (ULONG i = 0; i < g_hook_count; i++)
    {
        if (g_hook_table[i].HookId == hookEntry->HookId)
        {
            //restore original function and set hook values to 0
            g_hook_table[i].originalFunction = 0;
            g_hook_table[i].hookedFunction = 0;
            g_hook_table[i].syscallNumber = 0;
            log_message("syscall hook uninstalled successfully for hook id: %d", hookEntry->HookId);
            return STATUS_SUCCESS;
        }
    }
    log_message("couldn't find hook id: %d to uninstall", hookEntry->HookId);
    return STATUS_UNHOOK_FAILED;

}



NTSTATUS my_hook(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    log_message("our syscall hook was called for ZwQuerySystemInformation");
    //loop through to find original and call if valid
    for (ULONG i = 0; i < g_hook_count; i++)
    {
        if (g_hook_table[i].hookedFunction == (ULONG_PTR)my_hook && g_hook_table[i].originalFunction)
        {
            pfnZwQuerySystemInformation original_function = (pfnZwQuerySystemInformation)g_hook_table[i].originalFunction;
            return original_function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        }
    }
    return STATUS_NOT_FOUND; //if original function not found return not found
}