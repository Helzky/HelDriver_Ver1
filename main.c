#include <ntifs.h>
#include "driver_defs.h"
#include "logging.h"
#include "memory_manager.h"
#include "string_obfuscation.h"
#include "syscall_hook.h"

// global communication buffer
COMMUNICATION_BUFFER g_comm_buffer;

// global variables
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_DeviceName, g_SymbolicLinkName;

// handles device io control requests
NTSTATUS dispatch_device_control(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    PCOMMUNICATION_BUFFER commBuffer = Irp->AssociatedIrp.SystemBuffer;

    switch (ioControlCode)
    {

    case IO_CONTROL_GET_PROCESS_ID:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER))
        {
            UNICODE_STRING processName;
            RtlInitUnicodeString(&processName, L"notepad.exe"); // example target process

            PEPROCESS process = NULL;
            HANDLE processId;

            status = GetProcessIdByName(&processName, &process, &processId);

            if (NT_SUCCESS(status)) {
                commBuffer->ProcessId = processId;
                log_message("process id: %d", (int)processId);
            }
            else {
                log_message("failed to get process by name, status: 0x%08X", status);
            }

            if (process)
                ObDereferenceObject(process);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid get process parameter");
        }
        break;

    case IO_CONTROL_READ_MEMORY:

        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->Address && commBuffer->Size > 0)
        {
            PEPROCESS process;
            status = PsLookupProcessByProcessId(commBuffer->ProcessId, &process); // lookup the process by id
            if (!NT_SUCCESS(status) || !process) {
                log_message("failed to get process object from id 0x%08X", commBuffer->ProcessId);
                status = STATUS_NOT_FOUND;
                break;
            }

            PVOID readBuffer = allocate_memory(commBuffer->Size, POOL_TAG_READ_M);
            if (readBuffer) {
                status = read_memory(process, commBuffer->Address, readBuffer, commBuffer->Size);
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(commBuffer->Buffer, readBuffer, commBuffer->Size);
                    commBuffer->Status = status;
                    log_message("succesfully read memory at address 0x%p", commBuffer->Address);
                }
                free_memory(readBuffer, POOL_TAG_READ_M); // free our buffer that was used for reading
            }
            else
            {
                status = STATUS_MEMORY_ALLOCATION_FAILED;
                log_message("failed to allocate memory for reading, status: 0x%08X", status);
            }
            if (process)
                ObDereferenceObject(process);

        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid read memory parameter");
        }

        break;

    case IO_CONTROL_WRITE_MEMORY:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->Address && commBuffer->Size > 0 && commBuffer->Buffer)
        {
            PEPROCESS process;
            status = PsLookupProcessByProcessId(commBuffer->ProcessId, &process); // lookup the process by id
            if (!NT_SUCCESS(status) || !process) {
                log_message("failed to get process object from id 0x%08X", commBuffer->ProcessId);
                status = STATUS_NOT_FOUND;
                break;
            }

            status = inject_memory(process, commBuffer->Address, commBuffer->Buffer, commBuffer->Size);
            if (NT_SUCCESS(status))
                log_message("injected memory at address: 0x%p", commBuffer->Address);

            if (process)
                ObDereferenceObject(process);

        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid write memory parameter");
        }

        break;

    case IO_CONTROL_ENCRYPT_STRING:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->Size > 0 && commBuffer->Buffer)
        {
            encrypt_string(commBuffer->Buffer, commBuffer->Size);
            log_message("string encrypted");
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid encrypt string parameter");
        }

        break;

    case IO_CONTROL_DECRYPT_STRING:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->Size > 0 && commBuffer->Buffer)
        {
            decrypt_string(commBuffer->Buffer, commBuffer->Size);
            log_message("string decrypted");
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid decrypt string parameter");
        }
        break;

    case IO_CONTROL_INJECT_MEMORY:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->Address && commBuffer->Size > 0 && commBuffer->Buffer)
        {
            PEPROCESS process;
            status = PsLookupProcessByProcessId(commBuffer->ProcessId, &process); // lookup the process by id
            if (!NT_SUCCESS(status) || !process) {
                log_message("failed to get process object from id 0x%08X", commBuffer->ProcessId);
                status = STATUS_NOT_FOUND;
                break;
            }

            status = inject_memory(process, commBuffer->Address, commBuffer->Buffer, commBuffer->Size);
            if (NT_SUCCESS(status))
                log_message("injected memory at address: 0x%p", commBuffer->Address);

            if (process)
                ObDereferenceObject(process);

        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid inject memory parameter");
        }
        break;

    case IO_CONTROL_SCAN_PATTERN:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->Address && commBuffer->Size > 0 && commBuffer->Pattern && commBuffer->Mask)
        {
            PVOID patternAddress = find_pattern(commBuffer->Address, commBuffer->Size, commBuffer->Pattern, commBuffer->Mask, &commBuffer->PatternId);
            if (patternAddress)
            {
                commBuffer->Address = patternAddress;
                commBuffer->Status = STATUS_SUCCESS;
                log_message("pattern found at address: 0x%p with id: %d", commBuffer->Address, commBuffer->PatternId);
            }
            else
            {
                commBuffer->Status = STATUS_NOT_FOUND;
                log_message("pattern not found");
            }
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid scan pattern parameter");
        }

        break;
    case IO_CONTROL_INSTALL_HOOK:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->HookAddress)
        {
            SYSCALL_HOOK_ENTRY hookEntry;
            ULONG syscall_number = (ULONG)commBuffer->HookAddress;
            status = install_syscall_hook(&hookEntry, my_hook, syscall_number);

            if (NT_SUCCESS(status))
            {
                commBuffer->HookId = hookEntry.HookId; // return the hook id
                commBuffer->OriginalFunction = hookEntry.originalFunction;
                commBuffer->Status = status;
                log_message("successfully installed hook with hook id: %d", hookEntry.HookId);
            }
            else {
                log_message("failed to install hook, status: 0x%08X", status);
                commBuffer->Status = status;
            }
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid install hook parameters");
        }

        break;
    case IO_CONTROL_UNINSTALL_HOOK:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER))
        {
            SYSCALL_HOOK_ENTRY hookEntry;
            hookEntry.HookId = commBuffer->HookId;
            status = uninstall_syscall_hook(&hookEntry);
            if (NT_SUCCESS(status))
            {
                log_message("successfully uninstalled hook with hook id: %d", commBuffer->HookId);
                commBuffer->Status = status;
            }
            else
            {
                log_message("failed to uninstall hook, status: 0x%08X", status);
                commBuffer->Status = status;
            }
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid uninstall hook parameters");
        }
        break;
    case IO_CONTROL_REMOVE_DRIVER:
        // remove driver from system
        break;
    case IO_CONTROL_PROTECT_MEMORY:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->Address && commBuffer->Size > 0) {
            status = protect_memory(commBuffer->Address, commBuffer->Size);
            commBuffer->Status = status;
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid parameters to protect memory");
        }

        break;
    case IO_CONTROL_UNPROTECT_MEMORY:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->Address && commBuffer->Size > 0) {
            status = unprotect_memory(commBuffer->Address, commBuffer->Size);
            commBuffer->Status = status;
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid parameters to unprotect memory");
        }
        break;
    case IO_CONTROL_GET_MODULE_ADDRESS:
        if (commBuffer && irpStack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(COMMUNICATION_BUFFER) && commBuffer->ModuleName)
        {
            PEPROCESS process;
            status = PsLookupProcessByProcessId(commBuffer->ProcessId, &process); // lookup the process by id
            if (!NT_SUCCESS(status) || !process) {
                log_message("failed to get process object from id 0x%08X", commBuffer->ProcessId);
                status = STATUS_NOT_FOUND;
                break;
            }

            status = get_module_base_address(process, commBuffer->ModuleName, &commBuffer->ModuleBase);
            if (NT_SUCCESS(status))
                log_message("module base address found: 0x%p", commBuffer->ModuleBase);

            if (process)
                ObDereferenceObject(process);
            commBuffer->Status = status;

        }
        else {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid get module base parameter");
        }
        break;
    case IO_CONTROL_INJECT_DLL:
        // inject dll into a target process
        break;


    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        log_message("unhandled io control code %d", ioControlCode);
        break;

    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0; // bytes transferred
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// handles create irps
NTSTATUS dispatch_create_close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    if (irpStack->MajorFunction == IRP_MJ_CREATE)
        log_message("irp_mj_create received");
    else
        log_message("irp_mj_close received");

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


// gets a process id by name
NTSTATUS GetProcessIdByName(IN PUNICODE_STRING ProcessName, OUT PEPROCESS* Process, OUT HANDLE* ProcessId) {
    PSYSTEM_PROCESS_INFORMATION pCurrent = NULL;
    PSYSTEM_PROCESS_INFORMATION pNext = NULL;
    ULONG ulBufferSize = 0x1000;
    ULONG ulReturnLength = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID pBuffer = NULL;

    // allocate initial buffer
    pBuffer = allocate_memory(ulBufferSize, POOL_TAG_PROC_ID);
    if (!pBuffer) {
        log_message("couldn't allocate memory to get all processes");
        return STATUS_MEMORY_ALLOCATION_FAILED;
    }

    // try and get system process information. if buffer is too small, resize it
    while (TRUE) {
        Status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, ulBufferSize, &ulReturnLength);
        if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            free_memory(pBuffer, POOL_TAG_PROC_ID);
            ulBufferSize = ulReturnLength + 0x1000;
            pBuffer = allocate_memory(ulBufferSize, POOL_TAG_PROC_ID);
            if (!pBuffer) {
                log_message("couldn't allocate memory to get all processes");
                return STATUS_MEMORY_ALLOCATION_FAILED;
            }
            continue;
        }
        else if (!NT_SUCCESS(Status)) {
            log_message("ZwQuerySystemInformation failed with status 0x%08X", Status);
            free_memory(pBuffer, POOL_TAG_PROC_ID);
            return Status;
        }
        else {
            break;
        }
    }

    // loop through the process information structure
    pCurrent = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    do {
        pNext = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

        if (pCurrent->ImageName.Buffer && RtlEqualUnicodeString(ProcessName, &pCurrent->ImageName, TRUE)) {

            CLIENT_ID ClientId = { 0 };
            ClientId.UniqueProcess = (HANDLE)pCurrent->UniqueProcessId;

            Status = PsLookupProcessByProcessId((HANDLE)pCurrent->UniqueProcessId, Process);
            if (NT_SUCCESS(Status)) {
                *ProcessId = (HANDLE)pCurrent->UniqueProcessId;
                log_message("process found: %wZ pid: %d", ProcessName, (int)pCurrent->UniqueProcessId);
            }
            free_memory(pBuffer, POOL_TAG_PROC_ID);
            return STATUS_SUCCESS;
        }


        pCurrent = pNext;
    } while (pCurrent->NextEntryOffset != 0);

    free_memory(pBuffer, POOL_TAG_PROC_ID);
    log_message("process %wZ not found", ProcessName);
    return STATUS_NOT_FOUND;
}


// our driver unload function
void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    log_message("driver unload");

    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLinkName);

    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

// our global syscall hook entry
extern SYSCALL_HOOK_ENTRY g_hook_table[];
extern ULONG g_hook_count;

// our driver entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    // use safe string copy function to improve security against buffer overflows !
    RtlInitUnicodeString(&g_DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&g_SymbolicLinkName, SYMLINK_NAME);




    status = IoCreateDevice(DriverObject, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        log_message("IoCreateDevice failed: 0x%08X", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        log_message("IoCreateSymbolicLink failed: 0x%08X", status);
        IoDeleteDevice(g_DeviceObject); // cleanup on error
        return status;
    }


    // initialize driver features
    status = InitializeDriver(DriverObject);
    if (!NT_SUCCESS(status))
    {

        log_message("Failed to initialize driver features.");

        IoDeleteSymbolicLink(&g_SymbolicLinkName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    log_message("Driver loaded successfully.");

    return STATUS_SUCCESS;
}

NTSTATUS InitializeDriver(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = STATUS_SUCCESS;
    // Set up dispatch routines (IRP Handlers)
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = UnsupportedDispatchRoutine; // default handler for unsupported IRPs
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatchRoutine;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatchRoutine;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatchRoutine;
    DriverObject->DriverUnload = DriverUnload;

    // this is for syscall, not implemented, not that safe
    // example:
    // SYSCALL_HOOK_ENTRY hookEntry;
    // status = install_syscall_hook(&hookEntry, my_hook, ZwQuerySystemInformation); // Replace ZwQuerySystemInformation with your target syscall
    // if (!NT_SUCCESS(status)) {
    //     log_message("install_syscall_hook failed: 0x%08X", status);
    //     // Handle error appropriately (e.g., return status and unload driver)
    //     return status; 
    // }
    // g_HookInstalled = TRUE; // set hook installed flag if needed.

    return status;
}

NTSTATUS UnsupportedDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS CreateCloseDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    // add logic to handle/close requests

    NTSTATUS status = STATUS_SUCCESS;
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS DeviceControlDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;



    PCOMMUNICATION_BUFFER commBuffer = NULL;


    if (inputBufferLength >= sizeof(COMMUNICATION_BUFFER) && outputBufferLength >= sizeof(COMMUNICATION_BUFFER)) {
        commBuffer = (PCOMMUNICATION_BUFFER)Irp->AssociatedIrp.SystemBuffer;
    }
    else {
        status = STATUS_BUFFER_TOO_SMALL;
        log_message("Insufficient buffer size for IOCTL.");
    }



    switch (ioControlCode) {
    case IO_CONTROL_GET_PROCESS_ID:
    {

        if (!commBuffer) break;  // handle buffer size error case

        UNICODE_STRING processName;

        if (commBuffer->ModuleName) {
            // convert module name (char*) to UNICODE_STRING
            ANSI_STRING ansiProcessName;
            RtlInitAnsiString(&ansiProcessName, commBuffer->ModuleName);
            status = RtlAnsiStringToUnicodeString(&processName, &ansiProcessName, TRUE);

            if (!NT_SUCCESS(status)) {
                log_message("RtlAnsiStringToUnicodeString failed: 0x%08X", status);
                commBuffer->Status = status;
                break;
            }
        }
        else {
            // handle error: No process name provided.
            status = STATUS_INVALID_PARAMETER;
            commBuffer->Status = status;
            log_message("No process name provided.");

            break;
        }


        PEPROCESS process = NULL;
        HANDLE processId = NULL;

        status = GetProcessIdByName(&processName, &process, &processId);
        if (NT_SUCCESS(status)) {
            commBuffer->ProcessId = processId;
            log_message("Process ID found: %lu", processId);
        }
        else {
            log_message("GetProcessIdByName failed: 0x%08X", status);
        }

        commBuffer->Status = status;


        if (process) ObDereferenceObject(process);
        RtlFreeUnicodeString(&processName); // free allocated string

        break;

    }
    case IO_CONTROL_READ_MEMORY:
    {
        if (!commBuffer) break;

        if (!commBuffer->ProcessId || !commBuffer->Address || !commBuffer->Buffer || commBuffer->Size == 0) {
            commBuffer->Status = STATUS_INVALID_PARAMETER;
            log_message("Invalid parameters for ReadMemory.");
            break;
        }

        PEPROCESS process;
        status = PsLookupProcessByProcessId(commBuffer->ProcessId, &process);

        if (!NT_SUCCESS(status) || !process)
        {
            log_message("PsLookupProcessByProcessId failed 0x%08X", status);
            commBuffer->Status = STATUS_INVALID_PARAMETER;
            break;
        }


        PVOID readBuffer = allocate_memory(commBuffer->Size, POOL_TAG_READ_M);

        if (!readBuffer)
        {
            commBuffer->Status = STATUS_MEMORY_ALLOCATION_FAILED;
            log_message("Failed to allocate read buffer");
            if (process)
                ObDereferenceObject(process);
            break;
        }


        status = read_memory(process, commBuffer->Address, readBuffer, commBuffer->Size);


        if (NT_SUCCESS(status))
        {
            RtlCopyMemory(commBuffer->Buffer, readBuffer, commBuffer->Size);
        }

        free_memory(readBuffer, POOL_TAG_READ_M);
        if (process)
            ObDereferenceObject(process);


        commBuffer->Status = status;

        break;
    }
    case IO_CONTROL_WRITE_MEMORY:
    {

        if (!commBuffer) break;

        if (!commBuffer->ProcessId || !commBuffer->Address || !commBuffer->Buffer || commBuffer->Size == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            log_message("invalid parameters for IO_CONTROL_WRITE_MEMORY");
            break;
        }

        PEPROCESS process;
        status = PsLookupProcessByProcessId(commBuffer->ProcessId, &process);
        if (!NT_SUCCESS(status) || !process) {
            log_message("PsLookupProcessByProcessId failed 0x%08X", status);
            commBuffer->Status = status;

            break;
        }

        status = inject_memory(process, commBuffer->Address, commBuffer->Buffer, commBuffer->Size);

        if (!NT_SUCCESS(status))
            log_message("inject memory failed, status 0x%08X", status);



        if (process)
            ObDereferenceObject(process);
        commBuffer->Status = status;

        break;

    }

    // implement other methods as needed

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        log_message("Invalid IOCTL: 0x%08X", ioControlCode);
    }


    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0; // bytes returned to usermode
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;

}