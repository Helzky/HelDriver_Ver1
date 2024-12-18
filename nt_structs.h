#pragma once

// SYSTEM_INFORMATION_CLASS definition
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemDriverInformation,
    SystemModuleInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPagefileInformation,
    SystemVdmInstEmuInformation,
    SystemVmCountersInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleTracingInformation,
    SystemWorkingSetInformation,
    SystemSessionInformation,
    SystemLookasideInformation,
    SystemDiskInformation,
    SystemLastHardErrorInformation,
    SystemFileCacheInformation,
    SystemAddInInformation,
    SystemCrashDumpInformation,
    SystemPagingFileInfo,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemSystemCacheInformation,
    SystemPoolTagInformation,
    SystemProcessorGroupInformation,
    SystemSystemPowerInformation,
    SystemProcessorIdleInformation,
    SystemEnclaveInformation,
    SystemRegistryQuotaInformation,
    SystemCpuQuotaInformation,
    SystemHypervisorInformation,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemProcessMemoryInformation,
    SystemTokenFilterInformation,
    SystemVerifierInformation,
    SystemExtendedSystemInformation,
    SystemVirtualAddressInformation,
    SystemBigPoolInformation,
    SystemModuleIntegrityInformation,
    SystemFeatureInformation,
    SystemPrivilegedInstructionInformation,
    SystemInterruptInformation,
    SystemCpuPolicyInformation,
    SystemLastType
} SYSTEM_INFORMATION_CLASS;


// SYSTEM_PROCESS_INFORMATION structure definition.  Note:  This is a simplified structure. A more complete structure may be needed depending on your requirements.
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PrivatePageCount;
    IO_COUNTERS IoCounters;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;