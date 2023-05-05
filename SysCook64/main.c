/// <summary>
///     SysCook64 - 
///         PoC for indirect syscall execution
///         via context crafting and thread hijacking
/// 
/// <author>
///     x0reaxeax (https://github.com/x0reaxeax)
/// 
/// <remarks> // oneapi intel compiler warning
///     This project is intended to be compiled with the Intel(R) oneAPI DPC++ Compiler
///     (https://software.intel.com/content/www/us/en/develop/tools/oneapi/components/dpc-compiler.html)
/// 
///     Why? Cuz x64 inline assembly support, bubba ;)
/// 
/// THIS SOFTWARE IS LICENSED UNDER THE MIT LICENSE.
/// THIS CODE WAS WRITTEN PURELY FOR EDUCATIONAL PURPOSES.
/// THE AUTHOR OF THIS SOFTWARE IS NOT RESPONSIBLE FOR ANY MISUSE OF THIS SOFTWARE.

#include <Windows.h>
#include <stdio.h>

struct threadInfo {
    HANDLE hMainThread;
    DWORD dwMainThreadId;
    ULONG_PTR ulpLabelAddress;
};

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    Sleep(2000);                                            // wait for main thread to cool off

    DWORD dwCurrentTid = GetCurrentThreadId();
    printf(
        "[%lu] Child thread running..\n",
        dwCurrentTid
    );

    struct threadInfo *tInfo = (struct threadInfo *) lpParameter;

    HANDLE hMainThread = OpenThread(
        THREAD_ALL_ACCESS,
        FALSE,
        tInfo->dwMainThreadId
    );

    if (NULL == hMainThread) {
        fprintf(
            stderr,
            "[-] OpenThread failed with error code %lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    if (-1 == SuspendThread(hMainThread)) {
        fprintf(
            stderr,
            "[-] SuspendThread failed with error code %lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    CONTEXT origCtx = {
        .ContextFlags = CONTEXT_FULL
    },
        syscallCtx = {
        .ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER
    };

    if (!GetThreadContext(hMainThread, &origCtx)) {
        fprintf(
            stderr,
            "[-] GetThreadContext failed with error code %lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    PBYTE pNtAllocateVirtualMemory = (PBYTE) GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtAllocateVirtualMemory"
    );

    if (NULL == pNtAllocateVirtualMemory) {
        fprintf(
            stderr,
            "[-] GetProcAddress failed with error code %lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    WORD wSyscall = 0x050f;

    if (wSyscall != *(PWORD) (pNtAllocateVirtualMemory + 18)) {
        fprintf(                                            // we're landing directly
            stderr,                                         // on the `syscall` instruction,
            "[-] no syscall? :(\n"                          // so bypass go brrrr
        );
        return EXIT_FAILURE;
    }

    HANDLE hProcess = (HANDLE) -1;                          // current process
    ULONG_PTR ulpBaseAddress = 0;                           // choose for me bby
    SIZE_T cbRegionSize = 0x1000;
    ULONG ulAllocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG ulProtect = PAGE_EXECUTE_READWRITE;

    syscallCtx.Rsp = origCtx.Rsp;                           // we're gonna patch tf out of this

    // craft stack
    *(PULONG_PTR) (syscallCtx.Rsp + 0x28) = ulProtect;
    *(PULONG_PTR) (syscallCtx.Rsp + 0x20) = ulAllocationType;

    // craft GPRs
    syscallCtx.Rax = 0x18;
    syscallCtx.Rcx = (DWORD64) hProcess;
    syscallCtx.R10 = (DWORD64) hProcess;
    syscallCtx.Rdx = (DWORD64) &ulpBaseAddress;
    syscallCtx.R8 = (DWORD64) 0;
    syscallCtx.R9 = (DWORD64) &cbRegionSize;
    syscallCtx.Rsp = (DWORD64) origCtx.Rsp - 0x8;

    *(PULONG_PTR) syscallCtx.Rsp = tInfo->ulpLabelAddress;   // return address

    syscallCtx.Rip = (DWORD64) pNtAllocateVirtualMemory;     // syscall

    if (!SetThreadContext(hMainThread, &syscallCtx)) {
        fprintf(
            stderr,
            "[-] SetThreadContext failed with error code %lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    printf("[%lu] Resuming main thread..\n", dwCurrentTid);

    if (-1 == ResumeThread(hMainThread)) {
        fprintf(
            stderr,
            "[-] ResumeThread failed with error code %lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    Sleep(1000);                                            // wait a bit, we're patient lads.. sometimes
    printf(
        "[%lu] Successfully allocated 0x1000 bytes at 0x%02llx..\n",
        dwCurrentTid,
        ulpBaseAddress
    );

    printf("[%lu] Child thread exiting..\n", dwCurrentTid);

    return EXIT_SUCCESS;
}

int main(void) {
    PBYTE pMain = (PBYTE) main;
    while (1) {                                             // find our fugazi label
        BYTE bPattern[] = { 0xde, 0xad, 0xbe, 0xef, 0x90, 0x90 };
        if (0 == memcmp(pMain, bPattern, sizeof(bPattern))) {
            break;
        }
        pMain++;
    }

    pMain += 6;                                             // skip over the pattern

    struct threadInfo tInfo = {
        .hMainThread = GetCurrentThread(),
        .dwMainThreadId = GetCurrentThreadId(),
        .ulpLabelAddress = (ULONG_PTR) pMain
    };

    printf("[%lu] Main thread running..\n", tInfo.dwMainThreadId);

    DWORD dwThreadId = 0;
    printf("[%lu] Spawning new thread..\n", tInfo.dwMainThreadId);
    HANDLE hThread = CreateThread(
        NULL,
        0,
        ThreadProc,
        &tInfo,
        0,
        &dwThreadId
    );

    if (NULL == hThread) {
        fprintf(
            stderr,
            "[-] CreateThread failed with error code %lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    /// basically `jmp $`. intel inline asm doesn't support this,
    /// so we'll have to use a label.
    /// other thing is, if you're wondering why not just do `while(1)`
    /// the answer is that the compiler will optimize it out
    /// everything after the loop, because it considers it unreachable code
    __asm __volatile {
        loop:
        jmp loop
    }

    /// this is a placeholder pattern which we'll use as a replacement
    /// for GNU's &&label (getting the address of a label).
    /// it's purely for the sake of convenience.
    /// when returning from the NTAPI call, we'll be landing
    /// immediately after the pattern bytes.
    __asm __volatile {
        .byte 0xde, 0xad, 0xbe, 0xef, 0x90, 0x90            // garbage `fisubr WORD PTR [rbp-0x6f6f1042]`
    }

    printf(
        "[%lu] Hello from main().. again!\n",
        tInfo.dwMainThreadId
    );

    while (1);                                              // go check VMMap :0 ;)

    return EXIT_SUCCESS;
}