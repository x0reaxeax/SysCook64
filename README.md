# SysCook64 - Cooking thread contexts for fun and profit

## What is this?
This is a PoC technique for indirect syscall execution, by suspending, altering and resuming a thread.  
The target thread's context is modified in order to land on a `syscall` instruction in `NTDLL` (we're doing `NtAllocateVirtualMemory`), with registers and stack prepared for syscall execution.  
There's no need for syscall stubs, since all the arguments are written directly to the target's thread context, while it's suspended.  

## Demo
[YouTube](https://youtu.be/HU47BmJJw98)
