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

// general purpose registers, sorted by index
const char *reg32[] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
};

int main()
{
    MEMORY_BASIC_INFORMATION mbi = {};
    unsigned char *addr;

    unsigned char *busy_loop = NULL;
    unsigned char *read_gadget = NULL;
    unsigned char *write_gadget = NULL;
    // displacement in the source, source register, destination register
    // e.g. mov read_dst, dword [read_src+read_disp]
    int read_disp, read_src, read_dst;
    // displacement in the destination, source register, destination register
    // e.g. mov dword [write_dst+write_disp], write_src
    int write_disp, write_src, write_dst;

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
                    if(is_read && read_gadget != 0 || is_read == 0 &&
                            write_gadget != 0) {
                        continue;
                    }

                    // calculate the length of the mov instruction; one byte
                    // for the instruction itself, one byte for the mod R/M
                    // byte and optionally one or four bytes for the
                    // displacement
                    int len = 2 + (mod == 1 ? 1 : 0) + (mod == 2 ? 4 : 0);

                    // next instruction is located after this instruction
                    unsigned char *p2 = p + len;

                    // We don't want a general purpose register for the rm
                    // value. Besides that, I lied, we don't support SIB at
                    // the moment (again, for SIB, see the documentation on
                    // sandpile.org, or perhaps the intel docs.)
                    if(mod != 3 && rm != 4) {

                        // obtain displacement used in the memory address
                        // we have to subtract this displacement later, e.g.
                        // if we have to following read gadget:
                        //   mov eax, dword [ebx+8]
                        // and we want to read from an address 0x11223344,
                        // then ebx should be set to 0x11223344-8
                        if(mod == 1) {
                            if(is_read) read_disp = *(signed char *)(p + 2);
                            else write_disp = *(signed char *)(p + 2);
                        }
                        else if(mod == 4) {
                            if(is_read) read_disp = *(int *)(p + 2);
                            else write_disp = *(int *)(p + 2);
                        }

                        // now we have found the mov instruction, let's see
                        // if it's followed by a return instruction. If it is
                        // then the `value' and the `rm' from the mod R/M byte
                        // cannot be esp.
                        if((*p2 == 0xc3 || *p2 == 0xc2) && value != 4 &&
                                rm != 4) {

                            // we found a read or write gadget, depending on
                            // the `is_read' variable.

                            printf("0x%08x %s %s dword [%s+0x%08x]\n", p,
                                is_read ? "read" : "write",
                                reg32[is_read ? value : rm],
                                reg32[is_read ? rm : value],
                                is_read ? read_disp : write_disp);

                            // store the address of this gadget and mod R/M
                            // information
                            if(is_read) {
                                read_gadget = p;
                                read_dst = value;
                                read_src = rm;
                            }
                            else {
                                write_gadget = p;
                                write_dst = rm;
                                write_src = value;
                            }
                        }

                        // we were unable to find a retn instruction, but
                        // perhaps we can find a jmp instruction (although we
                        // already know this is not going to happen..)
                        else if(*p2 == 0xff && (p2[1] >= 0xd0 &&
                                p2[1] < 0xd8 || p2[1] >= 0xe0 &&
                                p2[1] < 0xe8)) {

                            // we found a read or write gadget, depending on
                            // the `is_read' variable.

                            printf("0x%08x %s %s dword [%s+0x%08x] %s %s\n",
                                p, is_read ? "read" : "write",
                                reg32[is_read ? value : rm],
                                reg32[is_read ? rm : value],
                                is_read ? read_disp : write_disp,
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
    if(read_gadget == NULL || write_gadget == NULL || busy_loop == NULL) {
        printf("Unfortunately, your ntdll is not supported!\n");
        return 0;
    }

}
