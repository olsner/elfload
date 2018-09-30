#include "elfload.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef uint64_t u64;
typedef uint8_t u8;
#define PAGE_SIZE 4096
#define NORETURN __attribute__((noreturn))
#define STACK_SIZE (4 * 1024 * 1024)

#define CASE(e) case e: return #e
static const char *get_ptype_name(int ptype) {
    switch (ptype) {
        CASE(PT_NULL);
        CASE(PT_LOAD);
        CASE(PT_DYNAMIC);
        CASE(PT_INTERP);
        CASE(PT_NOTE);
        CASE(PT_SHLIB);
        CASE(PT_PHDR);
        CASE(PT_TLS);
        CASE(PT_NUM);
        CASE(PT_GNU_EH_FRAME);
        CASE(PT_GNU_STACK);
        CASE(PT_GNU_RELRO);
        CASE(PT_SUNWBSS);
        CASE(PT_SUNWSTACK);
    default: return NULL;
    }
}

static NORETURN void unimpl(const char *what) {
    printf("UNIMPL: %s\n", what);
    abort();
}
static void debug_check(const char *file, int line, const char *why, int err) {
    printf("%s:%d: returning error %d (%s): %s\n", file, line, err, strerror(err), why);
}
static NORETURN void exit_errno(const char *file, int line, const char *why, int err) {
    printf("%s:%d: returning error %d (%s): %s\n", file, line, err, strerror(err), why);
    _exit(1);
}

#if 1
#define CHECK_SIZE(n) do { if (n > size) RETURN_ERRNO(EINVAL, "Value out of range"); } while (0)
#else
#define CHECK_SIZE(n) (void)0
#endif
#define RETURN_ERRNO(err, why) do { debug_check(__FILE__, __LINE__, why, err); errno = err; return -1; } while (0)
#define EXIT_ERRNO(err, why) exit_errno(__FILE__, __LINE__, why, err)
#define GETHEADER(name, type, offset) CHECK_SIZE(offset + sizeof(Elf64_##type)); const Elf64_##type *name = (const Elf64_##type *)&bytes[offset]
#define SELF_SIZE 4096
#define USER_VADDR_END ((1ull << 47) - 1)
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

static bool no_overlap(uintptr_t start1, uintptr_t end1, const void* p2, uintptr_t size2) {
    const uintptr_t start2 = (uintptr_t)p2;
    const uintptr_t end2 = start2 + size2;
    return end2 < start1 || start2 > end1;
}

static int relocate_to(uintptr_t target) {
    printf("Relocate to %tx\n", target);
    unimpl("relocate_to");
}

static int check_relocate(Elf64_Addr start, Elf64_Addr end, const void *bytes, uintptr_t size) {
    // Perhaps split up into another function for the "rest" that is explicitly relocatable.
    if (no_overlap(start, end, &el_memexecve, SELF_SIZE) && no_overlap(start, end, bytes, size)) {
        // TODO Do relocation anyway so that we force it to be tested
        printf("Sweet! no relocation necessary!\n");
        return 0;
    } else if (start > 0x100000 + SELF_SIZE) {
        // TODO Relocate the program too? It could probably be done on the fly while loading though.
        return relocate_to(start - SELF_SIZE);
    } else if (end < USER_VADDR_END - SELF_SIZE) {
        return relocate_to(end);
    } else {
        return 1;
    }
}

static int invalid_elf_file(const uint8_t* const bytes, const size_t size) {
    if (memcmp(bytes, ELFMAG, SELFMAG)) {
        RETURN_ERRNO(EINVAL, "Invalid ELF magic");
    }

    const uint8_t eclass = bytes[EI_CLASS];
    // TODO compare to "our" native elfclass instead. This makes us 64-bit specific.
    if (eclass != ELFCLASS64) {
        RETURN_ERRNO(EINVAL, "ELF class not 64-bit");
    }
    // Also, compare to "native" instead of assuming little-endian.
    if (bytes[EI_DATA] != ELFDATA2LSB) {
        RETURN_ERRNO(EINVAL, "ELF not little-endian");
    }
    if (bytes[EI_VERSION] != EV_CURRENT) {
        RETURN_ERRNO(EINVAL, "ELF version not current");
    }
    if (bytes[EI_OSABI] != ELFOSABI_NONE
        && bytes[EI_OSABI] != ELFOSABI_LINUX) {
        RETURN_ERRNO(EINVAL, "Not a SysV or Linux ELF");
    }

    // Preliminary checks OK, now we know it's an Elf64_Ehdr we want to read
    // from it, and can do more checks on fields in a struct.
    CHECK_SIZE(sizeof(Elf64_Ehdr));
    GETHEADER(ehdr, Ehdr, 0);

    // Are dynamically linked executables still ET_EXEC and not ET_DYN?
    if (ehdr->e_type != ET_EXEC) {
        RETURN_ERRNO(EINVAL, "ELF type not executable");
    }
    if (ehdr->e_machine != EM_X86_64) {
        RETURN_ERRNO(EINVAL, "ELF machine not x86-64 (integrate qemu?)");
    }

    return 0;
}

static int prot_from_flags(int pflags) {
    int prot = 0;
    if (pflags & PF_X) prot |= PROT_EXEC;
    if (pflags & PF_W) prot |= PROT_WRITE;
    if (pflags & PF_R) prot |= PROT_READ;
    return prot;
}

static u64 round_up(u64 x, u64 align) {
    return (x + align - 1) & -align;
}

static NORETURN void switch_to(void* stack, uintptr_t rip) {
    asm volatile("mov %0, %%rsp; jmp *%1":: "r"(stack), "r"(rip));
    // Shoul be unreachable!
    abort();
}

int el_memexecve(const void *const buf, const size_t size, char *const*const argv, char *const*const envp) {
    const uint8_t* const bytes = (const uint8_t *)buf;
    CHECK_SIZE(EI_NIDENT);

    if (invalid_elf_file(bytes, size)) {
        return -1;
    }

    GETHEADER(ehdr, Ehdr, 0);
    Elf64_Addr start = UINT64_MAX, end = 0;
    int found_interpreter = 0;
    int stack_prot = PROT_READ | PROT_WRITE;
    for (int ph = 0; ph < ehdr->e_phnum; ph++) {
        const Elf64_Off phoff = ehdr->e_phoff + ehdr->e_phentsize * ph;
        GETHEADER(phdr, Phdr, phoff);

        printf("Program header %d: type=%x (%s)\n", ph, phdr->p_type, get_ptype_name(phdr->p_type));
        switch (phdr->p_type) {
        case PT_PHDR:
            printf("PT_PHDR: ignored\n");
            break;
        case PT_INTERP:
            found_interpreter = 1;
            break;
            // TODO Perhaps we should treat static executables as interpreted
            // too, but provide our own interpreter for those. Then we should
            // have a clean way to handle both cases?
        case PT_LOAD:
            start = MIN(phdr->p_vaddr, start);
            end = MAX(phdr->p_vaddr + phdr->p_memsz, end);
            break;
        case PT_GNU_STACK:
            // How about a read-only or inaccessible stack? Seems ridiculous though :)
            if (phdr->p_flags & PF_X) stack_prot |= PROT_EXEC;
            break;
        }
    }
    if (found_interpreter) {
        RETURN_ERRNO(EINVAL, "Interpreted ELF files not supported yet");
    }
    if (end <= start) {
        RETURN_ERRNO(EINVAL, "Nothing to load");
    }
    printf("Load addresses at %lx..%lx, self at %p, data at %p..%p\n",
            start, end, &el_memexecve, bytes, bytes + size);
    // TODO Check if we need to relocate the stack too
    if (check_relocate(start, end, bytes, size)) {
        RETURN_ERRNO(ENOMEM, "No space to relocate the ELF loader");
    }

    // Point of no return: If we fail from now on we can only just _exit(1).
    // After this we have actually unmapped part of the previous process.
    if (munmap((void*)start, end - start)) {
        EXIT_ERRNO(errno, "munmap failed");
    }

    // Would like to just mremap the stuff from where it's already mapped in memory anyway.
    // But this needs to handle overlap in the ends of segments - e.g.
    // code from 0x1000 to 0x17ff and data from 0x1800 on, which means that the
    // data has to be copied (or the mapping duplicated) to its vaddr.
    // Doesn't look like mremap readily supports this, but we can iterate first
    // to find the overlapping pages and duplicate those while mremapping
    // everything else.
    for (int ph = 0; ph < ehdr->e_phnum; ph++) {
        const Elf64_Off phoff = ehdr->e_phoff + ehdr->e_phentsize * ph;
        GETHEADER(phdr, Phdr, phoff);

        if (phdr->p_type == PT_LOAD) {
            u64 vaddr_offset = phdr->p_vaddr & (PAGE_SIZE - 1);
            u64 vaddr_page = phdr->p_vaddr - vaddr_offset;
            u64 vaddr_size = round_up(phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE) - vaddr_page;

            printf("Mapping %08lx..%08lx to %08lx..%08lx (%08lx..%08lx)\n",
                    phdr->p_offset, phdr->p_offset + phdr->p_filesz,
                    phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz,
                    vaddr_page, vaddr_page + vaddr_size);

            u8 *dest = (u8*)mmap((void*)vaddr_page, vaddr_size, PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
            if (dest == MAP_FAILED) {
                EXIT_ERRNO(errno, "mmap failed");
            }

            memcpy(dest + vaddr_offset, bytes + phdr->p_offset, phdr->p_filesz);
            // TODO If using remap and this is a data segment, might need to clear
            // out some data from a neighbor segment if the data segment didn't
            // fill out a page.

            mprotect(dest, phdr->p_memsz, prot_from_flags(phdr->p_flags));
        }
    }

    void *stack_start = mmap(0, STACK_SIZE, stack_prot, MAP_GROWSDOWN | MAP_STACK | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (stack_start == MAP_FAILED) {
        EXIT_ERRNO(errno, "mmap stack failed");
    }
    void *stack_end = (char*)stack_start + STACK_SIZE;

    // Unmap everything we don't want anymore, e.g. everything except:
    // - new program's stack
    // - the loaded program itself
    // - the elf interpreter (if loaded)
    // - arguments and environment (stored on stack?)
    // - the minimum necessary to jump into the new program
    //   though if the loader is less than one page, we could just keep the whole thing

    // Close CLOEXEC files
    // Check what else kind of magic exec does to tear down the old process.
    //
    // Is it possible to modify the /proc/self/exe link?

    printf("Jumping to entry point %lx\n", ehdr->e_entry);
    // Any other registers of interest?
    switch_to(stack_end, ehdr->e_entry);
}

/**
 * Like with fexecve, the FD_CLOEXEC flag should usually be set on the executable.
 */
int el_fexecve(int fd, char *const argv[], char *const envp[]) {
    struct stat st;
    if (fstat(fd, &st)) {
        return -1;
    }

    // Mapped PROT_READ initially. memexecve will remap the pages with appropriate protections.
    void* mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        return -1;
    }

    if (el_memexecve(mem, st.st_size, argv, envp)) {
        munmap(mem, st.st_size);
        return -1;
    }

    // memexecve may never return successfully
    abort();
}
int el_execatve(int cwd, const char *path, char *const argv[], char *const envp[]) {
    int fd = openat(cwd, path, O_CLOEXEC | O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (el_fexecve(fd, argv, envp)) {
        close(fd);
        return -1;
    }

    // el_fexecve may never return successfully
    abort();
}
int el_execve(const char *path, char *const argv[], char *const envp[]) {
    return el_execatve(AT_FDCWD, path, argv, envp);
}
