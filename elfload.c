#include "elfload.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

typedef uint64_t u64;
typedef uint8_t u8;
typedef struct auxv_t {
    u64 a_type;
    union {
        u64 a_val;
        void *a_ptr;
        const char *a_str;
    };
} auxv_t;
extern char **environ;
#define PAGE_SIZE 4096
#define NORETURN __attribute__((noreturn))
#define DEFAULT_STACK_SIZE (4 * 1024 * 1024)

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
    default: return "unknown";
    }
}
static const char *get_atype_name(int atype) {
    switch (atype) {
CASE(AT_NULL);
CASE(AT_IGNORE);
CASE(AT_EXECFD);
CASE(AT_PHDR);
CASE(AT_PHENT);
CASE(AT_PHNUM);
CASE(AT_PAGESZ);
CASE(AT_BASE);
CASE(AT_FLAGS);
CASE(AT_ENTRY);
CASE(AT_NOTELF);
CASE(AT_UID);
CASE(AT_EUID);
CASE(AT_GID);
CASE(AT_EGID);
CASE(AT_CLKTCK);
CASE(AT_PLATFORM);
CASE(AT_HWCAP);
CASE(AT_FPUCW);
CASE(AT_DCACHEBSIZE);
CASE(AT_ICACHEBSIZE);
CASE(AT_UCACHEBSIZE);
CASE(AT_IGNOREPPC);
CASE(AT_SECURE);
CASE(AT_BASE_PLATFORM);
CASE(AT_RANDOM);
CASE(AT_HWCAP2);
CASE(AT_EXECFN);
CASE(AT_SYSINFO);
CASE(AT_SYSINFO_EHDR);
CASE(AT_L1I_CACHESHAPE);
CASE(AT_L1D_CACHESHAPE);
CASE(AT_L2_CACHESHAPE);
CASE(AT_L3_CACHESHAPE);
    default: return "unknown";
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
    asm volatile("mov %0, %%rsp; jmp *%1":: "r"(stack), "r"(rip), "d"(0));
    // Should be unreachable!
    abort();
}

// Stack on entry:
// [from %rsp and increasing addresses!]
// argc
// argv[argc]
// nullptr
// env[]
// nullptr
// aux[] (2 qwords each)
// AT_NULL
//
// Remaining space may be used to copy the environment, arguments and aux
// vector information.
static void* build_stack(void* stack_start, u64* stack_end, char *const*const argv, char *const*const envp, auxv_t* auxv) {
    size_t args_size = 0;
    size_t argc = 0, envc = 0, auxc = 0;

    char *const *p;
    for (p = argv; *p; p++) {
        args_size += strlen(*p) + 1;
        argc++;
    }
    for (p = envp; *p; p++) {
        args_size += strlen(*p) + 1;
        envc++;
    }
    // For now, assume that the aux vector is always built by copying the one
    // for the current process. In reality, it's filled in by the kernel.
    for (auxv_t* auxp = auxv; auxp->a_type != AT_NULL; auxp++) {
        printf("input auxv %ld (%s): %p\n", auxp->a_type, get_atype_name(auxp->a_type), auxp->a_ptr);
        auxc++;
        switch (auxp->a_type) {
        case AT_RANDOM:
            args_size += 16;
            break;
        case AT_PLATFORM:
            args_size += strlen(auxp->a_str) + 1;
            break;
        }
    }

    // TODO Check args_size against limit (accounting for all the pointers and
    // a minimum process stack size).
    stack_end -= (args_size + 7) / 8;
    char *data_start = (char *)stack_end;

    *--stack_end = AT_NULL;
    for (int i = auxc; i--;) {
        auxv_t a = auxv[i];
        switch (a.a_type) {
        case AT_RANDOM:
            syscall(__NR_getrandom, data_start, 16, 0);
            data_start += 16;
            break;
        case AT_EXECFN:
        case AT_PLATFORM:
            // skip for now, since we haven't copied the data
            continue;
        // May be incorrect for the process we're starting. Should move this
        // filtering somewhere else so we also have a place where we'd fill
        // these in for the benefit of the dynamic linker.
        case AT_PHDR:
        case AT_PHENT:
        case AT_PHNUM:
        case AT_BASE:
        case AT_ENTRY:
            continue;
        }
        printf("forwarding auxv %ld (%s): %p\n", a.a_type, get_atype_name(a.a_type), a.a_ptr);
        *--stack_end = a.a_val;
        *--stack_end = a.a_type;
    }

    // envp
    *--stack_end = 0;
    for (int i = envc; i--;) {
        *--stack_end = (u64)data_start;
        const size_t n = strlen(envp[i]) + 1;
        memcpy(data_start, envp[i], n);
        data_start += n;
    }

    // argv
    *--stack_end = 0;
    for (int i = argc; i--;) {

        *--stack_end = (u64)data_start;
        const size_t n = strlen(argv[i]) + 1;
        memcpy(data_start, argv[i], n);
        data_start += n;
    }
    *--stack_end = argc;

    return stack_end;
}

static auxv_t* find_auxv(char** envp) {
    while (*envp++) /* find end of envp list */;
    return (auxv_t*)envp;
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
    int stack_size = DEFAULT_STACK_SIZE;
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
            // TODO The size of the stack can be indicated using the p_memsz of
            // this program header. Update stack_size if that size looks good.
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

    void *stack_start = mmap(0, stack_size, stack_prot, MAP_GROWSDOWN | MAP_STACK | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (stack_start == MAP_FAILED) {
        EXIT_ERRNO(errno, "mmap stack failed");
    }
    void *stack_end = (char*)stack_start + stack_size;

    stack_end = build_stack(stack_start, (u64*)stack_end, argv, envp, find_auxv(environ));
    if (!stack_end) {
        munmap(stack_start, stack_size);
        EXIT_ERRNO(E2BIG, "Command line/environment too big");
    }
    printf("Generated %zu bytes of argument/environment data\n", stack_start + stack_size - stack_end);

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
