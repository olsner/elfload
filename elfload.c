#include "elfload.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#define enable_debug 0

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
// Note with 5-level page tables, this goes up to 1<<56 (minus one page). How
// do we check for that feature from user space?
static const uintptr_t USER_VADDR_END = (1ull << 47) - PAGE_SIZE;

#if enable_debug
#define debug_printf(fmt, ...) printf(fmt, ## __VA_ARGS__)
#else
#define debug_printf(fmt, ...) (void)sizeof(printf(fmt, ## __VA_ARGS__))
#endif
#define debug(fmt, ...) debug_printf("%s:%d: " fmt, __FILE__, __LINE__, ## __VA_ARGS__)

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

static inline int64_t syscall2(uint64_t nr, uint64_t arg1, uint64_t arg2) {
    int64_t res;
    __asm__ __volatile__ ("syscall"
            : /* return value */
            "=a" (res),
            /* clobbered inputs */
            "=D" (arg1), "=S" (arg2)
            : "a" (nr), "D" (arg1), "S" (arg2)
            /* clobbers all caller-save registers */
            : "%rdx", "r8", "r9", "r10", "r11", "%rcx", "memory");
    return res;
}
static NORETURN void raw_exit(int status) {
    for (;;) syscall2(__NR_exit, status, 0);
}
static int raw_munmap(void *start, size_t length) {
    return syscall2(__NR_munmap, (u64)start, (u64)length);
}

static NORETURN void unimpl(const char *what) {
    printf("UNIMPL: %s\n", what);
    abort();
}
static void debug_check(const char *file, int line, const char *why, int err) {
    debug_printf("%s:%d: returning error %d (%s): %s\n", file, line, err, strerror(err), why);
}
static NORETURN void exit_errno(const char *file, int line, const char *why, int err) {
    debug_printf("%s:%d: returning error %d (%s): %s\n", file, line, err, strerror(err), why);
    _exit(1);
}
static NORETURN void assert_failed(const char *file, int line, const char *what) {
    debug_printf("%s:%d: assertion failed: %s\n", file, line, what);
    _exit(1);
}

#define assert(x) do { if (!(x)) assert_failed(__FILE__, __LINE__, #x); } while (0)
#if 1
#define CHECK_SIZE(n) do { if (n > size) RETURN_ERRNO(EINVAL, "Value out of range"); } while (0)
#else
#define CHECK_SIZE(n) (void)0
#endif
#define RETURN_ERRNO(err, why) do { debug_check(__FILE__, __LINE__, why, err); errno = err; return -1; } while (0)
#define EXIT_ERRNO(err, why) exit_errno(__FILE__, __LINE__, why, err)
#define GETHEADER(name, type, offset) CHECK_SIZE(offset + sizeof(Elf64_##type)); const Elf64_##type *name = (const Elf64_##type *)&bytes[offset]
#define SELF_SIZE 4096
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

static bool no_overlap(uintptr_t start1, uintptr_t end1, const void* p2, uintptr_t size2) {
    const uintptr_t start2 = (uintptr_t)p2;
    const uintptr_t end2 = start2 + size2;
    return end2 < start1 || start2 > end1;
}

static int relocate_to(uintptr_t target) {
    debug("Relocate to %tx\n", target);
    unimpl("relocate_to");
}

static int check_relocate(Elf64_Addr loadstart, Elf64_Addr loadend, const void *bytes, uintptr_t size) {
    // Perhaps split up into another function for the "rest" that is explicitly relocatable.
    if (no_overlap(loadstart, loadend, &el_fexecve, SELF_SIZE)
        && no_overlap(loadstart, loadend, bytes, size)) {
        // TODO Do relocation anyway so that we force it to be tested
        debug("Sweet! no relocation necessary!\n");
        return 0;
    } else if (loadstart > 0x100000 + SELF_SIZE) {
        // TODO Relocate the program too? It could probably be done on the fly while loading though.
        return relocate_to(loadstart - SELF_SIZE);
    } else if (loadend < USER_VADDR_END - SELF_SIZE) {
        return relocate_to(loadend);
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

    // Static: ET_EXEC
    // Dynamic: ET_EXEC with PT_INTERP pointing to (e.g.) ld-linux.so
    // Dynamic PIE: ET_DYN with PT_INTERP
    // Static PIE: ET_DYN without PT_INTERP
    // Interpreter: ET_DYN without PT_INTERP (no recursive interpretation??)
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

static u64 round_down(u64 x, u64 align) {
    return x & -align;
}

static u64 round_up(u64 x, u64 align) {
    return (x + align - 1) & -align;
}

static NORETURN void switch_to(void* stack, uintptr_t rip) {
    asm volatile("mov %0, %%rsp; jmp *%1":: "r"(stack), "r"(rip), "d"(0));
    // Should be unreachable!
    abort();
}

static size_t copy_str(void* dst, const char* src) {
    const size_t n = strlen(src) + 1;
    memcpy(dst, src, n);
    return n;
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
static void* build_stack(void* stack_start, u64* stack_end, char *const*const argv, char *const*const envp, const auxv_t* auxv) {
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
    for (const auxv_t* auxp = auxv; auxp->a_type != AT_NULL; auxp++) {
        debug("input auxv %ld (%s): %p\n", auxp->a_type, get_atype_name(auxp->a_type), auxp->a_ptr);
        switch (auxp->a_type) {
        case AT_RANDOM:
            args_size += 16;
            break;
        case AT_PLATFORM:
            args_size += strlen(auxp->a_str) + 1;
            break;
        // Skipped below, so skip over here to get the correct auxc
        case AT_EXECFN:
        case AT_PHDR:
        case AT_PHENT:
        case AT_PHNUM:
        case AT_BASE:
        case AT_ENTRY:
            continue;
        }
        auxc++;
    }

    // TODO Check args_size against limit (accounting for all the pointers and
    // a minimum process stack size).
    stack_end -= (args_size + 7) / 8;

    const size_t stack_words = (1 + 2 * auxc) + (1 + envc) + (1 + argc) + 1;
    // If we have an odd number of words left to push and the stack is
    // currently 16 byte aligned, misalign the stack by 8 bytes.
    // And vice versa.
    if (!(stack_words & 1) != !((uintptr_t)stack_end & 8)) {
        stack_end--;
    }
    // TODO Since we've calculated the number of words we need now, we could
    // fill in the data forwards instead of backwards.
    char *data_start = (char *)stack_end;

    *--stack_end = AT_NULL;
    for (const auxv_t* auxp = auxv; auxp->a_type != AT_NULL; auxp++) {
        auxv_t a = *auxp;
        switch (auxp->a_type) {
        case AT_RANDOM:
            a.a_ptr = data_start;
            syscall(__NR_getrandom, data_start, 16, 0);
            data_start += 16;
            break;
        case AT_PLATFORM:
            a.a_ptr = data_start;
            data_start += copy_str(data_start, auxp->a_str);
            break;
        case AT_EXECFN:
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
        debug("forwarding auxv %ld (%s): %p\n", a.a_type, get_atype_name(a.a_type), a.a_ptr);
        *--stack_end = a.a_val;
        *--stack_end = a.a_type;
    }

    // envp
    *--stack_end = 0;
    for (int i = envc; i--;) {
        *--stack_end = (u64)data_start;
        data_start += copy_str(data_start, envp[i]);
    }

    // argv
    *--stack_end = 0;
    for (int i = argc; i--;) {
        *--stack_end = (u64)data_start;
        data_start += copy_str(data_start, argv[i]);
    }
    *--stack_end = argc;

    // Stack must be 16 byte aligned on entry
    assert(!((uintptr_t)stack_end & 15));

    return stack_end;
}

static auxv_t* find_auxv(char** envp) {
    while (*envp++) /* find end of envp list */;
    return (auxv_t*)envp;
}

static size_t fsize(int fd) {
    struct stat st;
    if (fstat(fd, &st)) {
        return -1;
    }
    return st.st_size;
}

// NB: there are more magic mappings we might want to avoid. Annoying stuff.
static void get_vdso_range(uintptr_t *start, uintptr_t *end) {
    *start = getauxval(AT_SYSINFO_EHDR);
    //const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)*start;
    // Lazy :)
    *end = *start + PAGE_SIZE;
}

static uintptr_t get_rip(void) {
    return (uintptr_t)__builtin_return_address(0);
}

static void munmap_range(uintptr_t start, uintptr_t end) {
    //debug("Unmapping %16lx..%16lx\n", start, end);
    int e;
    if ((e = raw_munmap((void*)start, end - start))) {
        raw_exit(e);
    }
}

/**
 * Like with fexecve, the FD_CLOEXEC flag should usually be set on the executable.
 */
int el_fexecve(const int fd, char *const argv[], char *const envp[]) {
    const size_t size = fsize(fd);

    // Mapped PROT_READ initially. we'll remap the pages with appropriate
    // protections in the load part, this is just for reading the headers.
    // Could avoid mapping the whole file if we wanted to.
    const uint8_t* const bytes = (const uint8_t *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (bytes == MAP_FAILED) {
        return -1;
    }

    CHECK_SIZE(EI_NIDENT);

    if (invalid_elf_file(bytes, size)) {
        return -1;
    }

    GETHEADER(ehdr, Ehdr, 0);
    Elf64_Addr loadstart = UINT64_MAX, loadend = 0;
    int found_interpreter = 0;
    int stack_prot = PROT_READ | PROT_WRITE;
    int stack_size = DEFAULT_STACK_SIZE;
    for (int ph = 0; ph < ehdr->e_phnum; ph++) {
        const Elf64_Off phoff = ehdr->e_phoff + ehdr->e_phentsize * ph;
        GETHEADER(phdr, Phdr, phoff);

        debug("Program header %d: type=%x (%s)\n", ph, phdr->p_type, get_ptype_name(phdr->p_type));
        switch (phdr->p_type) {
        case PT_INTERP:
            found_interpreter = 1;
            break;
            // TODO Perhaps we should treat static executables as interpreted
            // too, but provide our own interpreter for those. Then we should
            // have a clean way to handle both cases?
        case PT_LOAD:
            loadstart = MIN(phdr->p_vaddr, loadstart);
            loadend = MAX(phdr->p_vaddr + phdr->p_memsz, loadend);
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
    if (loadend <= loadstart) {
        RETURN_ERRNO(EINVAL, "Nothing to load");
    }
    debug("Load addresses at %lx..%lx, self at %p, data at %p..%p\n",
            loadstart, loadend, &el_fexecve, bytes, bytes + size);

    if (check_relocate(loadstart, loadend, bytes, size)) {
        RETURN_ERRNO(ENOMEM, "No space to relocate the ELF loader");
    }

    uintptr_t vdso_start, vdso_end;
    get_vdso_range(&vdso_start, &vdso_end);

    // FIXME Make sure this doesn't overlap where we're about to put anything
    // either. Should probably go before relocate so we know we don't need
    // anything at all from the old address space (except the loader code
    // itself). We can move the stack if it does though, it's a single big block.
    void *const stack_start = mmap(0, stack_size, stack_prot, MAP_GROWSDOWN | MAP_STACK | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (stack_start == MAP_FAILED) {
        EXIT_ERRNO(errno, "stack mmap failed");
    }
    void *const stack_end = (char*)stack_start + stack_size;

    void *const stack_ptr = build_stack(stack_start, (u64*)stack_end, argv, envp, find_auxv(environ));
    if (!stack_ptr) {
        // TODO THis should happen before the point of no return.
        EXIT_ERRNO(E2BIG, "Command line/environment too big");
    }
    debug("Generated %zu bytes of argument/environment data\n", stack_start + stack_size - stack_ptr);

    // Point of no return: If we fail from now on we can only just _exit(1).
    // After this we may have actually unmapped part of the previous process.
    munmap_range(loadstart, loadend);

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
            const u64 vaddr_offset = phdr->p_vaddr & (PAGE_SIZE - 1);
            const u64 vaddr_page = phdr->p_vaddr - vaddr_offset;
            const u64 vaddr_size = round_up(phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE) - vaddr_page;

            const u64 file_offset = phdr->p_offset & (PAGE_SIZE - 1);
            const u64 file_page = phdr->p_offset - file_offset;
            const u64 file_size = round_up(phdr->p_offset + phdr->p_filesz, PAGE_SIZE) - file_page;

            if (file_offset != vaddr_offset) {
                EXIT_ERRNO(errno, "Impossible file/vaddr offset mismatch");
            }

            debug("Mapping %08lx..%08lx to %08lx..%08lx (%08lx..%08lx)\n",
                    phdr->p_offset, phdr->p_offset + phdr->p_filesz,
                    phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz,
                    vaddr_page, vaddr_page + vaddr_size);

            const int prot = prot_from_flags(phdr->p_flags);
            if (mmap((void*)vaddr_page, file_size, prot,
                    MAP_PRIVATE | MAP_FIXED, fd, file_page) == MAP_FAILED) {
                EXIT_ERRNO(errno, "mmap failed");
            }

            // TODO Add tests:
            // - check that extra BSS pages are accessible and zeroed
            // - check that the BSS part of the tail of the .data section is properly zeroed
            if (vaddr_size > file_size) {
                debug("Mapping BSS %08lx..%08lx\n", vaddr_page + file_size, vaddr_page + vaddr_size);
                if (mmap((void*)(vaddr_page + file_size), vaddr_size - file_size, prot,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0) == MAP_FAILED) {
                    EXIT_ERRNO(errno, "mmap failed");
                }
            }
            if (phdr->p_memsz > phdr->p_filesz) {
                const u64 vaddr_file_end = phdr->p_vaddr + phdr->p_filesz;
                const u64 clear_end = round_up(vaddr_file_end, PAGE_SIZE);
                debug("Clearing %zu bytesin partial page from file: %08lx..%08lx\n",
                        clear_end - vaddr_file_end, vaddr_file_end, clear_end);
                memset((void*)vaddr_file_end, 0, clear_end - vaddr_file_end);
            }
        }
    }
    debug("Unmapping image %p..%p\n", bytes, bytes + size);
    const Elf64_Addr entrypoint = ehdr->e_entry;
    munmap((void*)bytes, size);

    // Unmap everything we don't want anymore, e.g. everything except:
    // - new program's stack
    // - the loaded program itself
    // - the elf interpreter (if loaded)
    // - arguments and environment (stored on stack?)
    // - the minimum necessary to jump into the new program
    //   though if the loader is less than one page, we could just keep the whole thing

    // Close CLOEXEC files (we may need to hold on to fd to pass it to an interpreter though)
    // Check what else kind of magic exec does to tear down the old process.
    //
    // Is it possible to modify the /proc/self/exe link?
    //  Yes! prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, ...)
    //  Hmm, although it can only be set once? Ew.

    const uintptr_t mypage = round_down(get_rip(), PAGE_SIZE);
    debug("Preparing to clean up virtual memory:\n");
    debug("mypage: %lx\n", mypage);
    debug("stack: %p..%p\n", stack_start, stack_end);
    debug("binary: %lx..%lx\n", loadstart, loadend);

    // This is to keep track of the range of things (including the stack) that we need to keep around.
    // This is pretty bad though, since the stack seems to end up near the end
    // of address space, so we just preserve everything. Should be much more
    // fine-grained.
    loadstart = MIN(loadstart, (uintptr_t)stack_start);
    loadend = MAX(loadend, (uintptr_t)stack_end);
    const uintptr_t loadend_page = round_up(loadend, PAGE_SIZE);
    debug("keeping bin+stack: %16lx..%16lx\n", loadstart, loadend);
    debug("keeping myself:    %16lx..%16lx\n", mypage, mypage + PAGE_SIZE);
    // Can't unmap the stack :( Need a better way to handle this stuff. The
    // relocation step should make sure to put "us" in a well-known place.
    munmap_range(0, MIN(mypage, loadstart));
    if (mypage < loadstart) {
        munmap_range(mypage + PAGE_SIZE, loadstart);
    } else if (mypage > loadend) {
        munmap_range(loadend_page, mypage);
    } else {
        // mypage is inside the range (this should eventually be impossible,
        // but is now possible because of including the stack in loadstart/end)
        debug("mypage is between program and stack\n");
    }
    // TODO This unmaps our stack and everything asplode.
    //munmap_range(MAX(loadend_page, mypage + PAGE_SIZE), vdso_start);
    switch_to(stack_ptr, entrypoint);
}

int el_execveat(int dirfd, const char *path, char *const argv[], char *const envp[], int flags) {
    int oflags = O_CLOEXEC | O_RDONLY;
    if (flags & AT_SYMLINK_NOFOLLOW) {
        oflags |= O_NOFOLLOW;
    }

    bool use_dirfd = false;
    if ((flags & AT_EMPTY_PATH) && !*path) {
        use_dirfd = true;
    }

    const int fd = use_dirfd ? dirfd : openat(dirfd, path, oflags);
    if (fd < 0) {
        return -1;
    }

    el_fexecve(fd, argv, envp);

    // el_fexecve may never return successfully, so this is some kind of error
    // regardless of what fexecve returned.
    close(fd);
    return -1;
}
int el_execve(const char *path, char *const argv[], char *const envp[]) {
    return el_execveat(AT_FDCWD, path, argv, envp, 0);
}
