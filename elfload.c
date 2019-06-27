// Needed for unshare()
#define _GNU_SOURCE

#include "elfload.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/prctl.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#define enable_debug 0

typedef uint64_t u64;
typedef uint32_t u32;
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
static uintptr_t raw_brk(uintptr_t addr) {
    return syscall2(__NR_brk, addr, 0);
}

static NORETURN void unimpl(const char *what) {
    printf("UNIMPL: %s\n", what);
    abort();
}
static void debug_check(const char *file, int line, const char *why, int err) {
    debug_printf("%s:%d: returning error %d (%s): %s\n", file, line, err, strerror(err), why);
}
static NORETURN void exit_errno(const char *file, int line, const char *why, int err) {
    printf("%s:%d: returning error %d (%s): %s\n", file, line, err, strerror(err), why);
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

static u64 is_aligned(u64 x, u64 align) {
    return !(x & (align - 1));
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

static size_t get_args_size(char *const argv[], size_t* count) {
    char*const* p;
    size_t args_size = 0;
    size_t argc = 0;
    for (p = argv; *p; p++) {
        args_size += strlen(*p) + 1;
        argc++;
    }
    *count = argc;
    return args_size;
}

// Return argument (data) size, store count by reference.
static size_t get_auxv_size(const auxv_t* auxv, size_t* count) {
    size_t args_size = 0;
    size_t auxc = 0;
    for (const auxv_t* auxp = auxv; auxp->a_type != AT_NULL; auxp++) {
        switch (auxp->a_type) {
        case AT_RANDOM:
            args_size += 16;
            break;
        case AT_PLATFORM:
            args_size += strlen(auxp->a_str) + 1;
            break;
        // TODO AT_EXECFN
        }
        auxc++;
    }
    *count = auxc;
    return args_size;
}

// Duplicates a lot of stuff calculated in build_stack. Return a struct of stack layout data?
static size_t get_stack_size(char *const argv[], char *const envp[], const auxv_t* auxv) {
    size_t args_size = 0;
    size_t argc = 0, envc = 0, auxc = 0;

    args_size += get_args_size(argv, &argc);
    args_size += get_args_size(envp, &envc);
    args_size += get_auxv_size(auxv, &auxc);

    // TODO Check args_size against limit (accounting for all the pointers and
    // a minimum process stack size).
    args_size = (args_size + 7) / 8;

    size_t stack_words = 2 * (1 + auxc) + (1 + envc) + (1 + argc) + 1;
    // If we have an odd number of words left to push and the stack is
    // currently 16 byte aligned, misalign the stack by 8 bytes.
    // And vice versa.
    if (!(stack_words & 1) != !(args_size & 8)) {
        stack_words++;
    }

    return args_size + stack_words * 8;
}

// Stack on entry:
// [from %rsp and increasing addresses!]
// argc
// argv[argc]
// nullptr
// env[]
// nullptr
// aux[] (2 qwords each)
// 2 * AT_NULL
//
// Remaining space may be used to copy the environment, arguments and aux
// vector information.
static void* build_stack(void* stack_start, u64* stack_end, char *const argv[], char *const envp[], const auxv_t* auxv, struct prctl_mm_map* mm_map) {
    size_t args_size = 0;
    size_t argc = 0, envc = 0, auxc = 0;

    args_size += get_args_size(argv, &argc);
    args_size += get_args_size(envp, &envc);
    args_size += get_auxv_size(auxv, &auxc);

    // For now, assume that the aux vector is always built by copying the one
    // for the current process. In reality, it's filled in by the kernel.
    for (const auxv_t* auxp = auxv; auxp->a_type != AT_NULL; auxp++) {
        debug("input auxv %ld (%s): %p\n", auxp->a_type, get_atype_name(auxp->a_type), auxp->a_ptr);
    }

    stack_end -= (args_size + 7) / 8;

    const size_t stack_words = 2 * (1 + auxc) + (1 + envc) + (1 + argc) + 1;
    // If we have an odd number of words left to push and the stack is
    // currently 16 byte aligned, misalign the stack by 8 bytes.
    // And vice versa.
    if (!(stack_words & 1) != !((uintptr_t)stack_end & 8)) {
        stack_end--;
    }
    char *data_start = (char *)stack_end;

    // TODO Since we have auxc we could fill this in forwards.
    *--stack_end = AT_NULL;
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
        // May be incorrect for the process we're starting, so for now just
        // clear them. (This is required since PR_SET_MM expects a full
        // complement of auxv data.)
        case AT_EXECFN:
        case AT_PHDR:
        case AT_PHENT:
        case AT_PHNUM:
        case AT_BASE:
        case AT_ENTRY:
            a.a_val = 0;
            break;
        }
        debug("forwarding auxv %ld (%s): %p\n", a.a_type, get_atype_name(a.a_type), a.a_ptr);
        *--stack_end = a.a_val;
        *--stack_end = a.a_type;
    }
    mm_map->auxv = (__u64*)stack_end;
    // Includes the terminating null entries
    mm_map->auxv_size = 2 * (1 + auxc);

    // envp
    *--stack_end = 0;
    const char** out_envp = (const char**)(stack_end -= envc);
    // env_start..end is a list of null-terminated strings in the environment.
    mm_map->env_start = (uintptr_t)data_start;
    for (size_t i = 0; i < envc; i++) {
        out_envp[i] = data_start;
        data_start += copy_str(data_start, envp[i]);
    }
    mm_map->env_end = (uintptr_t)data_start;

    // argv
    *--stack_end = 0;
    const char** out_argv = (const char**)(stack_end -= argc);
    // mm_map arg_start and arg_end are the list of null-terminated strings that are the arguments, in order.
    mm_map->arg_start = (uintptr_t)data_start;
    for (size_t i = 0; i < argc; i++) {
        out_argv[i] = data_start;
        data_start += copy_str(data_start, argv[i]);
    }
    mm_map->arg_end = (uintptr_t)data_start;
    *--stack_end = argc;

    // Stack must be 16 byte aligned on entry
    assert(!((uintptr_t)stack_end & 15));

    // Is this supposed to be the lower address (i.e. the end of the stack), or
    // the address where the stack starts out?
    mm_map->start_stack = (uintptr_t)stack_end;

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

static void get_vdso_range(uintptr_t *start, uintptr_t *end) {
    uintptr_t vdso_start = getauxval(AT_SYSINFO_EHDR);
    size_t vdso_size = PAGE_SIZE;
    // TODO Not really safe to hardcode, should extract the actual size from vdso or kernel info somehow. Worst case we could just parse /proc/self/maps?
    const size_t vvar_size = 3 * PAGE_SIZE;
    // Checking what's available there
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)vdso_start;
    for (int ph = 0; ph < ehdr->e_phnum; ph++) {
        const Elf64_Off phoff = ehdr->e_phoff + ehdr->e_phentsize * ph;
        const Elf64_Phdr* phdr = (const Elf64_Phdr*)(vdso_start + phoff);

        debug("vDSO header %d: type=%x (%s)\n", ph, phdr->p_type, get_ptype_name(phdr->p_type));

        if (phdr->p_type == PT_LOAD) {
            uintptr_t loadend = round_up(phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE);
            vdso_size = MAX(vdso_size, loadend);
        }
    }
    *start = vdso_start - vvar_size;
    *end = vdso_start + vdso_size;
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

static void reset_process(int keep_fd);
NORETURN static void finish_load(int fd, const uint8_t* const bytes, const size_t size, u64 loadstart, u64 loadend, void* stack_ptr);

/**
 * Like with fexecve, the FD_CLOEXEC flag should usually be set on the executable.
 */
int el_fexecve(const int fd, char *const argv[], char *const envp[]) {
    const size_t size = fsize(fd);

    const size_t used_stack = get_stack_size((char**)argv, (char**)envp, find_auxv(environ));

    // Mapped PROT_READ initially. we'll remap the pages with appropriate
    // protections in the load part, this is just for reading the headers.
    // Could avoid mapping the whole file if we wanted to.
    const uint8_t* const bytes = (const uint8_t *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (bytes == MAP_FAILED) {
        RETURN_ERRNO(errno, "Failed mapping executable");
    }

    CHECK_SIZE(EI_NIDENT);

    if (invalid_elf_file(bytes, size)) {
        RETURN_ERRNO(ENOEXEC, "Not valid ELF file");
    }

    GETHEADER(ehdr, Ehdr, 0);
    Elf64_Addr loadstart = UINT64_MAX, loadend = 0;
    int found_interpreter = 0;
    int stack_prot = PROT_READ | PROT_WRITE;
    size_t stack_size = round_up(used_stack, PAGE_SIZE) + DEFAULT_STACK_SIZE;
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
            if ((phdr->p_offset ^ phdr->p_vaddr) & (PAGE_SIZE - 1)) {
                RETURN_ERRNO(EINVAL, "Impossible file/vaddr offset mismatch");
            }

            loadstart = MIN(phdr->p_vaddr, loadstart);
            loadend = MAX(phdr->p_vaddr + phdr->p_memsz, loadend);
            break;
        case PT_GNU_STACK:
            // How about a read-only or inaccessible stack? Seems ridiculous though :)
            if (phdr->p_flags & PF_X) stack_prot |= PROT_EXEC;
            // FDPIC ELF uses p_memsz to indicate stack size too, but it seems normal ELFs don't do that.
            break;
        }
    }
    assert(is_aligned(stack_size, PAGE_SIZE));
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

    // Must be strictly larger than end_data and start_data
    const uintptr_t start_brk = (loadend + PAGE_SIZE) & -PAGE_SIZE;
    struct prctl_mm_map mm_map = {
        // TODO How are these calculated by Linux?
        .start_code = loadstart,
        .end_code = loadend - 1,
        // start_data < end_data is required. I guess we should just track the
        // executable/data split. Based on program header access flags?
        .start_data = loadend - 1,
        .end_data = loadend,
        .start_brk = start_brk,
        .brk = start_brk,
        // stack, arg, env and auxv stuff is set in build_stack
        // Since exe_fd requires more privileges to modify, set it separately
        // though PR_SET_MM_EXE_FILE so we can ignore failures.
        .exe_fd = (u32)-1
    };
    unsigned int mm_map_size = 0;
    if (prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, (unsigned long)&mm_map_size, 0, 0)) {
        RETURN_ERRNO(errno, "Failed getting size of struct mm_map");
    } else if (mm_map_size != sizeof(mm_map)) {
        RETURN_ERRNO(ENOSYS, "Incompatible struct mm_map");
    }

    uintptr_t vdso_start, vdso_end;
    get_vdso_range(&vdso_start, &vdso_end);
    debug("vDSO range: %lx..%lx\n", vdso_start, vdso_end);

    // FIXME Make sure this doesn't overlap where we're about to put anything
    // either. Should probably go before relocate so we know we don't need
    // anything at all from the old address space (except the loader code
    // itself). The stack could be moved after the fact but the pointers would
    // need updating. Alternatively, if we know the final location we can
    // adjust pointers while building it.
    void *const stack_start = mmap(0, stack_size, stack_prot, MAP_GROWSDOWN | MAP_STACK | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (stack_start == MAP_FAILED) {
        RETURN_ERRNO(E2BIG, "stack mmap failed");
    }
    void *const stack_end = (char*)stack_start + stack_size;

    void *const stack_ptr = build_stack(stack_start, (u64*)stack_end, argv, envp, find_auxv(environ), &mm_map);
    debug("Generated %zu bytes of argument/environment data\n", stack_start + stack_size - stack_ptr);

    // From this point forward we'll start messing with the original process so
    // we should exit rather than return, but we still have access to libc
    // functions and e.g. errno since we haven't unampped anything yet.

    reset_process(fd);

    if (prctl(PR_SET_MM, PR_SET_MM_MAP, (unsigned long)&mm_map, sizeof(mm_map), 0)) {
        EXIT_ERRNO(errno, "prctl PR_SET_MM_MAP failed");
    }

    munmap_range(loadstart, loadend);

    // This is to keep track of the range of things (including the stack) that we need to keep around.
    // This is pretty bad though, since the stack seems to end up near the end
    // of address space, so we just preserve everything. Should be much more
    // fine-grained.
    loadstart = MIN(loadstart, (uintptr_t)stack_start);
    loadend = MAX(loadend, (uintptr_t)stack_end);

    finish_load(fd, bytes, size, loadstart, loadend, stack_ptr);
}

// Reset all fiddly process state to the clean slate required by the new
// process in exec(). Since this starts to mess with process state, all errors
// result in terminating the process.
// This runs with all old memory still mapped, so we can use libc and errno freely.
void reset_process(const int keep_fd) {
    // Disable the alternate signal stack as mandated by POSIX (required also
    // since the alternative stack might point into memory we're about to
    // unmap).
    {
        stack_t ss;
        ss.ss_flags = SS_DISABLE;
        if (sigaltstack(&ss, NULL)) {
            EXIT_ERRNO(errno, "sigaltstack");
        }
    }

    // Reset signal dispositions for signals that are being caught. (the signal
    // handlers will be unmapped...)
    // POSIX.1 specifies that the dispositions of any signals that are ignored
    // or set to the default are left unchanged.
    {
        struct sigaction oldact;
        int max_sig = sizeof(oldact.sa_mask) * CHAR_BIT;
        for (int i = 0; i < max_sig; i++) {
            if (sigaction(i, NULL, &oldact)) {
                if (errno != EINVAL) {
                    debug("%d: sigaction error %d (%s)\n", i, errno, strerror(errno));
                }
                continue;
            }
            if (oldact.sa_handler != SIG_DFL && oldact.sa_handler != SIG_IGN) {
                memset(&oldact, 0, sizeof(oldact));
                oldact.sa_handler = SIG_DFL;
                if (sigaction(i, &oldact, NULL)) {
                    EXIT_ERRNO(errno, "Resetting sigaction");
                }
            }
        }
    }

    // Maybe also CLONE_SYSVSEM. The other unshare/clone flags seem to have to
    // do with namespaces which exec doesn't affect.
    // Make a test with vfork() to make sure the closing of CLOEXEC files does
    // not affect the parent.
    unshare(CLONE_FILES);

    // Close CLOEXEC files (we may need to hold on to fd to pass it to an interpreter though)
    //   See execveat/fexecve documentation about running file descriptors with interpreters though.
    // Check what else kind of magic exec does to tear down the old process.
    // See execve(2).
    //
    // POSIX:
    // - mlock/mlockall memory locks are not preserved
    // - the floating-point environment is reset
    //
    // Linux:
    // - PR_SET_DUMPABLE is set
    // - PR_SET_KEEPCAPS is cleared
    // - PR_SET_NAME process name is reset to the executable name
    // - SECBIT_KEEP_CAPS[securebits] is cleared
    // - termination signal is reset to SIGCHLD
    //   This should probably be done first since errors cause termination in this section
    //
    // I think the above stuff can all be done before we start unmapping
    // memory, which means we can use libc to do it.
}

// This function does everything after the "point of no return", we start unmapping memory and 
void finish_load(int fd, const uint8_t* const bytes, const size_t size, u64 loadstart, u64 loadend, void* stack_ptr) {
    // TODO Prepare a list of instructions from the other function instead of
    // getting it from ELF headers here, then send only the original file
    // descriptor?
    // The plan then is that everything old is unmapped right away except for
    // the trampoline code and data. Probably the data is stored on the new
    // stack such that it is popped before jumping to the entry point.
    // The trampoline then covers mmap and memset as required.
    Elf64_Ehdr* const ehdr = (Elf64_Ehdr*)bytes;
    for (int ph = 0; ph < ehdr->e_phnum; ph++) {
        const Elf64_Off phoff = ehdr->e_phoff + ehdr->e_phentsize * ph;
        Elf64_Phdr* const phdr = (Elf64_Phdr*)(bytes + phoff);

        if (phdr->p_type == PT_LOAD) {
            const u64 vaddr_offset = phdr->p_vaddr & (PAGE_SIZE - 1);
            const u64 vaddr_page = phdr->p_vaddr - vaddr_offset;
            const u64 vaddr_size = round_up(phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE) - vaddr_page;

            const u64 file_offset = phdr->p_offset & (PAGE_SIZE - 1);
            const u64 file_page = phdr->p_offset - file_offset;
            const u64 file_size = round_up(phdr->p_offset + phdr->p_filesz, PAGE_SIZE) - file_page;

            debug("Mapping %08lx..%08lx to %08lx..%08lx (%08lx..%08lx)\n",
                    phdr->p_offset, phdr->p_offset + phdr->p_filesz,
                    phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz,
                    vaddr_page, vaddr_page + vaddr_size);

            const int prot = prot_from_flags(phdr->p_flags);
            if (file_size) {
                if (mmap((void*)vaddr_page, file_size, prot,
                            MAP_PRIVATE | MAP_FIXED, fd, file_page) == MAP_FAILED) {
                    EXIT_ERRNO(errno, "mmap failed");
                }
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

    // Unmap everything we don't want anymore, e.g. everything except:
    // - new program's stack
    // - the loaded program itself
    // - the elf interpreter (if loaded)
    // - arguments and environment (stored on stack?)
    // - the minimum necessary to jump into the new program
    //   though if the loader is less than one page, we could just keep the whole thing

    debug("Unmapping image %p..%p\n", bytes, bytes + size);
    const Elf64_Addr entrypoint = ehdr->e_entry;
    munmap((void*)bytes, size);

    // TODO This can only be done after unmapping all pages of the old
    // executable, so it needs to be part of the evantual trampoline function.
    if (prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0)) {
        // Not an error, since this requires additional privileges for now ignore failures.
        debug("PR_SET_MM_EXE_FILE failed\n");
    }

    const uintptr_t mypage = round_down(get_rip(), PAGE_SIZE);
    debug("Preparing to clean up virtual memory:\n");
    debug("mypage: %lx\n", mypage);
    debug("binary+stack: %lx..%lx\n", loadstart, loadend);
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
