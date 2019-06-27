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
#include <stdarg.h>
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
typedef uint16_t u16;
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

#define debug_printf(f, l, fmt, ...) do { if (enable_debug) fprintf(stderr, "%s:%d: " fmt, f, l, ## __VA_ARGS__); } while (0)
#define debug(fmt, ...) debug_printf(__FILE__, __LINE__, fmt, ## __VA_ARGS__)

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

static inline int64_t syscall6(uint64_t nr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    int64_t res;
    register int64_t r8 __asm__("r8") = arg5;
    register int64_t r9 __asm__("r9") = arg6;
    // r10 takes the place of rcx in the usual convention since rcx is taken by syscall
    register int64_t r10 __asm__("r10") = arg4;
    __asm__ __volatile__ ("syscall"
            : /* return value(s) */
            "=a" (res),
            /* clobbered inputs */
            "=D" (arg1), "=S" (arg2), "=d" (arg3), "=r" (r8), "=r" (r9), "=r"(r10)
            : "a" (nr), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r8), "r" (r9), "r"(r10)
            : "r11", "%rcx", "memory");
    return res;
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
    syscall2(__NR_exit, status, 0);
    __builtin_unreachable();
}
static int raw_munmap(void *start, size_t length) {
    return syscall2(__NR_munmap, (u64)start, (u64)length);
}
static uintptr_t raw_brk(uintptr_t addr) {
    return syscall2(__NR_brk, addr, 0);
}
// Note on x86-64, the system call takes a byte offset. Various architectures
// have different variants, e.g. x86 has mmap2 for page offset (allowing larger
// offsets than fit in 32 bits) and mmap for byte offset.
static intptr_t raw_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return syscall6(__NR_mmap, (u64)addr, length, prot, flags, fd, offset);
}
static void* inline_memset(void* dest, int c, size_t n) {
	asm("rep stosb": "+D"(dest), "+c"(n), "=m"(dest) : "a"(c) : "memory");
	return dest;
}

static NORETURN void unimpl(const char *what) {
    printf("UNIMPL: %s\n", what);
    abort();
}
static void debug_check(const char *file, int line, const char *why, int err) {
    debug_printf(file, line, "returning error %d (%s): %s\n", err, strerror(err), why);
}
static NORETURN void exit_errno(const char *file, int line, const char *why, int err) {
    printf("%s:%d: returning error %d (%s): %s\n", file, line, err, strerror(err), why);
    _exit(1);
}
static NORETURN void assert_failed(const char *file, int line, const char *what) {
    debug_printf(file, line, "assertion failed: %s\n", what);
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
    __builtin_unreachable();
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

static void get_vdso_range(void** start, void** end) {
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
    *start = (void*)(vdso_start - vvar_size);
    *end = (void*)(vdso_start + vdso_size);
}

enum loadcmd_type {
    // Unmap: munmap(par[0].p, par[1].p - par[0].p)
    LC_Unmap,
    // mmap(par[0].p (address), par[1].u (size), par[2].u (prot), [implicit flags], par[3].i (fd), par[4].u (offset in file))
    LC_Map,
    // mmap(par[0].p (address), par[1].u (size), par[2].u (pro)) anonymous, read/write and zeroed
    LC_MapAnon,
    // memset(par[0].p, 0, par[1].u)
    LC_Memset0,
    // PR_SET_MM_EXE_FILE with par[0].i
//    LC_SetExeFD,
    // Set rsp=par[0], jump to rip=par[1], this terminates the program.
    // TODO Also clear any registers that should have defined values on entry.
    // TODO Figure out a way to combine this with unmapping the page of memory
    // that we are currently running from. Maybe a bit of ROP programming - set
    // registers for the munmap call, push the entre point and a pointer to a
    // syscall+ret combination e.g. in the vdso, then "return" to it.
    LC_Enter
};
struct loadcmd {
    enum loadcmd_type cmd;
    union {
        intptr_t i;
        uintptr_t u;
        void* p;
    } par[5];
};
typedef struct loadcmd loadcmd;

static void run_loadcmd(loadcmd cmd) {
    intptr_t res = 0;
    switch (cmd.cmd) {
    case LC_Unmap:
        res = raw_munmap(cmd.par[0].p, cmd.par[1].p - cmd.par[0].p);
        break;
    case LC_Map: {
        int prot = cmd.par[2].u;
        res = raw_mmap(cmd.par[0].p, cmd.par[1].u, prot,
                MAP_FIXED | (prot & PROT_WRITE ? MAP_PRIVATE : MAP_SHARED),
                cmd.par[3].i, cmd.par[4].u);
        break;
    }
    case LC_MapAnon:
        res = raw_mmap(cmd.par[0].p, cmd.par[1].u, cmd.par[2].u,
                MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        break;
    case LC_Memset0:
        inline_memset(cmd.par[0].p, 0, cmd.par[1].u);
        break;
    case LC_Enter:
        switch_to(cmd.par[0].p, cmd.par[1].u);
        break;
    }

    if (res < 0) {
        abort();
    }
}
// Interpret a load script starting at p, until it encounters an LC_Enter command
NORETURN static void run_loadscript(loadcmd* p, loadcmd* q) {
    for (;;) run_loadcmd(*p++);
}

static void debug_loadcmd(const char* file, int line, loadcmd cmd) {
    switch (cmd.cmd) {
    case LC_Unmap:
        debug_printf(file, line, "LOADCMD: munmap(%p..%p)\n", cmd.par[0].p, cmd.par[1].p);
        break;
    case LC_Map: {
        size_t length = cmd.par[1].u;
        size_t offset = cmd.par[4].u;
        int prot = cmd.par[2].i;
        debug_printf(file, line, "LOADCMD: mmap(%p <= %zu bytes from %#lx prot=%c%c%c)\n",
                cmd.par[0].p, length, offset,
                prot & PROT_READ ? 'r' : '-', prot & PROT_WRITE ? 'w' : '-', prot & PROT_EXEC ? 'x' : '-');
        break;
    }
    case LC_MapAnon: {
        size_t length = cmd.par[1].u;
        int prot = cmd.par[2].i;
        debug_printf(file, line, "LOADCMD: mmap(%p <= %zu anonymous bytes prot=%c%c%c)\n",
                cmd.par[0].p, length,
                prot & PROT_READ ? 'r' : '-', prot & PROT_WRITE ? 'w' : '-', prot & PROT_EXEC ? 'x' : '-');
        break;
    }
    case LC_Memset0:
        debug_printf(file, line, "LOADCMD: memset(%p, %d, %zu)\n", cmd.par[0].p, 0, cmd.par[1].u);
        break;
    case LC_Enter:
        debug_printf(file, line, "LOADCMD: switch_to(rsp=%p, entry=%p)\n", cmd.par[0].p, cmd.par[1].p);
        break;
    }
}
static void debug_loadscript(loadcmd* p, loadcmd* q) {
    while (p < q) debug_loadcmd(__FILE__, __LINE__, *p++);
}

static void add_loadcmd(loadcmd** dest, enum loadcmd_type cmd, ...) {
    struct loadcmd c;
    c.cmd = cmd;
    va_list ap;
    va_start(ap, cmd);
    for (int i = 0; i < 5; i++) {
        c.par[i].u = va_arg(ap, uintptr_t);
    }
    va_end(ap);

    *(*dest)++ = c;
}
#define ADD_LOADCMD(cmd, ...) \
    do { \
        assert(loadscript < loadscript_limit); \
        add_loadcmd(&loadscript, cmd, ## __VA_ARGS__); \
        debug_loadcmd(__FILE__, __LINE__, loadscript[-1]); \
    } while (0)

static void reset_process(int keep_fd);

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

    void* vdso_start;
    void* vdso_end;
    get_vdso_range(&vdso_start, &vdso_end);
    debug("vDSO range: %p..%p\n", vdso_start, vdso_end);

    // FIXME Make sure this doesn't overlap where we're about to put anything.
    // The stack could be moved after the fact but the pointers would need
    // updating. Alternatively if we know a usable final location we can adjust
    // pointers while building it, then remap the stack.
    void *const stack_start = mmap(0, stack_size, stack_prot, MAP_GROWSDOWN | MAP_STACK | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (stack_start == MAP_FAILED) {
        RETURN_ERRNO(E2BIG, "stack mmap failed");
    }
    void* const stack_end = (char*)stack_start + stack_size;
    loadcmd* const loadscript_limit = stack_end;
    loadcmd* const loadscript_start = (loadcmd*)(round_down((uintptr_t)stack_end, PAGE_SIZE) - PAGE_SIZE);
    loadcmd* loadscript = loadscript_start;

    void *const stack_ptr = build_stack(stack_start, (u64*)stack_end, argv, envp, find_auxv(environ), &mm_map);
    debug("Generated %zu bytes of argument/environment data\n", stack_start + stack_size - stack_ptr);

    debug("Load addresses at %lx..%lx, self at %p, stack at %p..%p (%zu bytes)\n",
            loadstart, loadend, &el_fexecve, stack_start, stack_end, stack_size);

    // Make a copy of just the run_loadscript function in a separate page. This
    // page will be "saved" by the unmapping stuff below, but lets us unmap all
    // pages from the old process. (TODO: Need to make sure the allocated page
    // does not overlap any pages that will be loaded.)
    // Could be cleaned up a bit with an assembly load script runner that doesn't need any stack. That
    // can also tell us its size so we don't have to copy a whole page.
    void* loadscript_runner = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (loadscript_runner == MAP_FAILED) {
        RETURN_ERRNO(errno, "Loader trampoline allocation failed");
    }
    // movabsq $stack_ptr, %rsp
    *(u16*)loadscript_runner = 0xbc48;
    *(void**)(loadscript_runner + 2) = stack_ptr;
    memcpy(loadscript_runner + 10, run_loadscript, PAGE_SIZE - 10);
    NORETURN void (*run_loadscript_ptr)(void*, void*) = loadscript_runner;
    mprotect(loadscript_runner, PAGE_SIZE, PROT_READ | PROT_EXEC);

    const void* mypage = loadscript_runner;
    const void* mypage_end = (char*)loadscript_runner + PAGE_SIZE;
    debug("keeping stack:  %16p..%16p\n", stack_start, stack_end);
    debug("keeping loader: %16p..%16p\n", mypage, mypage_end);
    debug("keeping vDSO:   %16p..%16p\n", vdso_start, vdso_end);

    ADD_LOADCMD(LC_Unmap, 0, MIN(mypage, stack_start));
    if (mypage < stack_start) {
        ADD_LOADCMD(LC_Unmap, mypage_end, stack_start);
    } else if (stack_end < mypage) {
        ADD_LOADCMD(LC_Unmap, stack_end, mypage);
    }
    assert(vdso_start > stack_end);
    ADD_LOADCMD(LC_Unmap, MAX(stack_end, mypage_end), vdso_start);
    ADD_LOADCMD(LC_Unmap, vdso_end, USER_VADDR_END);

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

            debug("Mapping %08lx..%08lx to %08lx..%08lx (%08lx..%08lx)\n",
                    phdr->p_offset, phdr->p_offset + phdr->p_filesz,
                    phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz,
                    vaddr_page, vaddr_page + vaddr_size);

            const int prot = prot_from_flags(phdr->p_flags);
            if (file_size) {
                ADD_LOADCMD(LC_Map, vaddr_page, file_size, prot, fd, file_page);
            }

            // TODO Add tests:
            // - check that extra BSS pages are accessible and zeroed
            // - check that the BSS part of the tail of the .data section is properly zeroed
            if (vaddr_size > file_size) {
                debug("Mapping BSS %08lx..%08lx\n", vaddr_page + file_size, vaddr_page + vaddr_size);
                ADD_LOADCMD(LC_MapAnon, vaddr_page + file_size, vaddr_size - file_size, prot);
            }
            if (phdr->p_memsz > phdr->p_filesz) {
                const u64 vaddr_file_end = phdr->p_vaddr + phdr->p_filesz;
                const u64 clear_end = round_up(vaddr_file_end, PAGE_SIZE);
                debug("Clearing %zu bytesin partial page from file: %08lx..%08lx\n",
                        clear_end - vaddr_file_end, vaddr_file_end, clear_end);
                ADD_LOADCMD(LC_Memset0, vaddr_file_end, vaddr_size - file_size);
            }
        }
    }

    debug("Unmapping image %p..%p\n", bytes, bytes + size);
    const Elf64_Addr entrypoint = ehdr->e_entry;
    munmap((void*)bytes, size);

    // Final command: enter the new process with the appropriate stack pointer
    ADD_LOADCMD(LC_Enter, stack_ptr, entrypoint);

    // From this point forward we'll start messing with the original process so
    // we should exit rather than return, but we still have access to libc
    // functions and e.g. errno since we haven't unampped anything yet.

    reset_process(fd);

    if (prctl(PR_SET_MM, PR_SET_MM_MAP, (unsigned long)&mm_map, sizeof(mm_map), 0)) {
        EXIT_ERRNO(errno, "prctl PR_SET_MM_MAP failed");
    }

    // TODO This can only be done after unmapping all pages of the old
    // executable, so it needs to be part of the load script.
    if (prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0)) {
        // Not an error, since this requires additional privileges for now ignore failures.
        debug("PR_SET_MM_EXE_FILE failed\n");
    }

    debug_loadscript(loadscript_start, loadscript);

    run_loadscript_ptr(loadscript_start, loadscript);
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
