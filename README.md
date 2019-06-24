# User-space ELF loader #

The idea is to emulate exec() as faithfully as possible in user-space.

Lots of things are still unsupported or not working correctly, and even when
everything is implemented, kernel-mode exec() is practically atomic while a
user-space implementation has many ways to fail with a partially loaded new
process or partially unloaded old process.

The biggest issue is lack of support for dynamically linked executables and
executables where any segment to load overlaps the code of the elf loader
itself.

## License ##

MIT license, see COPYING for details.

## Known issues ##

* ELF interpreters (e.g. PIE and dynamic executables) are not supported
* The loaded process must not overlap the elf loader, this limits the usability
  severely since most statically linked non-PIE executables will have the same
  load address.
* File descriptors marked `CLOEXEC` will not be closed

* exec() in a program with running threads will most likely crash as the code
  for the running threads gets unmapped. This doesn't affect fork/exec though
  since the forked child does not have any threads.
* All parts of the previous process might not be unmapped
* Stack size hint/request in `PT_GNU_STACK` is not respected
* The start/end of code/data segment in `prctl_mm_map` is not correct. Unclear
  how the kernel actually uses these. Might be visible as incorrect statistics
  in some `/proc/self` files?
* `/proc/self/exe` is not updated. This file cannot be updated without being
  root in the current namespace.
* Enough checks are not done before the "point of no return", so the previous
  process can't handle errors.
* Not all resources will be released in error cases.
* 32-bit programs cannot be exec()ed from a 64-bit process.

## Untested features ##

* Resetting of signal handlers on `exec()`
