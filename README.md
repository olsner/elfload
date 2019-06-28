# User-space ELF loader #

The idea is to emulate exec() as faithfully as possible in user-space.

Lots of things are still unsupported or not working correctly, and even when
everything is implemented, kernel-mode exec() is practically atomic while a
user-space implementation has many ways to fail with a partially loaded new
process or partially unloaded old process.

## License ##

MIT license, see the file LICENSE for details.

## Known issues ##

* ELF interpreters (e.g. PIE and dynamic executables) are not supported
* exec() in a program with running threads will most likely crash as the code
  for the running threads gets unmapped. This doesn't affect fork/exec though
  since the forked child does not have any threads.
* The start/end of code/data segment in `prctl_mm_map` is not correct. Unclear
  how the kernel actually uses these. Might be visible as incorrect statistics
  in some `/proc/self` files?
* `/proc/self/exe` is not updated. This file cannot be updated without being
  root in the current namespace.
* Enough checks are not done before the "point of no return", so the previous
  process can't handle errors.
* Not all resources will be released in error cases.
* One page of executable code will remain mapped in the new process. We'd need
  to find a way for this code to unmap itself at the same time as it transfers
  control to the new executable.
