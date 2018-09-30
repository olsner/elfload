SYSTEM := $(shell uname -s)

ifeq ($(SYSTEM), Darwin)
FILE_SIZE = stat -f%z
else
FILE_SIZE = stat -c%s
endif

# Default is not verbose, i.e. VERBOSE is empty.
ifeq ($(VERBOSE),YES)
CP=cp -v
else
CP=cp
endif

ifneq ($(VERBOSE),YES)
HUSH_AR     = @echo ' [AR]\t'$@;
HUSH_AS     = @echo ' [AS]\t'$@;
HUSH_CC     = @echo ' [CC]\t'$@;
HUSH_CXX    = @echo ' [CXX]\t'$@;
HUSH_LD     = @echo ' [LD]\t'$@;
HUSH_OBJCOPY= @echo ' [OBJCOPY]\t'$@;

SIZE_AS=@echo ' [AS]\t'$@: `$(FILE_SIZE) $@` bytes
SIZE_AR=@echo ' [AR]\t'$@: `$(FILE_SIZE) $@` bytes
SIZE_CC= @echo ' [CC]\t'$@: `$(FILE_SIZE) $@` bytes
SIZE_LD= @echo ' [LD]\t'$@: `$(FILE_SIZE) $@` bytes
SIZE_OBJCOPY= @echo ' [OBJCOPY]\t'$@: `$(FILE_SIZE) $@` bytes
endif
