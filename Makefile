.PHONY: all clean install commit
.SECONDARY:

include build/common.mk
include build/makejobs.mk

OUTDIR ?= out
CFLAGS := -std=gnu11
CFLAGS += -g -Os -march=native
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -fPIC -fno-jump-tables

CFLAGS += -W -Wall -Wextra -Werror
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -Wmissing-include-dirs
CFLAGS += -Wno-unused-function -Wno-unused-parameter

LDFLAGS = -g -Wl,--gc-sections -L$(OUTDIR) -Wl,-Map,$@.map

SOURCES := runelf.c elfload.c
LIB_SOURCES := elfload.c
OBJECTS := $(SOURCES:%.c=$(OUTDIR)/%.o)
LIB_OBJECTS := $(LIB_SOURCES:%.c=$(OUTDIR)/%.o)
BINARIES := $(addprefix $(OUTDIR)/, \
	runelf runelf-pie runelf-static \
	hello hello-pie hello-dynamic \
	hello-asm hello-asm-pie \
	sleep \
	unmap_vdso-dynamic \
	)
LIBRARIES := $(addprefix $(OUTDIR)/, libelfload.a)

CCACHE ?= #ccache
CC := $(CCACHE) $(CC)
CXX := $(CCACHE) $(CXX)

default: all test

all: $(BINARIES) $(LIBRARIES)

test: all
	cd test && ./test.sh

clean:
	rm -fr out

$(OUTDIR)/runelf: $(OUTDIR)/runelf.o $(OUTDIR)/libelfload.a
	$(HUSH_LD) $(CC) $(LDFLAGS) -o $@ $< -lelfload
	$(SIZE_LD)

$(OUTDIR)/runelf-pie: $(OUTDIR)/runelf.o $(OUTDIR)/libelfload.a
	$(HUSH_LD) $(CC) $(LDFLAGS) -pie -o $@ $< -lelfload
	$(SIZE_LD)

$(OUTDIR)/runelf-static: $(OUTDIR)/runelf.o $(OUTDIR)/libelfload.a
	$(HUSH_LD) $(CC) $(LDFLAGS) -static -o $@ $< -lelfload
	$(SIZE_LD)

$(OUTDIR)/libelfload.a: $(LIB_OBJECTS)
	$(HUSH_AR) $(AR) crs $@ $^
	$(SIZE_AR)

$(OUTDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(HUSH_CC) $(CC) $(CFLAGS) -c -MP -MMD -o $@ $<

$(OUTDIR)/%: $(OUTDIR)/%.o
	$(HUSH_CC) $(CC) $(CFLAGS) $(LDFLAGS) -static -MP -MMD -o $@ $<
	$(SIZE_CC)

$(OUTDIR)/%-dynamic: $(OUTDIR)/%.o
	$(HUSH_CC) $(CC) $(CFLAGS) $(LDFLAGS) -MP -MMD -o $@ $<
	$(SIZE_CC)

$(OUTDIR)/%-pie: $(OUTDIR)/%.o
	$(HUSH_CC) $(CC) $(CFLAGS) $(LDFLAGS) -pie -MP -MMD -o $@ $<
	$(SIZE_CC)

$(OUTDIR)/%: %.S
	$(HUSH_AS) $(CC) -nostdlib $(CFLAGS) $(LDFLAGS) -static -MP -MMD -o $@ $<
	$(SIZE_AS)

# Kind of similar to what GCC passes to the linker when -static-pie, based on
# https://github.com/gcc-mirror/gcc/commit/6d1ab23dc1fbc5cc0fde2d9d4e01026bf099a333
STATIC_PIE_LDFLAGS = -Wl,-static,-pie,--no-dynamic-linker,-z,text,-z,max-page-size=4096
$(OUTDIR)/hello-asm-pie: hello-asm.S
	$(HUSH_AS) $(CC) -nostdlib $(CFLAGS) $(LDFLAGS) -fpie $(STATIC_PIE_LDFLAGS) -MP -MMD -o $@ $<
	$(SIZE_AS)

-include $(OBJECTS:.o=.d)
