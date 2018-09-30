.PHONY: all clean install commit

include build/common.mk
include build/makejobs.mk

OUTDIR ?= out
CFLAGS := -std=gnu11
CFLAGS += -g -Os -march=native
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -fPIC

CFLAGS += -W -Wall -Wextra -Werror
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -Wmissing-include-dirs
CFLAGS += -Wno-unused-function -Wno-unused-parameter

LDFLAGS := -Wl,--gc-sections -L$(OUTDIR)

SOURCES := runelf.c elfload.c
LIB_SOURCES := elfload.c
OBJECTS := $(SOURCES:%.c=$(OUTDIR)/%.o)
LIB_OBJECTS := $(LIB_SOURCES:%.c=$(OUTDIR)/%.o)
BINARIES := $(addprefix $(OUTDIR)/, runelf runelf-pie true true-asm)
LIBRARIES := $(addprefix $(OUTDIR)/, libelfload.a)

CCACHE ?= #ccache
CC := $(CCACHE) $(CC)
CXX := $(CCACHE) $(CXX)

default: all

all: $(BINARIES) $(LIBRARIES)

clean:
	rm -fr out

$(OUTDIR)/runelf: $(OUTDIR)/runelf.o $(OUTDIR)/libelfload.a
	$(HUSH_LD) $(CC) $(LDFLAGS) -o $@ $< -lelfload
	$(SIZE_LD)

$(OUTDIR)/runelf-pie: $(OUTDIR)/runelf.o $(OUTDIR)/libelfload.a
	$(HUSH_LD) $(CC) $(LDFLAGS) -pie -o $@ $< -lelfload
	$(SIZE_LD)

$(OUTDIR)/libelfload.a: $(LIB_OBJECTS)
	$(HUSH_AR) $(AR) crs $@ $^
	$(SIZE_AR)

$(OUTDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(HUSH_CC) $(CC) $(CFLAGS) -c -MP -MMD -o $@ $<

$(OUTDIR)/true: true.c
	$(HUSH_CC) $(CC) $(CFLAGS) $(LDFLAGS) -static -MP -MMD -o $@ $<
	$(SIZE_CC)

$(OUTDIR)/true-asm: true-asm.S
	$(HUSH_AS) $(CC) -nostdlib $(CFLAGS) $(LDFLAGS) -static -MP -MMD -o $@ $<
	$(SIZE_AS)

-include $(OBJECTS:.o=.d)
