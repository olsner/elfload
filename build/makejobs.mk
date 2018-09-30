# Prevent setting -jN for submakes - we should let the jobserver handle it.
ifneq ($(DID_SET_MAKEJOBS), YES)
# Set JOBS to NO to disable this code (e.g. when making recursively), set JOBS
# to another value to pass it to -j$(JOBS), or leave unset to default to the
# number of processors.
ifneq (NO,$(JOBS))
ifeq ($(SYSTEM), Darwin)
NPROC := $(shell sysctl -n hw.activecpu)
else
NPROC := $(shell nproc)
endif
JOBS ?= $(NPROC)
MAKEFLAGS += -j$(JOBS)
export DID_SET_MAKEJOBS=YES
endif
endif
