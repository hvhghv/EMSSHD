

TOP = ../../..

CROSS ?= 
CC = $(CROSS)gcc
CXX = $(CROSS)g++
LD = $(CROSS)ld
AS = $(CC)
AR = $(CROSS)ar
OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump

MKDIR = mkdir
CP = cp

BUILD = build
TARGET = $(BUILD)/emtask.exe

# CFLAGS += -std=gnu99
CFLAGS += -Wno-unused-result
CFLAGS += -DMBEDTLS_CONFIG_FILE='"mbedtls_config_port.h"'

# LDFLAGS += -nostdlib -nostdinc -fno-pic -fno-builtin -T linker.lds
LDFLAGS +=

INC += -I. -I"./$(BUILD)" -I"$(TOP)" -I"$(TOP)/include" -I"$(TOP)/APP/emtask"
INC += -I"$(TOP)/Libs/external/mbedtls/include" -I"$(TOP)/Libs/external/mbedtls/library"
INC += -I"$(TOP)/File/mbedtls-legacy"

LIB += -lws2_32 -ladvapi32

ifeq ($(DEBUG), 1)
CFLAGS += -O0 -g
CXXFLAGS += -O0 -g
ASFLAGS += -O0 -g

else
CFLAGS += -Os
CXXFLAGS += -Os
ASFLAGS += -Os
endif

ifeq ($(PG), 1)
CFLAGS += -pg
CXXFLAGS += -pg
ASFLAGS += -pg
LDFLAGS += -pg
endif
