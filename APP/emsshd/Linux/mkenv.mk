

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
TARGET = $(BUILD)/emsshd

# CFLAGS += -std=gnu99
CFLAGS += -Wno-unused-result

# LDFLAGS += -nostdlib -nostdinc -fno-pic -fno-builtin -T linker.lds
LDFLAGS +=

INC += -I. -I"./$(BUILD)" -I"$(TOP)" -I"$(TOP)/include" 
INC += -I"$(TOP)/Libs/external/mbedtls/include" -I"$(TOP)/Libs/external/mbedtls/library"

LIB += -lcrypt

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

