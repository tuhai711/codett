CC = gcc
MD = mkdir
RM = rm
CP = cp
COMP_VER = 0.0.1
SRC_PATH = ./src
INC_PATH = ./inc
X_VERSION = '1.0.1'

TARGET = ttdpd
CFLAGS  = -Wall 
CFLAGS += -Wunused-variable
CFLAGS += -Wunused-function
CFLAGS += -Wno-char-subscripts
CFLAGS += -D_GNU_SOURCE
#CFLAGS += -DHAVE_DAEMON
CFLAGS += -I./inc -I./inc/linux
LDFLAGS  = -lpthread
LDFLAGS += -levent
LDFLAGS += -lpcap -luuid

src = $(wildcard *.c) $(wildcard $(SRC_PATH)/*.c) $(wildcard $(SRC_PATH)/tlv/*.c) $(wildcard $(SRC_PATH)/common/*.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.d)  # one dependency file for each source

$(TARGET): $(obj)
	$(CC) -o ./bin/$@ $^ $(LDFLAGS)
%.d: %.c
	@$(CPP) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
.PHONY: clean
clean:
	$(RM) -f $(obj) $(TARGET) ./bin/$(TARGET)

