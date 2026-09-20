CC=gcc
CFLAGS=-Wall -g
LIBS=-lpcap -lm
INCLUDE=$(CURDIR)/include
SRC=$(CURDIR)/src
LIB=$(CURDIR)/lib
OBJDIR=$(CURDIR)/obj

SRCFILES=$(wildcard $(SRC)/*.c)
OBJFILES=$(SRCFILES:$(SRC)/%.c=$(OBJDIR)/%.o)

TARGET=sniffer

.PHONY: all clean rebuild

all: $(TARGET)

$(OBJDIR):
	mkdir -p $@

$(TARGET): $(OBJFILES)
		$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

$(OBJDIR)/%.o: $(SRC)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET) payload.log

rebuild: clean all