CC=clang
CC_BPF=clang
FLAGS=-Wall -g
FLAGS_BPF=-Wall -g -O2 -target bpf
LIBS=-lbpf
BPFTOOL=bpftool
INSTALL_DIR=/usr/local/bin/
TARGET=stats

all: $(TARGET)

$(TARGET): %: %.c %.bpf.o %.skel.h
	$(CC) $(FLAGS) -o $(TARGET) $< $(LIBS)

$(TARGET).skel.h: $(TARGET).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET).bpf.o: $(TARGET).bpf.c
	$(CC_BPF) $(FLAGS_BPF) -c $<

install:
	cp $(TARGET) $(INSTALL_DIR)


clean:
	rm $(TARGET) $(TARGET).bpf.o $(TARGET).skel.h
