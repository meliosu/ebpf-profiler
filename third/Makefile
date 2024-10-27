CC=clang
CC_BPF=clang
FLAGS=-Wall -g
FLAGS_BPF=-Wall -g -O2 -target bpf
BPFTOOL=bpftool
LIBS=-lbpf
TARGET=sample

all: $(TARGET)

$(TARGET): sample.c sample.bpf.o sample.skel.h
	$(CC) $(FLAGS) -o sample sample.c $(LIBS)

sample.skel.h: sample.bpf.o
	$(BPFTOOL) gen skeleton sample.bpf.o > sample.skel.h

sample.bpf.o: sample.bpf.c
	$(CC_BPF) $(FLAGS_BPF) -c sample.bpf.c

victim: victim.c
	$(CC) $(FLAGS) -fno-omit-frame-pointer -o victim victim.c

install:
	cp -f $(TARGET) /usr/local/bin
	

clean: 
	rm $(TARGET) sample.bpf.o sample.skel.h
