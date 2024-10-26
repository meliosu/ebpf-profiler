CC=gcc
CC_BPF=clang
FLAGS=-Wall -g
FLAGS_BPF=-Wall -g -O2 -target bpf
BPFTOOL=bpftool
LIBS=-lbpf
TARGET=profiler

all: $(TARGET)

profiler: profiler.c profiler.bpf.o profiler.skel.h
	$(CC) $(FLAGS) -o profiler profiler.c $(LIBS)

profiler.skel.h: profiler.bpf.o
	$(BPFTOOL) gen skeleton profiler.bpf.o > profiler.skel.h

profiler.bpf.o: profiler.bpf.c
	$(CC_BPF) $(FLAGS_BPF) -c profiler.bpf.c

victim: victim.c
	$(CC) $(FLAGS) -o victim victim.c

victim-mt: victim-mt.c
	$(CC) $(FLAGS) -o victim-mt victim-mt.c

clean:
	rm $(TARGET) profiler.bpf.o profiler.skel.h
