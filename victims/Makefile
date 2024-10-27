CC=clang
FLAGS=-Wall -g
TARGETS=victim victim-mt

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) $(FLAGS) -o $@ $<


clean:
	rm $(TARGETS)
