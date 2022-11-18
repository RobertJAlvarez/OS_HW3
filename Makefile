CC     = gcc
OBJS   = main.o
# -W* for warnings, -g3 for maximum debug, -O3 for maximum optimization
CFLAGS = -Wall -Wextra -Wundef -Wshadow -Wwrite-strings -Wcast-align -Wstrict-prototypes -Waggregate-return -Wpointer-arith -Wcast-equal \
         -Wswitch-default -Wswitch-enum -Wconversion -Wunreachable-code -Wfloat-equal -Wno-visibility -Wno-unused-parameter -g3 -O3

all: main

main: $(OBJS) implementation.o
	$(CC) $(CFLAGS) -o $@ $^

run: main
	./main

# deletes files generated by compilation
clean:
	rm -f *.o main

main.o: main.c implementation.h
implementation.o : implementation.h

