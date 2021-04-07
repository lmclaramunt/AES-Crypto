CC = g++
CFLAGS = -Wall -g -w
RM = rm -f
OBJS = $(subst .cc,.o,$(SRCS))
default: AES

AES: Main.o Sequence.o Block.o State.o Cipher.o
	$(CC) $(CFLAGS) -o AES Main.o Sequence.o Block.o State.o Cipher.o

Main.o: Main.cpp
	$(CC) $(CFLAGS) -c Main.cpp
Sequence.o: Sequence.cpp Sequence.hpp
	$(CC) $(CFLAGS) -c Sequence.cpp
Block.o: Block.cpp Block.hpp
	$(CC) $(CFLAGS) -c Block.cpp
State.o: State.cpp State.hpp
	$(CC) $(CFLAGS) -c State.cpp
Cipher.o: Cipher.cpp Cipher.hpp
	$(CC) $(CFLAGS) -c Cipher.cpp

clean: 
	$(RM) AES *.o *~