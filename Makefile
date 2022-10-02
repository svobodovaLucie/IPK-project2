# File:          Makefile
# Institution:   FIT BUT
# Academic year: 2021/2022
# Course:        IPK - Computer Communications and Networks
# Author:        Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz
#
# IPK- project 2 (ZETA variant): Packet sniffer

CC=g++
CFLAGS=-Wall -Wextra -g -Werror
LFLAGS=-lpcap
EXEC=ipk-sniffer

all: $(EXEC)

$(EXEC): ipk-sniffer.o
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

ipk-sniffer.o: ipk-sniffer.cpp ipk-sniffer.h
	$(CC) $(CFLAGS) -c $< $(LFLAGS)

clean:
	rm $(EXEC) ipk-sniffer.o

