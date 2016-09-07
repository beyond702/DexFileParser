RM=rm -rf
CC=g++

FLAGS=

#list all .cpp files
SRCS=$(wildcard *.cpp)
#all files patten substitude, from .c to .o
OBJS=$(patsubst %.cpp,%.o,$(SRCS))

all:dexparser

dexparser:$(OBJS)
	$(CC) $(FLAGS) $^ -o $@

%.o:%.cpp
	$(CC) $(FLAGS) -c $< -o $@

clean:
	$(RM) *.o dexparser
