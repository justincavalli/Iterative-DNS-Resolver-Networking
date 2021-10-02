CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -std=c11
JAVAC = javac

RESOLVER_SRC = resolver.c
RESOLVER_JAVA_SRC = Resolver.java

all: resolver Resolver.class

resolver: $(RESOLVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^

Resolver.class: $(RESOLVER_JAVA_SRC)
	$(JAVAC) $^

clean:
	$(RM) resolver Resolver.class
