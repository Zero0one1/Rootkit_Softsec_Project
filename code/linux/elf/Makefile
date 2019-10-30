all:
	make setsym

install:
	install setsym /usr/bin/


uninstall:
	rm -rf /usr/bin/setsym


setsym: setsym.c uelf.c
	${CC} -std=c99 setsym.c uelf.c -o setsym


clean:
	rm -f setsym