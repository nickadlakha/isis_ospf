FNAME ?= isis_ospf.c
OBJF := $(shell echo $(FNAME)|cut -d'.' -f1)

all:
	gcc -fomit-frame-pointer -O2 $(FNAME) -std=gnu11 -o $(OBJF) -lpthread
debug:
	gcc -fomit-frame-pointer -DDEBUG -O2 $(FNAME) -std=gnu11 -o $(OBJF) -lpthread
testisis:
	perl -e "syswrite(STDOUT, pack('C1498', 0xFF, 1, 2, 0)); sleep(5) && syswrite(STDOUT, pack('Cx1496C', 0x83, 2)) while (1)"|nc localhost 3000
testospf:
		perl -e "syswrite(STDOUT, pack('C1498', 0xFF, 1, 2, 4)); sleep(5) && syswrite(STDOUT, pack('C2nx40C6', 0x02, 0x01, 0x2C, 0x02, 0x00, 0xE0, 0x00, 0x00, 0x05)) while (1)"|nc localhost 7000
clean:
	rm $(OBJF)
