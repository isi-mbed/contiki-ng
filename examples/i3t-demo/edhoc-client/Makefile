CONTIKI_PROJECT = edhoc-test-client 

all: $(CONTIKI_PROJECT)

MODULES += /os/net/security/edhoc

CONTIKI = ../../..
MAKE_WITH_OSCORE = 1
WERROR = 0
CFLAGS += -DCOOJA_MTARCH_STACKSIZE=4096

CLFLAG += -Wunused-variable  

#uecc fast execution optimization
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1 


include $(CONTIKI)/Makefile.include
