CONTIKI_PROJECT = edhoc-test-server

all: $(CONTIKI_PROJECT)

MODULES += /os/net/security/edhoc

# Include CoAP resources
MODULES_REL += ./resources
MODULES_REL += $(TARGET)

#uecc fast execution optimization
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1 

CONTIKI = ../../..

MAKE_WITH_OSCORE = 1
WERROR = 0
CFLAGS += -DCOOJA_MTARCH_STACKSIZE=4096
#CFLAGS += -Wvla
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router
# Include webserver module
MODULES_REL += webserver
MODULES_REL +=  ../../rpl-border-router/webserver



# Include optional target-specific module
include $(CONTIKI)/Makefile.identify-target
MODULES_REL += $(TARGET)



include $(CONTIKI)/Makefile.include
