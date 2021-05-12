CONTIKI_PROJECT = ifrouter
all: $(CONTIKI_PROJECT)
CONTIKI = ../..

# The BR is either native or embedded, and in the latter case must support SLIP
PLATFORMS_EXCLUDE = nrf52dk z1

#MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
MAKE_ROUTING = MAKE_ROUTING_NULLROUTING

# Include RPL BR module
include $(CONTIKI)/Makefile.dir-variables
#MODULES += $(CONTIKI_NG_SERVICES_DIR)/if-router
# Include webserver module
MODULES_REL += webserver
MODULES_REL += embedded
# Include optional target-specific module
include $(CONTIKI)/Makefile.identify-target
MODULES_REL += $(TARGET)

PROJECT_SOURCEFILES += if-router.c

include $(CONTIKI)/Makefile.include
