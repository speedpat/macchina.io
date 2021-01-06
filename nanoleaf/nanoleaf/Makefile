include $(POCO_BASE)/build/rules/global
include $(POCO_BASE)/OSP/BundleCreator/BundleCreator.make

INCLUDE += -I$(PROJECT_BASE)/nanoleaf/poco-dnssd/include 

ifeq ($(OSNAME),Linux)
DNSSDLibrary = PocoDNSSDAvahi
INCLUDE += -I$(PROJECT_BASE)/nanoleaf/poco-dnssd/Avahi/include
else
DNSSDLibrary = PocoDNSSDBonjour
INCLUDE += -I$(PROJECT_BASE)/nanoleaf/poco-dnssd/Bonjour/include
endif


objects = BundleActivator

target      = net.speedpat.macchina.nanoleaf
target_libs = PocoOSP PocoUtil PocoJSON PocoXML PocoFoundation PocoNet PocoDNSSD $(DNSSDLibrary)

postbuild = $(SET_LD_LIBRARY_PATH) $(BUNDLE_TOOL) -n$(OSNAME) -a$(OSARCH) -o../bundles NanoLeaf.bndlspec

include $(POCO_BASE)/build/rules/dylib

