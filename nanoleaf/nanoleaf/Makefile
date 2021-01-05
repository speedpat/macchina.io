include $(POCO_BASE)/build/rules/global
include $(POCO_BASE)/OSP/BundleCreator/BundleCreator.make

INCLUDE += -I$(PROJECT_BASE)/nanoleaf/poco-dnssd/include -I$(PROJECT_BASE)/nanoleaf/poco-dnssd/Bonjour/include

objects = BundleActivator

target      = net.speedpat.macchina.nanoleaf
target_libs = PocoOSP PocoUtil PocoJSON PocoXML PocoFoundation PocoNet PocoDNSSD PocoDNSSDBonjour

postbuild = $(SET_LD_LIBRARY_PATH) $(BUNDLE_TOOL) -n$(OSNAME) -a$(OSARCH) -o../bundles NanoLeaf.bndlspec

include $(POCO_BASE)/build/rules/dylib

