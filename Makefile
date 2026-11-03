.PHONY: all
all: libtccd_inject.dylib tccd_control_helper

MODULE_SOURCES := native/tccd_inject.m native/Attribution.m
MODULE_INPUTS := $(MODULE_SOURCES) native/Attribution.h native/ControlProtocol.h

HELPER_SOURCES := native/tccd_control_helper.m native/ControlClient.m \
                  native/ControlBroker.m native/LogRing.m
HELPER_INPUTS := $(HELPER_SOURCES) native/ControlHelper.h native/LogRing.h \
                 native/ControlProtocol.h

COMMON_FLAGS := -fobjc-arc -framework Foundation -lbsm -mmacosx-version-min=15.0 \
                -O2 -Wall -Wextra -Werror
IDENTIFIER := me.cyandev.tcc-bypass

# Build and sign a temporary file so a mapped image is never truncated.
libtccd_inject.dylib: $(MODULE_INPUTS) Makefile
	@set -eu; \
	temporary=$$(mktemp .build-module.XXXXXX); \
	trap 'rm -f "$$temporary"' EXIT HUP INT TERM; \
	/usr/bin/xcrun clang -arch arm64e $(COMMON_FLAGS) -dynamiclib \
		-o "$$temporary" $(MODULE_SOURCES); \
	/usr/bin/codesign --force --sign - --identifier $(IDENTIFIER) "$$temporary"; \
	chmod 755 "$$temporary"; \
	mv -f "$$temporary" "$@"

tccd_control_helper: $(HELPER_INPUTS) Makefile
	@set -eu; \
	temporary=$$(mktemp .build-helper.XXXXXX); \
	trap 'rm -f "$$temporary"' EXIT HUP INT TERM; \
	/usr/bin/xcrun clang -arch arm64 $(COMMON_FLAGS) \
		-Wno-deprecated-declarations \
		-o "$$temporary" $(HELPER_SOURCES); \
	/usr/bin/codesign --force --sign - --identifier $(IDENTIFIER) "$$temporary"; \
	chmod 755 "$$temporary"; \
	mv -f "$$temporary" "$@"
