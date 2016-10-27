THEOS_DEVICE_IP = 192.168.0.115
TARGET = iphone:latest:8.0
include $(THEOS)/makefiles/common.mk
ARCHS = armv7 arm64
TWEAK_NAME = GetSerialNumber
GetSerialNumber_FILES = Tweak.xm
GetSerialNumber_LDFLAGS = -lMobileGestalt 
include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
