# yubikey4java

Java code to communicate to a YubiKey.
The code is loosely based on [python-yubico](https://github.com/Yubico/python-yubico).
Communication is done with the [usb4java USB library](https://github.com/usb4java) using libusb1.0.

Currently, only the challenge-response mechanism with Hmac-Sha1 is implemented.

## Use on Windows

According to [this](http://libusb.6.n5.nabble.com/HIDAPI-works-on-Mac-not-on-Windows-td4800748.html), there may be a 
problem to connect a mouse or keyboard device on Windows using the native HID API 
(as used by [hid4java](https://github.com/gary-rowe/hid4java) and [purejavahidapi](https://github.com/nyholku/purejavahidapi) 
among others). 

To avoid this issue, a workaround is to install a driver before you can communicate with the Yubikey 
using libusb [see here](https://github.com/libusb/libusb/wiki/Windows#How_to_use_libusb_on_Windows).
A simple way to do this is using Zadig, an Automated Driver Installer GUI application for WinUSB, libusb-win32 and libusbK.

You must run Zadig as an administrator, select the Yubikey in the drop-down list 
(you may have to click first on Open -> list all devices) and replace the HidUsb driver by the libusb-win32 driver.
*You must replace the driver for Interface 1. If you replace the driver for interface 0, you may be unable 
to configure the Yubikey using the personalization tool and the Yubikey will not be recognized as a keyboard anymore.*

![Zadig](http://i.imgur.com/9vreZ16.png "Zadig config")

## Open issue

With the workaround described above, the code works fine with the Yubikey Neo with VID:0x1050,PID:0x0114 and firmware 3.4.0.
However, the Yubikey with firmware version3.2.0 seems unable to communicate using the libusb library. This is also the case using the python-yubico tool.

The error returned is:
*Exception in thread "main" org.usb4java.LibUsbException: USB error 12: Unable to open USB device: Operation not supported or unimplemented on this platform
	at org.toporin.yubikey4java.YubikeyConnector.main(YubikeyConnector.java:366)*
	
	








