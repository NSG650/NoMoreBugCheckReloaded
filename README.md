# NoMoreBugCheckReloaded 
Prevent Windows from BSODing no matter what happens!

This time the kernel is patched on boot by an EFI driver instead of an Windows driver.

# Warning
Please do not use this on your main system. Even though I added code to let severe bsods pass through it is not guranteed that it would stop any hardware from getting damaged.
Like all issues in life one should try to resolve it instead of ignoring.
Please try to resolve the BSOD instead of ignoring it by using this tool.

# Usage
Load the EFI driver before booting Windows. Either via the EFI shell or configuring firmware settings.

# Demo


https://github.com/user-attachments/assets/4e8b9b5f-c3b0-41ac-9f6f-167c101b0bcc



# Note
I have not tested this on any other Windows version other than Windows 10 21H2.

### Original Readme
A simple UEFI bootkit made by [NSG650](https://github.com/NSG650) and me.

Credits:
https://github.com/0mWindyBug/WFPCalloutReserach/blob/15d968e93bc7bc85f23e0b7d1dededf65726d3e8/WFPDrivers/WFPEnumDriver/utils.cpp
For FindExport
