pyAndriller
===========

Andriller performs read-only, forensically sound, non-destructive acquisition from (rooted) Android devices. The executable is run from a terminal or by executing directly; it produces results in the terminal window, and a report in a HTML format.

# Usage:

Connect an Android device by a USB cable, have USB Debugging enabled; execute Andriller:

$ ./Andriller.py

for Windows (must have Python 3.x installed):
python Andriller.py
Andriller should run, download any data, and decode it all at once. Content download is supported for rooted devices only.

Note: Android version 4.2.2+ requires to authorise the PC to accept RSA fingerprint. Please do so, and tick the box to remember for future. 
Note: Devices with Superuser or SuperSU App require to authorise root access from an unlocked screen. Please grand permissions if requested.

# Description:

Once andriller is executed, it will produce permilinary results in the terminal window; for rooted devices it will download and decode the content automatically. It will produce a new folder in the location where it was executed, where the main "REPORT.html" file can be opened in a web browser.

# Supported data extraction:

adb serial, shell permissions, device manufacturer/model, IMEI, Android version, build number, Wifi mac, Bluetooth mac, Bluetooth name, Last known GPS location, Time & Date, Synchronised Accounts, SIM card ICCID/MSISDN/Carrier (not all devices supported, mainly SGS#);

For rooted devices only: Pattern lock, PIN lock (up to 4 digits only), Contacts, Call logs, SMS messages, WhatsApp App (contacts, messages), Facebook App (messages, viewed photographs).

# Disclaimer:

Andriller comes with absolutely no warranty. Even though Andriller was written in a way to be a forensically sound read-only utility, I do not take any responsibility to any damage or harm caused to your computer systems or your Android devices, which may be believed to have been caused by executing Andriller. I also do not take any responsibility of any unsolicited, non-consensual or unlawful misuses of this utility. It is the end user's responsibility to believe an appropriate consent or a lawful excuse was obtained if the utility is used with an other's Android devices, and they are aware what the utility does.

# Troubleshooting:

For andriller to work, you may need the following packages to be installed (if not already installed): adb. You can install them manually.

For Ubuntu (depending on distribution, must enable 'universe' in software sources first, and/or add this PPA for latest adb version):
$ sudo add-apt-repository ppa:phablet-team/tools && sudo apt-get update

$ sudo apt-get install android-tools-adb

For Fedora:
$ sudo yum install adb

For openSUSE:
$ sudo yast -i android-tools
For Android devices with version 4.2.2+, the latest adb version is required (version 1.0.31). Check which version you have installed: adb version
