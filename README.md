# PanGPA_Extractor
Tool to extract username and password of current user from PanGPA in plaintext under Windows

# EDIT 23/12/2024 : Appears fixed in 6.2.6-838, although I couldn't find the issue explicitly marked as solved at https://docs.paloaltonetworks.com/globalprotect/6-2/globalprotect-app-release-notes/globalprotect-addressed-issues

Palo Alto Networks GlobalProtect client queries the GlobalProtect Service for your username and password everytime you log on or refresh the connection.

It appears in memory as paintext - same with the uninstall password and deactivate passcode.

This is a PoC to demonstrate the extraction of the username and password. A full write up can be found over at [shells.systems](https://shells.systems/extracting-plaintext-credentials-from-palo-alto-global-protect/)

![image](https://github.com/user-attachments/assets/d277446a-8678-45c0-b778-5d3364941ba0)

Usage : run the compiled executable. No special privileges required.
