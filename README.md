# PanGPA_Extractor for v6.2.6-838
Tool to extract username and password of current user from PanGPA in plaintext under Windows

Palo Alto Networks GlobalProtect client queries the GlobalProtect Service for your username and password everytime you log on or refresh the connection.

It appears in memory as paintext - same with the uninstall password and deactivate passcode.

This is a PoC to demonstrate the extraction of the username and password. A full write up can be found over at [shells.systems](https://shells.systems/extracting-plaintext-credentials-from-palo-alto-global-protect/)

![PanGPA2](https://github.com/user-attachments/assets/e2590a23-2eac-477a-a55a-65f2c7d83a78)

Usage : run the compiled executable. No special privileges required.
