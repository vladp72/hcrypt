# C++ Helper Classes for Windows Credentials Manager a.k.a. Credman or Wincred

credman.h and credman_ui.h are header only library that provides C++ wrappers for credman API

[MSDN documentation for credman APIs](https://docs.microsoft.com/en-us/windows/win32/api/wincred/)

[cmdkey.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) is a command line utility for the credman that supports listing, adding and deleting of credentials in the Credential Manager.

Credentials manager allows association of alternative credentials (user name, domain and password) with a target computer name per [logon session](https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-sessionshttps://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-sessions) . Windows Authentication providers