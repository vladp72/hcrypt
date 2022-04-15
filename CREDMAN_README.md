# C++ Helper Classes for Windows Credentials Manager a.k.a. Credman or Wincred

The credman.h and credman_ui.h are header only library that provides C++ wrappers for credman API

[MSDN documentation for credman APIs](https://docs.microsoft.com/en-us/windows/win32/api/wincred/)

[Architectural overview of Windows Authentication](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)

[cmdkey.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) is a command line utility for the credman that supports listing, adding and deleting of credentials in the Credential Manager.

Credentials manager allows association of alternative credentials (user name, domain and password) for a target computer name with current [logon session](https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-sessions) . Windows Authentication providers are enlightened about credman. They would load and use these alternative credentials instead of original credentials in the logon session when authenticating on the target.

For example if current user does not have access to a file server you can provide alternative credentials and the next authentication attempt will use them.

```
dir \\server\share
  <access denied>
cmdkey /add:\\server /user:username /pass:password
dir \\server\share
  <returns content>
```

Test function [test_enumirate_all_credentials](https://github.com/vladp72/hcrypt/blob/master/test/credman_tests.cpp) demonstrated how to enumirate all credentials. 

Test functions [test_creds_lifetime and test_credentials](https://github.com/vladp72/hcrypt/blob/master/test/credman_tests.cpp) demonstrated how to add, read and delete credentials. 
