## Rubeus GUI - Version History

### Version 0.4.2

**Enhancements**

- Added the ability to export brute force results to CSV file
- Improved UI for disabled accounts when AS-REP Roasting
- Improved tooltip explanations

**Bug fixes**

- The option "only find users with AES encryption enabled" on the Kerberoasting tab was not working correctly
- The "supported encryptions" field on the Kerberoasting tab was empty in some scenarios
- When exporting hashes from AS-REP Roasting, error messages were also exported
- If a problem was encountered during initial startup then the process terminated silently without displaying any error message

### Version 0.4.0

**Enhancements**

- Usernames are no longer case sensitive when using AES encryption to request a TGT or when using the Brute Force feature
- Due to the change above, added an option to the Brute Forcer to skip the first AS-REQ without preauth if you want to speed things up but accept usernames being case sensitive
- Improved error messages when kerberoasting or AS-REP roasting

**Bug fixes**

- Requesting TGTs for usernames that contain UTF8 characters
- The option to limit the number of kerberoasting results actually works now
