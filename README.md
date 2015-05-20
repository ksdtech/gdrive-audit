gdrive-audit
============

Attempt to generate report of all files shared by a Google Apps users to 
"anyone" or to users outside a list of whitelisted domains.

Requirements
------------

- Python 2.7
- PyYAML
- (modified) PyDrive package for Google authentication.
- PyCrypto 

PyDrive modifications
---------------------

Use "Domain-Wide Delegation of Authority" to access
arbitrary accounts, not just the logged in user.  Details are here:

https://developers.google.com/drive/web/delegation

We use new Auth method added to my fork of PyDrive to get an access token
that is valid for the GDrive account of a "sub user":

- gauth.ServiceAccountAuth(sub\_user)

We also use new settings in settings.yaml:

- service\_account: {{bool}} - True to use service account credentials
- service\_account\_config\_file: {{str}} - service account JSON key file
  (contains email and private key)
- service\_account\_email: {{str}} - email address, like xxx@developer.gserviceaccount.com
- service\_account\_key\_file: {{str}} - path to .p12 file containing private key

You need to get the service account .p12 file, and 
service account email address from the developer console, and adjust
the settings.yaml file for this.  If these parameters are incorrect,
you will get an "invalid grant" access token error.


Domain Access for Service Account
---------------------------------

You also have to grant permission in the domain for 3rd party access.
If you don't allow the scopes for your application, you will get an
"access denied" access token error. You go to the Security area of
your GAFE domain console, click Advanced settings, then click 
Manage OAuth Client Access in the Authentication area.

In the Client Name box, enter the Client ID for the service account, like:

    xxx.apps.googleusercontent.com

In the One or More API Scopes, use the same scopes specified in the
settings.yaml file:

    https://www.googleapis.com/auth/userinfo.email,
    https://www.googleapis.com/auth/drive,
    https://www.googleapis.com/auth/drive.file,
    https://www.googleapis.com/auth/drive.readonly,
    https://www.googleapis.com/auth/drive.metadata.readonly,
    https://www.googleapis.com/auth/drive.appdata

    
Click the Authorize button.

