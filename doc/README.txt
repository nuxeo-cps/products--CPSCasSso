
CPSCasSso is a Product to plug CPS to a CAS (ITS Central
Authentication Service, http://www.yale.edu/tp/auth/) SSO (Single
Sign-On) system by modifying the Cookie Crumbler.

To use CPSCasSso :

 - Copy it into your Products directory
 - Log into the ZMI as manager
 - Go to your CPS root directory
 - Create an External Method with the following parameters:

     id            : cassso_install (or whatever)
     title         : CPS CAS CPS Install (or whatever)
     Module Name   : CPSCasSso.install
     Function Name : install

 - save it
 - click on the test tab of this external method
 - you now have an sso object in your CPS root. Go there.
 - set the parameters corresponding to your CAS server and save.

Note that your CAS server must be accessible via the HTTP/S protocol
for the users, and HTTP for the CPS.
