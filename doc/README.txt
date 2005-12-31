================
CPSCasSso README
================

:Revision: $Id$

.. sectnum::    :depth: 4
.. contents::   :depth: 4


CPSCasSso is a Product to plug CPS to a CAS (ITS Central
Authentication Service, http://www.yale.edu/tp/auth/) SSO (Single
Sign-On) system by modifying the Cookie Crumbler.

To use CPSCasSso:

1. Copy it into your Products directory.

2. Log into the ZMI as manager.

3. Go to your CPS root directory.

4. Create an External Method with the following parameters::

       id            : cassso_install (or whatever)
       title         : CPS CAS CPS Install (or whatever)
       Module Name   : CPSCasSso.install
       Function Name : install

5. Save it.

6. Click on the test tab of this external method.

7. You now have an SSO object in your CPS root. Go there.

8. Set the parameters corresponding to your CAS server and save.

Note that your CAS server must be accessible via the HTTP/S
protocol for the users, and HTTP for the CPS.


.. Emacs
.. Local Variables:
.. mode: rst
.. End:
.. Vim
.. vim: set filetype=rst:

