# (C) Copyright 2004 Nuxeo SARL <http://nuxeo.com/>
# (C) Copyright 2004 Capgemini <http://.com/>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$
"""
CPS CAS SSO Installer

Howto use the CPS CAS SSO installer :
 - Log into the ZMI as manager
 - Go to your CPS root directory
 - Create an External Method with the following parameters:

     id            : cassso_install (or whatever)
     title         : CPS CAS CPS Install (or whatever)
     Module Name   : CPSCasSso.install
     Function Name : install

 - save it
 - then click on the test tab of this external method
"""

from Products.CPSInstaller.CPSInstaller import CPSInstaller

import Products.CPSCasSso.CASSSO

class CPSCASSSOInstaller(CPSInstaller):

    SKINS = {'cps_cassso': 'Products/CPSCasSso/skins/cps_cassso',
             }

    def install(self):
        self.log("Starting CPSCasSso install")
        self.verifySkins(self.SKINS)
        self.resetSkinCache()
        # update the CPS login page 
        portal = self.portal
        cookie_auth = portal.cookie_authentication
        cookie_auth.auto_login_page = 'login_sso'
        if 'sso' not in portal.objectIds():
            Products.CPSCasSso.CASSSO.manage_addCASSSO(portal)            
        
        self.log("End of specific CPSCasSso install")

def install(self):
    installer = CPSCASSSOInstaller(self, 'CPSCasSso')
    installer.install()
    return installer.logResult()
