# Copyright (c) 2004 Nuxeo SARL <http://nuxeo.com>
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
""" CPS CAS SSO Init
"""

from Products.CMFCore.DirectoryView import registerDirectory

# Allow some methods
from AccessControl import allow_type, allow_class
from AccessControl import ModuleSecurityInfo

ModuleSecurityInfo('urllib').declarePublic('quote')

import CASSSO

registerDirectory('skins', globals())

def initialize(registrar):
    registrar.registerClass(
        CASSSO.CASSSO,
        constructors=(CASSSO.manage_addCASSSOForm,
                      CASSSO.manage_addCASSSO),
        #icon = 'images/cookie.gif'
        )

