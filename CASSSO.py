# (C) Copyright 2004 Unilog <http://www.unilog.com>
# (C) Copyright 2004 Capgemini <http://www.capgemini.com>
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

""" CAS SSO: 
    Integrate SSO Auth using CAS (http://www.yale.edu/tp/auth/)

$Id$
"""

from base64 import encodestring,decodestring
from urllib import quote, unquote
from AccessControl import ClassSecurityInfo
import Globals
from Globals import HTMLFile,DTMLFile
from zLOG import LOG, ERROR, DEBUG, INFO
import sys
from Products.CMFCore.CMFCorePermissions import View, ManagePortal

from ZPublisher.HTTPRequest import HTTPRequest
from zExceptions import Unauthorized
try:
    from zExceptions import BadRequest
except:
    # pre Zope 2.7
    class BadRequest(Exception):
        pass

from Products.CMFCore.CookieCrumbler import CookieCrumbler, ResponseCleanup
CPSInstaller_Enabled=1
try:
    from Products.CPSInstaller.CPSInstaller import CPSInstaller
except:
    CPSInstaller_Enabled=0
    from Products.CMFCore.ActionsTool import ActionInformation 
    from Products.CMFCore.Expression import Expression
    
from Products.CMFCore.CMFCorePermissions import View
from Products.CMFCore.utils import getToolByName

import urllib
import traceback

# Constants.
ATTEMPT_DISABLED = -1  # Disable cookie crumbler
ATTEMPT_NONE = 0       # No attempt at authentication
ATTEMPT_LOGIN = 1      # Attempt to log in
ATTEMPT_RESUME = 2     # Attempt to resume session

try:
    from zExceptions import Redirect
except ImportError:
    # Pre Zope 2.7
    Redirect = 'Redirect'

## Global var to keep track of site whose acl_user should be patched
gPatchedSiteList4aclu=[]

def setSitePatched(SiteId):
    gPatchedSiteList4aclu.append(SiteId)

def isSitePatched(SiteId):
    #LOG('CAS SSO', DEBUG, 'Patched Site List=%s' % gPatchedSiteList)
    return SiteId in gPatchedSiteList4aclu

###############################################################################
## User Folder Patches

# Hooked identify method:
#------------------------------------------------------------------------------

def identify(self, auth):
    
    LOG('CAS SSO', DEBUG, 'Patched identify auth=%s' % auth)
    LOG('CAS SSO', DEBUG, 'Site : %s ' % self.portal_url.getPortalPath())
    if auth:
        auth=auth.strip()
    
    # if this instance is patched...
    if isSitePatched(self.portal_url.getPortalPath()):
        # 
        LOG('CAS SSO', DEBUG, 'Patched identify auth=%s' % auth)
        # Client certificate auth    
    
        # SSO auth
        if auth and auth.lower().startswith('sso '):
            try:
                uid = decodestring(auth.split(' ')[-1])            
                # XXX call LDAP with uid (pwd should be empty, or dummy)
                name = password = uid
            except:
                raise BadRequest, \
                      'Invalid authentication token --auth: %s' % auth
            LOG('CAS SSO', DEBUG, 'SSO Auth: %s %s'%(name, password))
            return name, password
    else :
        LOG('CAS SSO', DEBUG, 'Not Patched identify !!!!!!!')
        return self.old_identify(auth)
    
    # Basic auth
    if auth and auth.lower().startswith('basic '):
        LOG('CAS SSO',DEBUG, 'decode=%s' % decodestring(auth.split(' ')[-1]))
        try:
            name, password=tuple(
                decodestring(auth.split(' ')[-1]).split(':', 1))
        except:
            LOG('CAS SSO', DEBUG, "exec_info : %s " \
                % str(traceback.format_tb(sys.exc_info()[2]) ))            
            raise BadRequest, \
                  'Invalid basic !!!! authentication token --auth: %s' % (auth)
        LOG('CAS SSO', DEBUG, 'Basic Auth: %s %s'%(name, password))
        return name, password
    else:
        return None, None


# Hooked authenticate method:
#------------------------------------------------------------------------------

def authenticate(self, name, password, request):
    LOG('CAS SSO', DEBUG, 'Patched authenticate : name=%s, password=%s' % \
        (name, password))
    emergency = self._emergency_user
    if name is None:
        return None
    if emergency and name==emergency.getUserName():
        user = emergency
    else:
        user = self.getUser(name)    
    
    # if this instance is patched...
    if isSitePatched(self.portal_url.getPortalPath()):
        
        #LOG("CAS SSO Auth",ERROR,"Users=%s" % self.user_names())
            
        # SSO auth
        if request._auth and request._auth.lower().startswith('sso '):
           if user is not None:
               return user
           else:
               return None

        # Basic auth
        if user is not None and user.authenticate(password, request):
            return user
        else:
            return None

    else:
        # Fall Back to initial method
        return self.old_authenticate(name, password, request)
    


###############################################################################
## CAS SSO : Handle Cookie authentification
##

class CASSSO (CookieCrumbler): 
    
    meta_type = 'CAS SSO'
    security = ClassSecurityInfo()
    
    manage_options = (
        {'label': 'CAS SSO',
         'action': 'manage_CASSSO',
        },     
        ) + CookieCrumbler.manage_options


    security.declareProtected(ManagePortal, 'manage_CASSSO')
    manage_CASSSO = DTMLFile('zmi/manage_CASSSO', globals())

    
    _properties = CookieCrumbler._properties + \
                  (
                    {'id':'sso_server', 'type': 'string', 'mode':'w',
                    'label':'SSO Server DNS Name'},          
                    {'id':'sso_ticket', 'type': 'string', 'mode':'w',
                    'label':'SSO ticket key'},
                    {'id':'sso_extserver', 'type': 'string', 'mode':'w',
                    'label':'SSO Server External DNS Name'},
                    {'id':'sso_WebApp', 'type': 'string', 'mode':'w',
                    'label':'SSO WebApp'},
                    {'id':'sso_login', 'type': 'string', 'mode':'w',
                    'label':'SSO login service'},                  
                    {'id':'sso_logout', 'type': 'string', 'mode':'w',
                    'label':'SSO logout service'},                  
                    {'id':'sso_validate', 'type': 'string', 'mode':'w',
                    'label':'SSO ticket validation service'},                  
                    {'id':'sso_httpport', 'type': 'string', 'mode':'w',
                    'label':'SSO http port'},                  
                    {'id':'sso_httpsport', 'type': 'string', 'mode':'w',
                    'label':'SSO https port'},                  
                    {'id':'sso_exthttpsport', 'type': 'string', 'mode':'w',
                    'label':'External SSO https port'},                  
           
                    )
    
    sso_server='cas.mydomain.com'
    sso_extserver='cas.mydomain.com'
    sso_WebApp='cas'
    sso_httpport='20080'
    sso_httpsport='20443'    
    sso_exthttpsport='20443'  
    sso_login='login'
    sso_logout='logout'
    sso_validate='validate'
    
    cas_session_att='cas_userid' # Session attribute used to store the
                                 # user id
    
    basic_auth = 'Basic Auth'
    sso_auth= 'SSO Auth'
    sso_ticket='ticket'
    
    def __call__(self, container, req):
        ## Flag the request to avoid a 2nd call
        if getattr(req, '_hook', 0) == 1:
            return
        
        req._hook = 1
        
        # Repatch aclu if necessary 
        site_path = self.portal_url.getPortalPath()        
        if not isSitePatched(site_path):
            LOG('CASSSO', DEBUG, '__call__ apply patch')
            self.PatchUserFolder()
            setSitePatched(site_path)
            LOG('CASSSO', DEBUG, '__call__ patch applied')
            
            
        CookieCrumbler.__call__(self, container, req)
    

    ##
    # Returns flags indicating what the user is trying to do.
    #
    def modifyRequest(self, req, resp):                

        if req.__class__ is not HTTPRequest:
            return ATTEMPT_DISABLED
        
        if not req[ 'REQUEST_METHOD' ] in ( 'GET', 'PUT', 'POST' ):
            return ATTEMPT_DISABLED
        
        if req.environ.has_key( 'WEBDAV_SOURCE_PORT' ):
            return ATTEMPT_DISABLED
        
        if req._auth and not getattr(req, '_cookie_auth', 0):
            # Using basic auth.
            return ATTEMPT_DISABLED
        else:
            ## Attempt to Login via SSO CAS
            if req.has_key(self.sso_ticket):
                #raise "debug"
                LOG('CASSSO', DEBUG,
                    'Attempt to login via SSO: %s' % req[self.sso_ticket])
                # use http to Validate ticket as we use the internal address
                validateurl='http://%s:%s/%s/%s' % \
                             (self.sso_server,
                              self.sso_httpport,
                              self.sso_WebApp,
                              self.sso_validate)
                path = req['TraversalRequestNameStack']
                path.reverse()
                path = req['URL'] + '/' + '/'.join(path)
                if req.has_key('came_from'):
                    path += '?came_from=%s' % req['came_from']
                path = quote(path)
                checkparams="?service=%s&%s=%s" % \
                             (path, self.sso_ticket,req[self.sso_ticket])
                validateurl='%s%s' % (validateurl, checkparams)
                LOG('CASSSO', DEBUG, 'SSO Validate send: %s'% validateurl)
                UO=urllib.URLopener()
                UO.proxies={}                
                if validateurl[:5].lower()=='https':
                    casdata = UO.open_https(validateurl)
                else:
                    casdata = UO.open(validateurl)
                test = casdata.readline().strip()
                LOG('CASSSO', DEBUG, 'SSO Validate return: %s'% test)
                if test[:3] == 'yes':
                    # user is validated
                    uid = casdata.readline().strip()
                    LOG('CASSSO', DEBUG, 'SSO User: %s'% uid)
                    
                    ac = encodestring('%s' % uid)
                    setattr(req.SESSION, self.cas_session_att, ac)
                else:
                    # redirect to SSO Login page : Ticket validation failed
                    resp.redirect(self.getLoginURL())
                    return ATTEMPT_NONE

            if hasattr(req.SESSION, self.cas_session_att):
                ac = getattr(req.SESSION, self.cas_session_att)
                req._auth = 'SSO %s' % ac
                req._cookie_auth = 1
                resp._auth = 1
                LOG('CASSSO', DEBUG, 'set _auth = %s ' % req._auth)
                return ATTEMPT_LOGIN
            
                self.delRequestVar(req, self.name_cookie)
                self.delRequestVar(req, self.pw_cookie)
                return ATTEMPT_LOGIN
                            
    security.declarePublic('getLoginURL')
    def getLoginURL(self, came_from=None):
        '''
        Redirects to the login page.
        '''
        # Send to SSO Server if defined
        req = self.REQUEST
        if self.sso_server!='':
            if came_from:
                service = came_from
            else:
                service = self.portal_url() + '/logged_in'
            # force https
            # use external SSO server parameters
            LOG('CASSSO', DEBUG, 'LoginURL redirection '+\
                'service = ' + service)
            return 'https://%s:%s/%s/%s?service=%s' % \
                   (self.sso_extserver,
                    self.sso_exthttpsport,
                    self.sso_WebApp,
                    self.sso_login,
                    service)
            
        if self.auto_login_page:            
            resp = req['RESPONSE']
            iself = getattr(self, 'aq_inner', self)
            parent = getattr(iself, 'aq_parent', None)
            page = getattr(parent, self.auto_login_page, None)
            if page is not None:
                retry = getattr(resp, '_auth', 0) and '1' or ''
                came_from = req.get('came_from', None)
                if came_from is None:
                    came_from = req['URL']                

                page_url = page.absolute_url().split("://")
                
                # https redirection
                LOG('CASSSO', DEBUG, 'https redirection')
                url = 'http://%s?came_from=%s&retry=%s&disable_cookie_login__=1' % (
                    page_url[1], quote(came_from), retry)

                return url
        return None
    
    
    def manage_EditSSOParams(self,REQUEST):
        """ save changes to SSO params """
        UpdateDico=REQUEST.form
        for FieldKey in UpdateDico.keys():
            if FieldKey.startswith("sso_"):
                self._updateProperty(FieldKey,UpdateDico[FieldKey])
        
        message="Saved changes."
        return self.manage_CASSSO(self,REQUEST,manage_tabs_message=message)        
    
    def manage_afterAdd(self, item, container):
        """ """
        # Set Login Action for CPS
        LOG('CASSSO', DEBUG, 'manage_afteradd')
        pm=self.portal_membership
        actions = (
          { 'tool': 'portal_membership',
            'id': 'login',
            'name': 'Login',
            'action': 'string:${portal/sso/getLoginURL}',
            'permission': (View, ),
            'condition': 'not: member',
            'category': 'user',
            'visible': 1,
          },)
        if CPSInstaller_Enabled:
            installer=CPSInstaller(self,product_name = 'CPSDefault')
            installer.deleteActions({'portal_membership':['login',]})
            installer.verifyActions(actions)
        else:
            # Do Action insertion by hand !
            pm=getToolByName(self,"portal_membership")
            idxAI=0
            pmaction_list=pm._actions
            ActionAsTuple=0
            if type(pmaction_list)==type(()):
                ActionAsTuple=1
                pmaction_list=list(pmaction_list)
            for AI in pmaction_list:
                if AI.id=='login':
                    del pmaction_list[idxAI]
                    break
                idxAI=idxAI+1
            newAction=ActionInformation(id='login',
                                        title='Login',
                                        description='Click here to Login'
            , action=Expression(text='string:${portal/sso/getLoginURL}')
            , permissions=(View,)
            , category='user'
            , condition=Expression(text='not: member')
            , visible=1
            )            
            pmaction_list.append(newAction)
            if ActionAsTuple:
                pmaction_list=tuple(pmaction_list)
            pm._actions=pmaction_list
        
        #self.PatchUserFolder()
        
        # Std Cookie Crumber after add : Traverse Hook
        CookieCrumbler.manage_afterAdd(self,item,container)

    def PatchUserFolder(self):
        # Patch UserFolder      
        LOG("CAS SSO", DEBUG, "Verify or apply patch to ACL_USERS")      
        aclu = self.portal_url.getPortalObject().acl_users
        aclu_klass = aclu.__class__        
        site_path = self.portal_url.getPortalPath()        
        patched_Site_List=getattr(aclu_klass,'patched_sites', None)
        if  patched_Site_List is None or type(patched_Site_List)!=type({}):
            LOG("CAS SSO", DEBUG, "Add Hook (patched_sites) to ACL_USERS")
            aclu_klass.patched_sites = {}

            #store old methods
            aclu_klass.old_identify = aclu_klass.identify
            aclu_klass.old_authenticate = aclu_klass.authenticate	    
            #patch
            aclu_klass.identify = identify
            aclu_klass.authenticate = authenticate	    
        else:
            LOG("CAS SSO", DEBUG,
                "PATCHED SITES: %s" % aclu_klass.patched_sites)
        
        #  
        if site_path not in aclu_klass.patched_sites.keys():
            LOG("CAS SSO", DEBUG, "Patching site: %s ...!" % site_path)
            aclu_klass.patched_sites[site_path]=""
        else:
            LOG("CAS SSO", DEBUG, "Site: %s already patched...!" % site_path)
            
    def manage_beforeDelete(self, item, container):
        LOG("CAS SSO", DEBUG, "REMOVE Hook")
        aclu = self.portal_url.getPortalObject().acl_users
        aclu_klass = aclu.__class__
        
        site_path = self.portal_url.getPortalPath()
        if site_path in aclu_klass.patched_sites.keys():
            LOG("CAS SSO", DEBUG, "UnPatching site: %s ...!" % site_path)
            del aclu_klass.patched_sites[site_path]
            if getattr(self,'old_identify',None)!=None:
                aclu_klass.identify = self.old_identify
                aclu_klass.authenticate = self.old_authenticate	    
        else:
            LOG("CAS SSO", DEBUG, "Site: %s was not patched...!" % site_path)

        # Std Cookie Crumber after delete : Traverse Hook
        CookieCrumbler.manage_beforeDelete(self,item,container)
        
        
Globals.InitializeClass(CASSSO)

manage_addCASSSOForm = HTMLFile('zmi/addCASSSO', globals())
manage_addCASSSOForm.__name__ = 'addCASSSO'

# __________________________________________________________________________
def manage_addCASSSO(self, id='sso', REQUEST=None):
    """add the sso object"""
    
    id='sso'
    ob = CASSSO()
    ob.id = id
    self._setObject(id, ob)
    if REQUEST is not None:
        return self.manage_main(self, REQUEST)
