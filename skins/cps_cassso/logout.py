## Script (Python) "logout"
##title=Logout handler
##parameters=
REQUEST = context.REQUEST
if REQUEST.has_key('portal_skin'):
    context.portal_skins.clearSkinCookie()
REQUEST.RESPONSE.expireCookie('__ac', path='/')

# expire session to logout from CPS
context.browser_id_manager.flushBrowserIdCookie()
# expire CAS cookie to logout from CAS
REQUEST.RESPONSE.expireCookie('CASTGC', path='/')

return REQUEST.RESPONSE.redirect(REQUEST.URL1+'/logged_out')
