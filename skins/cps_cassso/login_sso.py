## Script (Python) "login_sso"
##title=Login SSO
##parameters=came_from=None

# $Id$

""" Replace the login_form and redirect to the CAS login form.
login_sso should remplace login_form as the "Auto-login page ID"
Cookie Crumbler parameter. """

import urllib

logged_in = context.portal_url() + '/logged_in'
if came_from:
    logged_in += "?came_from=%s" % came_from

url = context.sso.getLoginURL(urllib.quote(logged_in))

context.REQUEST.RESPONSE.redirect(url)
