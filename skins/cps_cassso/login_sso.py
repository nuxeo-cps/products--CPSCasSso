##parameters=came_from=None

import urllib

logged_in=context.portal_url() + '/logged_in_sso'
if came_from:
    logged_in += "?came_from=%s" % came_from

url = context.sso.getLoginURL(urllib.quote(logged_in))

context.REQUEST.RESPONSE.redirect(url)
