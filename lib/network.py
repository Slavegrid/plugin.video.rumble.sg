# -*- coding: utf-8 -*-

import ssl
import re
import os
import time
import html
import requests

import xbmc
import xbmcaddon
import xbmcgui
import xbmcvfs

from six.moves import urllib

try:
    import json
except ImportError:
    import simplejson as json

ADDON = xbmcaddon.Addon()

BYPASS_CF_ENABLED = ADDON.getSettingBool('bypassCloudflare')

# Rumble's Cloudflare rules answer the old Windows/Chrome-149.0.0.0 user agent
# with a 403 "Just a moment..." challenge on every page request, which broke all
# browsing. A plain Linux user agent passes.
RUMBLE_USER_AGENT = ('Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 '
                     '(KHTML, like Gecko) Chrome/120 Safari/537.36')

# Only the Cloudflare protected service.php endpoints need a bypass; ordinary
# pages pass with the user agent above.
DEFAULT_FLARESOLVERR_URL = 'http://localhost:8191/v1'

# Disable urllib3's "InsecureRequestWarning: Unverified HTTPS request is being made" warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from urllib3.poolmanager import PoolManager
from requests.adapters import HTTPAdapter

class TLS11HttpAdapter(HTTPAdapter):

    """Transport adapter" that allows us to use TLSv1.1"""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, ssl_version=ssl.PROTOCOL_TLSv1_1
        )


class TLS12HttpAdapter(HTTPAdapter):

    """Transport adapter" that allows us to use TLSv1.2"""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize, block=block, ssl_version=ssl.PROTOCOL_TLSv1_2
        )

reqs = requests.session()
tls_adapters = [TLS12HttpAdapter(), TLS11HttpAdapter()]

def bypass_cloudflare(url, data):

    """
    When active, this method will try to bypass cloudflare
    using either Flaresolverr or Byparr
    """

    xbmc.log("Bypass Cloudflare: attempting")

    try:
        # get stored cookie string
        cookies = ADDON.getSetting('cookies')

        # split cookies into dictionary
        if cookies:
            cookie_dict = json.loads( cookies )
        else:
            cookie_dict = None

        bypass_cf_headers = {"Content-Type": "application/json"}

        timeout = ADDON.getSettingInt('flareSolverrTimeout')

        bypass_cf_data = {
            'url': url,
            'maxTimeout': 1000 * timeout,
            'disableMedia': True,
        }

        if data:
            bypass_cf_data['cmd'] = 'request.post'
            bypass_cf_data['postData'] = urllib.parse.urlencode(data)
        else:
            bypass_cf_data['cmd'] = 'request.get'

        # add authentication cookie
        if cookie_dict and cookie_dict.get( 'u_s', False ):
            bypass_cf_data['cookies'] = [{"name":"u_s","value":cookie_dict[ 'u_s' ]}]

        response = reqs.post(
            ADDON.getSetting('flareSolverrUrl'),
            headers=bypass_cf_headers,
            json=bypass_cf_data,
            verify=False,
            timeout=timeout
        )
        response.raise_for_status()

        js = response.json()

        cookies = {}
        for cookie in js['solution']['cookies']:
            cookies[cookie['name']] = cookie['value']

        if cookie_dict:
            cookie_dict.update( cookies )
        else:
            cookie_dict = cookies

        # set cloudflare cookies
        ADDON.setSetting('cookies', json.dumps(cookie_dict))
        # Set returned user-agent to use with future requests
        ADDON.setSetting('flareSolverrUserAgent', js['solution']['userAgent'])

        return_response = js['solution']['response']

        if '</pre>' in return_response and 'json-formatter-container' in return_response:
            json_body = re.compile(r'<pre>(.*)<\/pre>', re.MULTILINE|re.DOTALL|re.IGNORECASE).findall(return_response)
            if json_body:
                return_response = json_body[0]

        return return_response

    except Exception as err_str:
        dialog = xbmcgui.Dialog()
        dialog.notification("Cloudflare bypass failed", str(err_str), icon=xbmcgui.NOTIFICATION_ERROR)
        xbmc.log("Bypass Cloudflare: failed - " + str(err_str), xbmc.LOGWARNING)
    return False

def request_get( url, data=None, extra_headers=None, redirects=True ):

    """ makes a request """

    try:

        # headers
        my_headers = {
            'Accept-Language': 'en-gb,en;q=0.5',
            'User-Agent': RUMBLE_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Referer': url,
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'DNT': '1',
        }

        # add extra headers
        if extra_headers:
            my_headers.update(extra_headers)

        # if we need to insert flaresolverr useragent
        if BYPASS_CF_ENABLED:
            bypass_cf_useragent = ADDON.getSetting('flareSolverrUserAgent')
            if bypass_cf_useragent:
                my_headers[ 'User-Agent' ] = bypass_cf_useragent

        # get stored cookie string
        cookies = ADDON.getSetting('cookies')

        # split cookies into dictionary
        if cookies:
            cookie_dict = json.loads( cookies )
        else:
            cookie_dict = None

        uri = urllib.parse.urlparse(url)
        domain = uri.scheme + '://' + uri.netloc

        status = 0
        i = 0

        try_to_bypass_cloudflare = BYPASS_CF_ENABLED
        while status != 200 and i < 2:
            # make request
            if data:
                response = reqs.post(url, data=data, headers=my_headers, verify=False, cookies=cookie_dict, timeout=10, allow_redirects=redirects)
            else:
                response = reqs.get(url, headers=my_headers, verify=False, cookies=cookie_dict, timeout=10, allow_redirects=redirects)

            status = response.status_code
            if status != 200:
                if status == 403 and response.headers.get('server', '') == 'cloudflare':
                    if try_to_bypass_cloudflare:
                        result = bypass_cloudflare(url, data)
                        if result:
                            return result

                        # Only attempt to bypass once
                        try_to_bypass_cloudflare = False

                    reqs.mount(domain, tls_adapters[i])
                i += 1

        if response.cookies.get_dict():
            if cookie_dict:
                cookie_dict.update( response.cookies.get_dict() )
            else:
                cookie_dict = response.cookies.get_dict()

            # store cookies
            ADDON.setSetting('cookies', json.dumps(cookie_dict))

        return response.text

    except Exception:
        return ''


def stored_cookies():

    """ Returns the addon's stored Rumble cookies as a dictionary """

    cookies = ADDON.getSetting('cookies')

    if cookies:
        try:
            return json.loads( cookies )
        except Exception:
            return {}

    return {}


def parse_json_body( body ):

    """
    Parses a JSON response body.

    FlareSolverr renders a JSON response in a browser, so it comes back wrapped
    in an HTML <pre> block; unwrap that before parsing.
    """

    if not body:
        return None

    body = body.strip()

    if '<pre>' in body:
        body = body.split( '<pre>', 1 )[1]
        body = body.split( '</pre>', 1 )[0]
        body = html.unescape( body ).strip()
    elif body.startswith('<'):
        start, end = body.find('{'), body.rfind('}')
        if start == -1 or end <= start:
            return None
        body = body[ start:end + 1 ]

    try:
        return json.loads( body )
    except Exception:
        return None


def flaresolverr_get( url ):

    """
    Fetches a URL through FlareSolverr.

    service.php (which serves the subscription feed) answers a JavaScript
    challenge to plain HTTP clients, so it has to be requested by a real
    browser. The stored login cookies are forwarded so the response is the
    signed-in user's own data.
    """

    try:
        cookie_dict = stored_cookies()
        timeout = ADDON.getSettingInt('flareSolverrTimeout') or 60

        payload = {
            'cmd': 'request.get',
            'url': url,
            'maxTimeout': 1000 * timeout,
            'disableMedia': True,
        }

        if cookie_dict:
            payload[ 'cookies' ] = [
                { 'name': name, 'value': value } for name, value in cookie_dict.items()
            ]

        response = reqs.post(
            ADDON.getSetting('flareSolverrUrl') or DEFAULT_FLARESOLVERR_URL,
            headers={ 'Content-Type': 'application/json' },
            json=payload,
            verify=False,
            timeout=timeout + 30
        )
        response.raise_for_status()

        solution = response.json().get( 'solution', {} )

        xbmc.log( 'Rumble: FlareSolverr fetched ' + url )

        return solution.get( 'response', '' )

    except Exception as err_str:
        xbmc.log( 'Rumble: FlareSolverr request failed - ' + str( err_str ), xbmc.LOGWARNING )

    return ''


FEED_CACHE_SECONDS = 300


def feed_cache_file( offset, video_type ):

    """ Path of the cache file for one page of the subscription feed """

    try:
        profile = xbmcvfs.translatePath( ADDON.getAddonInfo('profile') )
    except Exception:
        return ''

    if not profile:
        return ''

    return os.path.join( profile, 'feed_%s_%s.json' % ( offset, video_type or 'all' ) )


def feed_from_cache( cache_file ):

    """ Returns a still fresh cached feed page, otherwise None """

    if not cache_file or not os.path.exists( cache_file ):
        return None

    try:
        if time.time() - os.path.getmtime( cache_file ) > FEED_CACHE_SECONDS:
            return None

        with open( cache_file ) as handle:
            cached = parse_json_body( handle.read() )

        if cached:
            xbmc.log( 'Rumble: subscription feed served from cache' )

        return cached

    except Exception:
        return None


def feed_to_cache( cache_file, feed ):

    """ Stores a feed page so paging back and forth does not re-solve Cloudflare """

    if not cache_file:
        return

    try:
        with open( cache_file, 'w' ) as handle:
            handle.write( json.dumps( feed ) )
    except Exception:
        pass


def subscription_feed( limit=24, offset=0, video_type=None ):

    """
    Returns the signed-in user's Rumble subscription feed as parsed JSON.

    Rumble replaced the server rendered /subscriptions page with a client
    rendered one ("My Feed") that carries no video markup, so the feed is read
    from its data endpoint instead of being scraped. Answers are cached briefly,
    because routing through FlareSolverr costs ~20 seconds.
    """

    params = {
        'api': '7',
        'name': 'user.subscription_feed',
        'options': 'video.full',
        'limit': str( limit ),
        'offset': str( offset ),
    }

    if video_type:
        params[ 'video_type' ] = video_type

    url = 'https://rumble.com/service.php?' + urllib.parse.urlencode( params )
    cache_file = feed_cache_file( offset, video_type )

    cached = feed_from_cache( cache_file )

    if cached:
        return cached

    # service.php is usually Cloudflare challenged, but try directly first: it
    # is far quicker when it is not.
    feed = parse_json_body(
        request_get( url, None, { 'Accept': 'application/json, text/plain, */*' } )
    )

    if not feed:
        feed = parse_json_body( flaresolverr_get( url ) )

    if feed:
        feed_to_cache( cache_file, feed )

    return feed
