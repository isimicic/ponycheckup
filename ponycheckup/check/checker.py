# Create your views here.

from django.conf import settings

import socket
from pyasn1.error import PyAsn1Error
import requests
try:
    from OpenSSL.SSL import Error as SSLError
except ImportError:
    # In development, we might not have OpenSSL - it's only needed for SNI
    class SSLError(Exception):
        pass

from .heartbleed import test_heartbleed
from .models import Check


class SecurityChecker(object):
    def run_check(self, url):
        self.session = requests.session()
        self.session.headers = [('User-agent', "Erik's pony checkup - http://ponycheckup.com/")]

        try:
            homepage = self.session.get(url, timeout=7)

            check_record = Check(url=url)

            check_record.hsts_header_found   = self.check_supports_hsts(url)
            check_record.xframe_header_found = True if 'X-Frame-Options' in homepage.headers else False
            check_record.supports_https      = self.check_supports_https(url)
            check_record.heartbleed_vuln     = self.check_heartbleed_vuln(url)

            (check_record.admin_found, check_record.admin_forces_https) = self.check_admin(url)

            (check_record.login_found, check_record.login_forces_https) = self.check_login(url)

            check_record.allows_trace      = self.check_trace(url)
            check_record.runs_debug        = self.check_runs_debug(url)
            check_record.csrf_cookie_found = True if self.find_csrf_cookie() else False

            session_cookie                 = self.find_session_cookie()
            if session_cookie:
                check_record.session_cookie_found    = True
                check_record.session_cookie_secure   = session_cookie.secure
                check_record.session_cookie_httponly = session_cookie.has_nonstandard_attr('httponly')
            else:
                check_record.session_cookie_found    = False

            check_record.update_recommendation_count()
            check_record.save()
            return check_record
        except (requests.RequestException, SSLError, PyAsn1Error) as error:
            return error

    def check_supports_https(self, url):
        try:
            self.session.get(url.replace("http", "https"), timeout=7)
        except:
            return False
        return True

    def check_heartbleed_vuln(self, url):
        try:
            url = url.replace("http://", "").replace("/", "")
            return bool(test_heartbleed(url))
        except socket.error:
            return False

    def check_supports_hsts(self, url):
        try:
            ssltest = self.session.get(url.replace("http", "https"), timeout=7)
        except:
            return False
        return 'Strict-Transport-Security' in ssltest.headers

    def check_runs_debug(self, url):
        data = self.session.get(url+"/[][][][][]-this-tries-to-trigger-404....", timeout=7)
        return "You're seeing this error because you have <code>DEBUG = True</code>" in data.content

    def check_trace(self, url):
        response = self.session.request('TRACE', url, timeout=7)
        return 'Content-Type' in response.headers and response.headers['Content-Type'] == "message/http"

    def check_admin(self, url):
        for admin_url in settings.ADMIN_URLS:
            response = self.session.get('{}/{}'.format(url, admin_url), timeout=7)
            if response.status_code == 200:
                data = response.content.lower()
                admin_found = '"id_username"' in data and ("csrfmiddlewaretoken" in data or "Django" in data or "__admin_media_prefix__" in data)
                return (admin_found, self._response_used_https(response))

        return (False, None)

    def check_login(self, url):
        for login_url in settings.LOGIN_URLS:
            response = self.session.get('{}/{}'.format(url, login_url), timeout=7)
            if response.status_code == 200:
                return (True, self._response_used_https(response))

        return (False, None)

    def _response_used_https(self, response):
        return response.url[:5] == "https"

    def find_session_cookie(self):
        for cookie in self.session.cookies:
            if cookie.name == 'sessionid':
                return cookie
        return False

    def find_csrf_cookie(self):
        for cookie in self.session.cookies:
            if cookie.name == 'csrftoken':
                return cookie
        return False
