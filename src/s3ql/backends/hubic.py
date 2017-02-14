from ..logging import logging, QuietError  # Ensure use of custom logger class
from . import swift
from dugong import HTTPConnection, CaseInsensitiveDict
from .common import AuthorizationError, retry
from ..inherit_docstrings import copy_ancestor_docstring
from urllib.parse import urlsplit, urlencode
import re
import urllib.parse
import sys
import threading
import requests
from requests.auth import HTTPBasicAuth
from time import time, strptime, mktime, timezone
import configparser
import os

log = logging.getLogger(__name__)


class Backend(swift.Backend):
    """A backend to store data in Hubic"""

    needs_login = False
    known_options = {'authfile', 'client-id', 'client-secret', 'redirect-uri', 'refresh-token'}

    authfile = None
    client_id = None
    client_secret = None
    redirect_uri = None
    refresh_token = None

    # Hubic endpoints
    token_url = 'https://api.hubic.com/oauth/token'
    auth_url = 'https://api.hubic.com/oauth/auth'
    cred_url = 'https://api.hubic.com/1.0/account/credentials'

    # We don't want to request an access token for each instance,
    # because there is a limit on the total number of valid tokens.
    # This class variable holds the mapping from refresh tokens to
    # access tokens.
    hubic_token = dict()
    os_token = dict()
    _refresh_lock = threading.Lock()

    def __init__(self, storage_url, login=None, password=None,
                 options=None):
        self.client_id = options['client-id']
        self.client_secret = options['client-secret']
        self.redirect_uri = options['redirect-uri']
        self.refresh_token = options['refresh-token']
        super().__init__(storage_url, login, password, options)

    @copy_ancestor_docstring
    def _parse_storage_url(self, storage_url, ssl_context):

        # hubic://<containername>/<prefix>
        hit = re.match(r'^[a-zA-Z0-9]+://'  # Backend
                       r'([^/]+)'  # Containername
                       r'(?:/(.*))?$',  # Prefix
                       storage_url)
        if not hit:
            raise QuietError('Invalid storage URL', exitcode=2)

        container_name = hit.group(1)
        prefix = hit.group(2) or ''

        self.container_name = container_name
        self.prefix = prefix

    def __str__(self):
        return 'Hubic container %s, prefix %s' % (self.container_name, self.prefix)

    def _get_hubic_token(self):

        log.info('Requesting new hubic token')

        payload = {'refresh_token': self.refresh_token,
                   'grant_type': 'refresh_token'}

        log.debug('Refresh access token')

        r = requests.post(self.token_url, payload,
                          auth=HTTPBasicAuth(self.client_id,
                                             self.client_secret),
                          allow_redirects=False)

        if r.status_code != 200:
            raise AuthorizationError(r.json()['error'])

        self.hubic_token = r.json()
        self.hubic_token['expires'] = time() + r.json()['expires_in']

    def _get_os_token(self):

        if not self.hubic_token or self.hubic_token['expires'] <= time():
            # check access_token expired
            log.debug('Access token has expired, try to renew it')
            self._get_hubic_token()

        log.info('Requesting new openstack swift token')

        headers = {'Authorization': 'Bearer ' + self.hubic_token['access_token']}

        # Retrieve storage url and token
        r = requests.get(self.cred_url, headers=headers)

        if r.status_code != 200:
            raise AuthorizationError(r.json()['error'])

        self.os_token = r.json()
        # Extract 'CEST time' from 'expires' return value
        self.os_token['expires'] = mktime(strptime((r.json()['expires'])[:-6],
                                                   '%Y-%m-%dT%H:%M:%S'))
        # Correct with local timezone
        self.os_token['expires'] -= (timezone + 3600)

    @retry
    def _get_conn(self):
        """Obtain connection to server and authentication token"""

        if not self.os_token or self.os_token['expires'] <= time():
            # check access_token expired
            log.debug('Access token has expired, try to renew it')

            # If we reach this point, then the access token must have
            # expired, so we try to get a new one. We use a lock to prevent
            # multiple threads from refreshing the token simultaneously.
            with self._refresh_lock:
                # Don't refresh if another thread has already done so while
                # we waited for the lock.
                self._get_os_token()

        log.debug('started')

        self.auth_token = self.os_token['token']
        o = urlsplit(self.os_token['endpoint'])
        self.auth_prefix = urllib.parse.unquote(o.path)
        if o.scheme == 'https':
            ssl_context = self.ssl_context
        elif o.scheme == 'http':
            ssl_context = None
        else:
            # fall through to scheme used for authentication
            pass

        conn = HTTPConnection(o.hostname, o.port, proxy=self.proxy,
                              ssl_context=ssl_context)
        conn.timeout = int(self.options.get('tcp-timeout', 10))
        return conn
