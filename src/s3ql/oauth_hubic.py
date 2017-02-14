from .logging import logging, setup_logging, QuietError
from .parse_args import ArgumentParser
import sys
import textwrap
import requests
from requests.auth import HTTPBasicAuth
from urllib import parse

log = logging.getLogger(__name__)

token_url = 'https://api.hubic.com/oauth/token'
auth_url = 'https://api.hubic.com/oauth/auth'
cred_url = 'https://api.hubic.com/1.0/account/credentials'


def parse_args(args):
    """Parse command line"""

    parser = ArgumentParser(
        description=textwrap.dedent('''\
        Obtain OAuth2 refresh token for Hubic
        '''))

    parser.add_debug()
    parser.add_quiet()
    parser.add_version()

    return parser.parse_args(args)


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    options = parse_args(args)
    setup_logging(options)

    # Request client app creds
    client_id = input('Client id: ')
    client_secret = input('Secret client: ')
    redirect_uri = input('Redirection domain: ')

    # Authorization request
    data = {'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': 'usage.r,account.r,getAllLinks.r,credentials.r,activate.w,links.drw',
            'response_type': 'code',
            'state': 'none'}

    log.debug('Request authorization code')

    print('Please open %s?%s in your browser' % (auth_url, parse.urlencode(data)))
    oauth_code = input('OAuth2 Code: ')

    data = {'code': oauth_code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'}

    log.debug('Request access token')

    r = requests.post(token_url, data,
                      auth=HTTPBasicAuth(client_id, client_secret),
                      allow_redirects=False)

    resp_json = r.json()

    if r.status_code != 200:
        raise QuietError('Authentication failed: ' + resp_json['error'])

    try:
        refresh_token = resp_json['refresh_token']

    except:
        raise QuietError('Something wrong has happened when requesting access token')

    print('Success. Your refresh token for Hubic is:\n',
          refresh_token)