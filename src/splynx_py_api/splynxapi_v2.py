'''Splynx API classes.
'''
# System imports
import hashlib
import hmac
import logging
import pprint
import time
import urllib.parse

from http.client import HTTPConnection

# External imports
import pyphp
import requests

logger = logging.getLogger(__name__)

class SplynxAPIv2:
    '''Splynx REST API v2.
    '''

    def __init__(self, base_url: str, key: str, secret: str) -> None:
        """Constructor.

        Args:
            url (str): Base URL for splynx
            key (str): _description_
            secret (str): _description_

        Returns:
            None
        """
        self._base_url = base_url
        self._api_url = None
        self._key = key
        self._secret = secret
        self._access_token = {}
        self._auth_data = {}
        self._auth_string = ''
        self._timeout = 30             # Timeout in seconds

    def debug_requests_on(self,):
        '''Switches on logging of the requests module.'''
        HTTPConnection.debuglevel = 1

        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    def debug_requests_off(self,):
        '''Switches off logging of the requests module, might be some side-effects'''
        HTTPConnection.debuglevel = 0

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.WARNING)
        root_logger.handlers = []
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.WARNING)
        requests_log.propagate = False

    def _gen_api_url(self, rel_url: str) -> str:
        """Generate API URL.

        Using the base URL generate the

        Args:
            rel_url (str): Relative URL for the specific API call we want.
            base_url (str): _description_

        Returns:
            str: _description_
        """
        msg = f"Call to _gen_api_url -> {rel_url} / {self._base_url} , {self._api_url}"
        logger.debug(msg)
        if self._api_url is None:
            self._api_url = urllib.parse.urljoin(self._base_url, "/api/2.0/")

        # For now remove the leading / in the rel_url as urljoin is seeing:
        # /admin/auth/tokens as an absolute URL, as a result:
        # https://<host>/api/2.0/ being joined to /admin/auth/tokens turning into
        # https://<host>/admin/auth/tokens
        if rel_url[0] == '/':
            rel_url = rel_url[1:]

        final_url = urllib.parse.urljoin(self._api_url, rel_url)
        return final_url

    @staticmethod
    def _get_nonce() -> int:
        """Generate a nonce value used within authentication functions.

        Returns:
            int: nonce value.
        """
        return int(time.time())

    #
    @staticmethod
    def _build_auth_data(key: str, secret: str) -> dict[str,str]:
        """Build auth_data dictionary.

        Calculates the dictionary with the following:
        - key
        - signature
        - nonce

        Args:
            key (str): _description_
            secret (str): _description_

        Returns:
            dict[str,str]: _description_
        """
        nonce = str(SplynxAPIv2._get_nonce())
        hash_obj = hmac.new(
            secret.encode(),
            f"{nonce}{key}".encode(),
            hashlib.sha256
        )
        signature = hash_obj.hexdigest().upper()

        auth_data = {
            'key':       key,
            'signature': signature,
            'nonce':     nonce,
        }

        return auth_data

    def _get_access_token_api_key(self, key: str = None, secret: str = None) -> dict[str,str]:
        """Get an access token (via API key).

        Get an access token if we have none, check for renewal if we do.
        Regardless return the access token needed for a request.

        API docs:
        https://splynx.docs.apiary.io/#introduction/authentication/by-access-token

        Args:
            key (str, optional): _description_. Defaults to None.
            secret (str, optional): _description_. Defaults to None.

        Returns:
            dict[str,str]: _description_
        """
        if key is None:
            key = self._key
        if secret is None:
            secret = self._secret

        if not self._auth_data:
            self._auth_data = self._build_auth_data(key=key,secret=secret)

        req_params = self._auth_data.copy()
        req_params["auth_type"] = "api_key"

        rel_url = '/admin/auth/tokens'
        full_url = self._gen_api_url(rel_url)

        http_response = requests.request(
            'POST',
            url=full_url,
            json=req_params,
            timeout=self._timeout
        )

        # logger.debug(f"Raw access token result:\n{http_response.text}")

        result_data = http_response.json()

        self._access_token = result_data

        return self._access_token['access_token']


    def search_intenet_services(self, **kwargs):
        """Search all internet services by the specified parameters.

        API documentation:
        https://splynx.docs.apiary.io/#reference/services/search-internet-services/list-internet-services-by-parameters

        Args:
            kwags (str):

        Returns:
            _type_: matching services.
        """
        rel_path = '/admin/customers/customer/0/internet-services'
        search_dicts = {'main_attributes': kwargs}
        logger.debug(f"Search dict:\n{pprint.pformat(search_dicts)}")
        search_params = pyphp.http_build_query(search_dicts)
        full_path = f"{self._gen_api_url(rel_path)}?{search_params}"

        access_token = self._get_access_token_api_key()

        http_response = requests.request(
            'GET',
            url=full_path,
            headers={
                'Authorization': f'Splynx-EA (access_token={access_token})',
            },
            timeout=self._timeout,
        )

        return http_response.json()

if __name__ == '__main__':
    import dotenv

    BASIC_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    # Upstream libraries
    logging.getLogger('requests.packages.urllib3').setLevel(logging.DEBUG)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
    # Internal modules
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.basicConfig(level = logging.INFO, format=BASIC_FORMAT)

    logging.info("Start")
    config = dotenv.dotenv_values()

    splynx_h = SplynxAPIv2(
        base_url = config['URL'],
        key      = config['KEY'],
        secret   = config['SECRET'],
    )
    splynx_h.debug_requests_on()

    mac_to_check = config['MAC']

    results = splynx_h.search_intenet_services(mac=mac_to_check)

    logging.info(f"Results:\n{pprint.pformat(results)}")
    logging.info(f"Size of result set: {len(results)}")

    logging.info("Done")
