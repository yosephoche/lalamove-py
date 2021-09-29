import hashlib
import hmac
import json
import time
import requests

from collections import namedtuple
from datetime import datetime
from enum import Enum
from typing import Tuple, Union

from requests import Response

from lalamove.helpers import snake_to_camel


class Client(object):
    def __init__(self, credentials: Tuple[str, str], sandbox_mode=True):
        self.credentials = credentials
        self.sandbox_mode = sandbox_mode

    @property
    def base_url(self):
        return'https://rest.sandbox.lalamove.com' if self.sandbox_mode else 'https://rest.sandbox.lalamove.com'

    @property
    def verify_ssl(self):
        return not self.sandbox_mode

    @property
    def headers(self):
        return {
            'Accept': 'application/json',
            'Content-type': 'application/json; charset=utf-8',
            'X-LLM-Market': 'SG_SIN',
        }

    def calculate_hash(self, body: str, method: str, path: str):
        key, secret = self.credentials

        timestamp = int(round(time.time() * 1000))
        raw_signature = f"{timestamp}\r\n{method}\r\n{path}\r\n\r\n{body}"

        signature = hmac.new(secret.encode(), raw_signature.encode(), hashlib.sha256).hexdigest()

        return "{key}:{timestamp}:{signature}".format(key=key, timestamp=timestamp, signature=signature)

    def get(self, url_path: str) -> Response:
        url = f"{self.base_url}{url_path}"
        headers = self.headers
        headers['Authorization'] = 'hmac ' + self.calculate_hash('', 'GET', url_path)
        return requests.get(url, headers=self.headers)

    def post(self, url_path: str, payload: Union[dict, namedtuple]) -> Response:
        url = f"{self.base_url}{url_path}"
        body = self._serialize_request(payload)
        headers = self.headers
        headers['Authorization'] = 'hmac ' + self.calculate_hash(body, 'POST', url_path)
        return requests.post(url, data=body)

    def _serialize_request(self, payload) -> str:
        """
        :param payload:
        :return:
        """
        return json.dumps(self._marshal_request(payload))

    def _marshal_request(self, payload) -> dict:
        """
        :param payload:
        :return:
        """
        marshalled = {}
        # 1. Skip all non-public attributes (starts with sunder or dunder)
        # 2. special case to ignore 'index' and 'count' attributes for namedtuples
        if isinstance(payload, dict):
            fields = payload.keys()
        else:
            if len(getattr(payload, '__slots__')) > 0:
                fields = getattr(payload, '__slots__')
            else:
                fields = getattr(payload, '_fields')
        for attr_name in fields:
            attr_val = getattr(payload, attr_name)
            if attr_name == 'en_SG':
                cameled_attr_name = attr_name
            else:
                cameled_attr_name = snake_to_camel(attr_name)
            if isinstance(attr_val, datetime):
                marshalled[cameled_attr_name] = int(attr_val.timestamp())
            elif isinstance(attr_val, Enum):
                marshalled[cameled_attr_name] = attr_val.value
            elif isinstance(attr_val, (int, str, bool, float)):
                marshalled[cameled_attr_name] = attr_val
            elif isinstance(attr_val, list):
                marshalled[cameled_attr_name] = [self._marshal_request(element) for element in attr_val]
            else:
                marshalled[cameled_attr_name] = self._marshal_request(attr_val)
        return marshalled
