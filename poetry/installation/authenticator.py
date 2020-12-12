import logging
import pathlib
import time
import urllib.parse

from typing import TYPE_CHECKING, Dict, Generator

import requests
import requests.auth
import requests.exceptions

from poetry.exceptions import PoetryException
from poetry.utils.password_manager import PasswordManager
from poetry.utils.helpers import get_cert, get_client_cert


if TYPE_CHECKING:
    from typing import Any
    from typing import Optional
    from typing import Tuple

    from clikit.api.io import IO

    from poetry.config.config import Config


logger = logging.getLogger()


class Authenticator(object):
    def __init__(self, config, io=None):  # type: (Config, Optional[IO]) -> None
        self._config = config
        self._io = io
        self._session = None
        self._credentials = {}
        self._certs = {}
        self._password_manager = PasswordManager(self._config)

    def _log(self, message, level="debug"):  # type: (str, str) -> None
        if self._io is not None:
            self._io.write_line(
                "<{level:s}>{message:s}</{level:s}>".format(
                    message=message, level=level
                )
            )
        else:
            getattr(logger, level, logger.debug)(message)

    @property
    def session(self):  # type: () -> requests.Session
        if self._session is None:
            self._session = requests.Session()

        return self._session

    def request(
        self, method, url, **kwargs
    ):  # type: (str, str, Any) -> requests.Response
        request = requests.Request(method, url)
        username, password = self.get_credentials_for_url(url)

        if username is not None and password is not None:
            request = requests.auth.HTTPBasicAuth(username, password)(request)

        session = self.session
        prepared_request = session.prepare_request(request)

        proxies = kwargs.get("proxies", {})
        stream = kwargs.get("stream")

        certs = self.get_certs_for_url(url)
        verify = kwargs.get("verify", certs.get("verify"))
        cert = kwargs.get("cert", certs.get("cert"))

        settings = session.merge_environment_settings(
            prepared_request.url, proxies, stream, verify, cert
        )

        # Send the request.
        send_kwargs = {
            "timeout": kwargs.get("timeout"),
            "allow_redirects": kwargs.get("allow_redirects", True),
        }
        send_kwargs.update(settings)

        attempt = 0

        while True:
            is_last_attempt = attempt >= 5
            try:
                resp = session.send(prepared_request, **send_kwargs)
            except (requests.exceptions.ConnectionError, OSError) as e:
                if is_last_attempt:
                    raise e
            else:
                if resp.status_code not in [502, 503, 504] or is_last_attempt:
                    resp.raise_for_status()
                    return resp

            if not is_last_attempt:
                attempt += 1
                delay = 0.5 * attempt
                self._log(
                    "Retrying HTTP request in {} seconds.".format(delay), level="debug"
                )
                time.sleep(delay)
                continue

        # this should never really be hit under any sane circumstance
        raise PoetryException("Failed HTTP {} request", method.upper())

    def get_credentials_for_url(
        self, url
    ):  # type: (str) -> Tuple[Optional[str], Optional[str]]
        parsed_url = urllib.parse.urlsplit(url)

        netloc = parsed_url.netloc

        credentials = self._credentials.get(netloc, (None, None))

        if credentials == (None, None):
            if "@" not in netloc:
                credentials = self._get_credentials_for_netloc_from_config(netloc)
            else:
                # Split from the right because that's how urllib.parse.urlsplit()
                # behaves if more than one @ is present (which can be checked using
                # the password attribute of urlsplit()'s return value).
                auth, netloc = netloc.rsplit("@", 1)
                if ":" in auth:
                    # Split from the left because that's how urllib.parse.urlsplit()
                    # behaves if more than one : is present (which again can be checked
                    # using the password attribute of the return value)
                    credentials = auth.split(":", 1)
                else:
                    credentials = auth, None

                credentials = tuple(
                    None if x is None else urllib.parse.unquote(x) for x in credentials
                )

        if credentials[0] is not None or credentials[1] is not None:
            credentials = (credentials[0] or "", credentials[1] or "")

            self._credentials[netloc] = credentials

        return credentials[0], credentials[1]

    def _get_credentials_for_netloc_from_config(
        self, netloc
    ):  # type: (str) -> Tuple[Optional[str], Optional[str]]
        credentials = (None, None)

        for (repository_name, repository_netloc) in self._get_repository_netlocs():
            if netloc == repository_netloc:
                auth = self._password_manager.get_http_auth(repository_name)

                if auth is None:
                    continue

                credentials = (auth["username"], auth["password"])
                break

        return credentials

    def get_certs_for_url(
        self, url
    ):  # type: (str) -> Dict[str, pathlib.PosixPath]
        parsed_url = urllib.parse.urlsplit(url)

        netloc = parsed_url.netloc

        return self._certs.setdefault(
            netloc,
            self._get_certs_for_netloc_from_config(netloc),
        )

    def _get_repository_netlocs(self):  # type: () -> Generator[[str, str], None, None]
        for repository_name in self._config.get("repositories", []):
            repository_config = self._config.get(
                "repositories.{}".format(repository_name)
            )
            if not repository_config:
                continue

            url = repository_config.get("url")
            if not url:
                continue

            parsed_url = urllib.parse.urlsplit(url)
            yield (repository_name, parsed_url.netloc)

    def _get_certs_for_netloc_from_config(
        self, netloc
    ):  # type: (str) -> Dict[str, pathlib.PosixPath]
        certs = dict(cert=None, verify=None)

        for (repository_name, repository_netloc) in self._get_repository_netlocs():
            if netloc == repository_netloc:
                certs['cert'] = get_client_cert(self._config, repository_name)
                certs['verify'] = get_cert(self._config, repository_name)
                break

        return certs
