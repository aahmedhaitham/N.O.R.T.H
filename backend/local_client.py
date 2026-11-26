"""Open an explicit, short-lived client session with a loopback NORTH API."""

from http.cookies import SimpleCookie
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def local_session(base):
    url = urlsplit(base)
    if (url.scheme not in ("http", "https") or url.hostname not in ("localhost", "127.0.0.1", "::1")
            or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment):
        raise ValueError("The local NORTH API must use a loopback address.")
    opener = build_opener(NoRedirect())
    request = Request(base.rstrip("/") + "/api/local-session", method="POST",
                      headers={"X-North-Local-Session": "start"})
    with opener.open(request, timeout=10) as response:
        cookies = SimpleCookie(response.headers.get("Set-Cookie", ""))
    if "north_local_session" not in cookies:
        raise ValueError("NORTH did not establish a local session.")
    opener.addheaders = [("Cookie", "north_local_session=" + cookies["north_local_session"].coded_value)]
    return opener
