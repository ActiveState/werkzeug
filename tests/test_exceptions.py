"""
    tests.exceptions
    ~~~~~~~~~~~~~~~~

    The tests for the exception classes.

    TODO:

    -   This is undertested.  HTML is never checked

    :copyright: 2007 Pallets
    :license: BSD-3-Clause
"""
from datetime import datetime

import pytest

from werkzeug import exceptions
from werkzeug.datastructures import WWWAuthenticate
from werkzeug.wrappers import Response


def test_proxy_exception():
    orig_resp = Response("Hello World")
    with pytest.raises(exceptions.HTTPException) as excinfo:
        exceptions.abort(orig_resp)
    resp = excinfo.value.get_response({})
    assert resp is orig_resp
    assert resp.get_data() == b"Hello World"


@pytest.mark.parametrize(
    "test",
    [
        (exceptions.BadRequest, 400),
        (exceptions.Unauthorized, 401, 'Basic "test realm"'),
        (exceptions.Forbidden, 403),
        (exceptions.NotFound, 404),
        (exceptions.MethodNotAllowed, 405, ["GET", "HEAD"]),
        (exceptions.NotAcceptable, 406),
        (exceptions.RequestTimeout, 408),
        (exceptions.Gone, 410),
        (exceptions.LengthRequired, 411),
        (exceptions.PreconditionFailed, 412),
        (exceptions.RequestEntityTooLarge, 413),
        (exceptions.RequestURITooLarge, 414),
        (exceptions.UnsupportedMediaType, 415),
        (exceptions.UnprocessableEntity, 422),
        (exceptions.Locked, 423),
        (exceptions.InternalServerError, 500),
        (exceptions.NotImplemented, 501),
        (exceptions.BadGateway, 502),
        (exceptions.ServiceUnavailable, 503),
    ],
)
def test_aborter_general(test):
    exc_type = test[0]
    args = test[1:]

    with pytest.raises(exc_type) as exc_info:
        exceptions.abort(*args)
    assert type(exc_info.value) is exc_type


def test_aborter_custom():
    myabort = exceptions.Aborter({1: exceptions.NotFound})
    pytest.raises(LookupError, myabort, 404)
    pytest.raises(exceptions.NotFound, myabort, 1)

    myabort = exceptions.Aborter(extra={1: exceptions.NotFound})
    pytest.raises(exceptions.NotFound, myabort, 404)
    pytest.raises(exceptions.NotFound, myabort, 1)


def test_exception_repr():
    exc = exceptions.NotFound()
    assert str(exc) == (
        "404 Not Found: The requested URL was not found on the server."
        " If you entered the URL manually please check your spelling"
        " and try again."
    )
    assert repr(exc) == "<NotFound '404: Not Found'>"

    exc = exceptions.NotFound("Not There")
    assert str(exc) == "404 Not Found: Not There"
    assert repr(exc) == "<NotFound '404: Not Found'>"

    exc = exceptions.HTTPException("An error message")
    assert str(exc) == "??? Unknown Error: An error message"
    assert repr(exc) == "<HTTPException '???: Unknown Error'>"


def test_method_not_allowed_methods():
    exc = exceptions.MethodNotAllowed(["GET", "HEAD", "POST"])
    h = dict(exc.get_headers({}))
    assert h["Allow"] == "GET, HEAD, POST"
    assert "The method is not allowed" in exc.get_description()


def test_unauthorized_www_authenticate():
    basic = WWWAuthenticate()
    basic.set_basic("test")
    digest = WWWAuthenticate()
    digest.set_digest("test", "test")

    exc = exceptions.Unauthorized(www_authenticate=basic)
    h = dict(exc.get_headers({}))
    assert h["WWW-Authenticate"] == str(basic)

    exc = exceptions.Unauthorized(www_authenticate=[digest, basic])
    h = dict(exc.get_headers({}))
    assert h["WWW-Authenticate"] == ", ".join((str(digest), str(basic)))

    exc = exceptions.Unauthorized()
    h = dict(exc.get_headers({}))
    assert "WWW-Authenticate" not in h


def test_response_header_content_type_should_contain_charset():
    exc = exceptions.HTTPException("An error message")
    h = exc.get_response({})
    assert h.headers["Content-Type"] == "text/html; charset=utf-8"


@pytest.mark.parametrize(
    ("cls", "value", "expect"),
    [
        (exceptions.TooManyRequests, 20, "20"),
        (
            exceptions.ServiceUnavailable,
            datetime(2020, 1, 4, 18, 52, 16),
            "Sat, 04 Jan 2020 18:52:16 GMT",
        ),
    ],
)
def test_retry_after_mixin(cls, value, expect):
    e = cls(retry_after=value)
    h = dict(e.get_headers({}))
    assert h["Retry-After"] == expect


@pytest.mark.parametrize(
    "cls",
    [
        exceptions.HTTPException,
        exceptions.BadRequest,
        exceptions.ClientDisconnected,
        exceptions.SecurityError,
        exceptions.BadHost,
        exceptions.Unauthorized,
        exceptions.Forbidden,
        exceptions.NotFound,
        exceptions.MethodNotAllowed,
        exceptions.NotAcceptable,
        exceptions.RequestTimeout,
        exceptions.Conflict,
        exceptions.Gone,
        exceptions.LengthRequired,
        exceptions.PreconditionFailed,
        exceptions.RequestEntityTooLarge,
        exceptions.RequestURITooLarge,
        exceptions.UnsupportedMediaType,
        exceptions.RequestedRangeNotSatisfiable,
        exceptions.ExpectationFailed,
        exceptions.ImATeapot,
        exceptions.UnprocessableEntity,
        exceptions.Locked,
        exceptions.FailedDependency,
        exceptions.PreconditionRequired,
        exceptions.TooManyRequests,
        exceptions.RequestHeaderFieldsTooLarge,
        exceptions.UnavailableForLegalReasons,
        exceptions.InternalServerError,
        exceptions.NotImplemented,
        exceptions.BadGateway,
        exceptions.ServiceUnavailable,
        exceptions.GatewayTimeout,
        exceptions.HTTPVersionNotSupported,
    ],
)
def test_passing_response(cls):
    dummy_mimetype = "application/x-dummy"

    class TestResponse(Response):
        default_mimetype = dummy_mimetype

    exc = cls(response=TestResponse("dummy"))
    rp = exc.get_response({})
    assert rp.content_type == dummy_mimetype
    assert isinstance(rp, TestResponse)
