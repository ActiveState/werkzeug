import functools
import json
import typing as t
import warnings
from datetime import datetime
from io import BytesIO

from .._internal import _to_str
from .._internal import _wsgi_decoding_dance
from ..datastructures import Accept
from ..datastructures import Authorization
from ..datastructures import CharsetAccept
from ..datastructures import CombinedMultiDict
from ..datastructures import EnvironHeaders
from ..datastructures import ETags
from ..datastructures import FileStorage
from ..datastructures import Headers
from ..datastructures import HeaderSet
from ..datastructures import IfRange
from ..datastructures import ImmutableList
from ..datastructures import ImmutableMultiDict
from ..datastructures import iter_multi_items
from ..datastructures import LanguageAccept
from ..datastructures import MIMEAccept
from ..datastructures import MultiDict
from ..datastructures import Range
from ..datastructures import RequestCacheControl
from ..formparser import default_stream_factory
from ..formparser import FormDataParser
from ..http import parse_accept_header
from ..http import parse_authorization_header
from ..http import parse_cache_control_header
from ..http import parse_cookie
from ..http import parse_date
from ..http import parse_etags
from ..http import parse_if_range_header
from ..http import parse_list_header
from ..http import parse_options_header
from ..http import parse_range_header
from ..http import parse_set_header
from ..urls import url_decode
from ..useragents import UserAgent
from ..utils import cached_property
from ..utils import environ_property
from ..utils import header_property
from ..wsgi import get_content_length
from ..wsgi import get_current_url
from ..wsgi import get_host
from ..wsgi import get_input_stream
from werkzeug.exceptions import BadRequest

if t.TYPE_CHECKING:
    from wsgiref.types import WSGIApplication
    from wsgiref.types import WSGIEnvironment


class _SansIORequest:
    """Represents the non-IO parts of a HTTP request, including the
    method, URL info, and headers.

    This class is not meant for general use. It should only be used when
    implementing WSGI, ASGI, or another HTTP application spec. Werkzeug
    provides a WSGI implementation at :cls:`werkzeug.wrappers.Request`.

    :param method: The method the request was made with, such as GET.
    :param path: The path part of the URL, without the query string.
    :param query_string: The optional portion of the URL after the "?".
    :param headers: The headers received with the request.
    :param scheme: The protocol the request used, such as HTTP or WS.
    :param remote_addr: Address of the client sending the request.
    :param root_path: Prefix that the application is mounted under. This
        is prepended to generated URLs, but is not part of route
        matching.

    .. versionadded:: 2.0
    """

    #: the charset for the request, defaults to utf-8
    charset = "utf-8"

    #: the error handling procedure for errors, defaults to 'replace'
    encoding_errors = "replace"

    #: the class to use for `args` and `form`.  The default is an
    #: :class:`~werkzeug.datastructures.ImmutableMultiDict` which supports
    #: multiple values per key.  alternatively it makes sense to use an
    #: :class:`~werkzeug.datastructures.ImmutableOrderedMultiDict` which
    #: preserves order or a :class:`~werkzeug.datastructures.ImmutableDict`
    #: which is the fastest but only remembers the last key.  It is also
    #: possible to use mutable structures, but this is not recommended.
    #:
    #: .. versionadded:: 0.6
    parameter_storage_class: t.Type[MultiDict] = ImmutableMultiDict

    #: The type to be used for dict values from the incoming WSGI
    #: environment. (For example for :attr:`cookies`.) By default an
    #: :class:`~werkzeug.datastructures.ImmutableMultiDict` is used.
    #:
    #: .. versionchanged:: 1.0.0
    #:     Changed to ``ImmutableMultiDict`` to support multiple values.
    #:
    #: .. versionadded:: 0.6
    dict_storage_class: t.Type[MultiDict] = ImmutableMultiDict

    #: the type to be used for list values from the incoming WSGI environment.
    #: By default an :class:`~werkzeug.datastructures.ImmutableList` is used
    #: (for example for :attr:`access_list`).
    #:
    #: .. versionadded:: 0.6
    list_storage_class: t.Type[t.List] = ImmutableList

    def __init__(
        self,
        method: str,
        path: str,
        query_string: bytes,
        headers: Headers,
        scheme: str,
        remote_addr: t.Optional[str],
        root_path: str,
    ) -> None:
        self.method = method.upper()
        self.path = "/" + path.lstrip("/")
        self.query_string = query_string
        self.headers = headers
        self.scheme = scheme
        self.remote_addr = remote_addr
        self.root_path = root_path.rstrip("/")

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.path} [{self.method}]>"

    @property
    def url_charset(self) -> str:
        """The charset that is assumed for URLs. Defaults to the value
        of :attr:`charset`.

        .. versionadded:: 0.6
        """
        return self.charset

    @cached_property
    def args(self) -> "MultiDict[str, str]":
        """The parsed URL parameters (the part in the URL after the question
        mark).

        By default an
        :class:`~werkzeug.datastructures.ImmutableMultiDict`
        is returned from this function.  This can be changed by setting
        :attr:`parameter_storage_class` to a different type.  This might
        be necessary if the order of the form data is important.
        """
        return url_decode(
            self.query_string,
            self.url_charset,
            errors=self.encoding_errors,
            cls=self.parameter_storage_class,
        )

    @cached_property
    def access_route(self) -> t.List[str]:
        """If a forwarded header exists this is a list of all ip addresses
        from the client ip to the last proxy server.
        """
        if "X-Forwarded-For" in self.headers:
            return self.list_storage_class(
                parse_list_header(self.headers["X-Forwarded-For"])
            )
        elif self.remote_addr is not None:
            return self.list_storage_class([self.remote_addr])
        return self.list_storage_class()

    @cached_property
    def full_path(self) -> str:
        """Requested path, including the query string."""
        return f"{self.path}?{_to_str(self.query_string, self.url_charset)}"

    @property
    def is_secure(self) -> bool:
        "`True` if the request is secure."
        return self.scheme in {"https", "wss"}

    @cached_property
    def cookies(self) -> "ImmutableMultiDict[str, str]":
        """A :class:`dict` with the contents of all cookies transmitted with
        the request."""
        return parse_cookie(  # type: ignore
            self.headers.get("Cookie"),
            self.charset,
            self.encoding_errors,
            cls=self.dict_storage_class,
        )

    # Common Descriptors

    content_type = header_property[str](
        "Content-Type",
        doc="""The Content-Type entity-header field indicates the media
        type of the entity-body sent to the recipient or, in the case of
        the HEAD method, the media type that would have been sent had
        the request been a GET.""",
        read_only=True,
    )

    @cached_property
    def content_length(self) -> t.Optional[int]:
        """The Content-Length entity-header field indicates the size of the
        entity-body in bytes or, in the case of the HEAD method, the size of
        the entity-body that would have been sent had the request been a
        GET.
        """
        return get_content_length(self.headers)

    content_encoding = header_property[str](
        "Content-Encoding",
        doc="""The Content-Encoding entity-header field is used as a
        modifier to the media-type. When present, its value indicates
        what additional content codings have been applied to the
        entity-body, and thus what decoding mechanisms must be applied
        in order to obtain the media-type referenced by the Content-Type
        header field.

        .. versionadded:: 0.9""",
        read_only=True,
    )
    content_md5 = header_property[str](
        "Content-MD5",
        doc="""The Content-MD5 entity-header field, as defined in
        RFC 1864, is an MD5 digest of the entity-body for the purpose of
        providing an end-to-end message integrity check (MIC) of the
        entity-body. (Note: a MIC is good for detecting accidental
        modification of the entity-body in transit, but is not proof
        against malicious attacks.)

        .. versionadded:: 0.9""",
        read_only=True,
    )
    referrer = header_property[str](
        "Referer",
        doc="""The Referer[sic] request-header field allows the client
        to specify, for the server's benefit, the address (URI) of the
        resource from which the Request-URI was obtained (the
        "referrer", although the header field is misspelled).""",
        read_only=True,
    )
    date = header_property(
        "Date",
        None,
        parse_date,
        doc="""The Date general-header field represents the date and
        time at which the message was originated, having the same
        semantics as orig-date in RFC 822.""",
        read_only=True,
    )
    max_forwards = header_property(
        "Max-Forwards",
        None,
        int,
        doc="""The Max-Forwards request-header field provides a
        mechanism with the TRACE and OPTIONS methods to limit the number
        of proxies or gateways that can forward the request to the next
        inbound server.""",
        read_only=True,
    )

    def _parse_content_type(self) -> None:
        if not hasattr(self, "_parsed_content_type"):
            self._parsed_content_type = parse_options_header(
                self.headers.get("Content-Type", "")
            )

    @property
    def mimetype(self) -> str:
        """Like :attr:`content_type`, but without parameters (eg, without
        charset, type etc.) and always lowercase.  For example if the content
        type is ``text/HTML; charset=utf-8`` the mimetype would be
        ``'text/html'``.
        """
        self._parse_content_type()
        return self._parsed_content_type[0].lower()

    @property
    def mimetype_params(self) -> t.Dict[str, str]:
        """The mimetype parameters as dict.  For example if the content
        type is ``text/html; charset=utf-8`` the params would be
        ``{'charset': 'utf-8'}``.
        """
        self._parse_content_type()
        return self._parsed_content_type[1]

    @cached_property
    def pragma(self) -> HeaderSet:
        """The Pragma general-header field is used to include
        implementation-specific directives that might apply to any recipient
        along the request/response chain.  All pragma directives specify
        optional behavior from the viewpoint of the protocol; however, some
        systems MAY require that behavior be consistent with the directives.
        """
        return parse_set_header(self.headers.get("Pragma", ""))

    # Accept

    @cached_property
    def accept_mimetypes(self) -> MIMEAccept:
        """List of mimetypes this client supports as
        :class:`~werkzeug.datastructures.MIMEAccept` object.
        """
        return parse_accept_header(self.headers.get("Accept"), MIMEAccept)

    @cached_property
    def accept_charsets(self) -> CharsetAccept:
        """List of charsets this client supports as
        :class:`~werkzeug.datastructures.CharsetAccept` object.
        """
        return parse_accept_header(self.headers.get("Accept-Charset"), CharsetAccept)

    @cached_property
    def accept_encodings(self) -> Accept:
        """List of encodings this client accepts.  Encodings in a HTTP term
        are compression encodings such as gzip.  For charsets have a look at
        :attr:`accept_charset`.
        """
        return parse_accept_header(self.headers.get("Accept-Encoding"))

    @cached_property
    def accept_languages(self) -> LanguageAccept:
        """List of languages this client accepts as
        :class:`~werkzeug.datastructures.LanguageAccept` object.

        .. versionchanged 0.5
           In previous versions this was a regular
           :class:`~werkzeug.datastructures.Accept` object.
        """
        return parse_accept_header(self.headers.get("Accept-Language"), LanguageAccept)

    # ETag

    @cached_property
    def cache_control(self) -> RequestCacheControl:
        """A :class:`~werkzeug.datastructures.RequestCacheControl` object
        for the incoming cache control headers.
        """
        cache_control = self.headers.get("Cache-Control")
        return parse_cache_control_header(cache_control, None, RequestCacheControl)

    @cached_property
    def if_match(self) -> ETags:
        """An object containing all the etags in the `If-Match` header.

        :rtype: :class:`~werkzeug.datastructures.ETags`
        """
        return parse_etags(self.headers.get("If-Match"))

    @cached_property
    def if_none_match(self) -> ETags:
        """An object containing all the etags in the `If-None-Match` header.

        :rtype: :class:`~werkzeug.datastructures.ETags`
        """
        return parse_etags(self.headers.get("If-None-Match"))

    @cached_property
    def if_modified_since(self) -> t.Optional[datetime]:
        """The parsed `If-Modified-Since` header as datetime object."""
        return parse_date(self.headers.get("If-Modified-Since"))

    @cached_property
    def if_unmodified_since(self) -> t.Optional[datetime]:
        """The parsed `If-Unmodified-Since` header as datetime object."""
        return parse_date(self.headers.get("If-Unmodified-Since"))

    @cached_property
    def if_range(self) -> IfRange:
        """The parsed `If-Range` header.

        .. versionadded:: 0.7

        :rtype: :class:`~werkzeug.datastructures.IfRange`
        """
        return parse_if_range_header(self.headers.get("If-Range"))

    @cached_property
    def range(self) -> t.Optional[Range]:
        """The parsed `Range` header.

        .. versionadded:: 0.7

        :rtype: :class:`~werkzeug.datastructures.Range`
        """
        return parse_range_header(self.headers.get("Range"))

    # User Agent

    @cached_property
    def user_agent(self) -> UserAgent:
        """The current user agent."""
        return UserAgent(self.headers.get("User-Agent", ""))  # type: ignore

    # Authorization

    @cached_property
    def authorization(self) -> t.Optional[Authorization]:
        """The `Authorization` object in parsed form."""
        return parse_authorization_header(self.headers.get("Authorization"))

    # CORS

    origin = header_property[str](
        "Origin",
        doc=(
            "The host that the request originated from. Set"
            " :attr:`~CORSResponseMixin.access_control_allow_origin` on"
            " the response to indicate which origins are allowed."
        ),
        read_only=True,
    )

    access_control_request_headers = header_property(
        "Access-Control-Request-Headers",
        load_func=parse_set_header,
        doc=(
            "Sent with a preflight request to indicate which headers"
            " will be sent with the cross origin request. Set"
            " :attr:`~CORSResponseMixin.access_control_allow_headers`"
            " on the response to indicate which headers are allowed."
        ),
        read_only=True,
    )

    access_control_request_method = header_property[str](
        "Access-Control-Request-Method",
        doc=(
            "Sent with a preflight request to indicate which method"
            " will be used for the cross origin request. Set"
            " :attr:`~CORSResponseMixin.access_control_allow_methods`"
            " on the response to indicate which methods are allowed."
        ),
        read_only=True,
    )

    @property
    def is_json(self) -> bool:
        """Check if the mimetype indicates JSON data, either
        :mimetype:`application/json` or :mimetype:`application/*+json`.
        """
        mt = self.mimetype
        return (
            mt == "application/json"
            or mt.startswith("application/")
            and mt.endswith("+json")
        )


class Request(_SansIORequest):
    """Represents an incoming WSGI HTTP request, with headers and body
    taken from the WSGI environment. Has properties and methods for
    using the functionality defined by various HTTP specs. The data in
    requests object is read-only.

    Text data is assumed to use UTF-8 encoding, which should be true for
    the vast majority of modern clients. Using an encoding set by the
    client is unsafe in Python due to extra encodings it provides, such
    as ``zip``. To change the assumed encoding, subclass and replace
    :attr:`charset`.

    :param environ: The WSGI environ is generated by the WSGI server and
        contains information about the server configuration and client
        request.
    :param populate_request: Add this request object to the WSGI environ
        as ``environ['werkzeug.request']``. Can be useful when
        debugging.
    :param shallow: Makes reading from :attr:`stream` (and any method
        that would read from it) raise a :exc:`RuntimeError`. Useful to
        prevent consuming the form data in middleware, which would make
        it unavailable to the final application.

    .. versionchanged:: 2.0
        Combine ``BaseRequest`` and mixins into a single ``Request``
        class. Using the old classes is deprecated and will be removed
        in version 2.1.

    .. versionchanged:: 0.5
        Read-only mode is enforced with immutable classes for all data.
    """

    #: the maximum content length.  This is forwarded to the form data
    #: parsing function (:func:`parse_form_data`).  When set and the
    #: :attr:`form` or :attr:`files` attribute is accessed and the
    #: parsing fails because more than the specified value is transmitted
    #: a :exc:`~werkzeug.exceptions.RequestEntityTooLarge` exception is raised.
    #:
    #: Have a look at :doc:`/request_data` for more details.
    #:
    #: .. versionadded:: 0.5
    max_content_length: t.Optional[int] = None

    #: the maximum form field size.  This is forwarded to the form data
    #: parsing function (:func:`parse_form_data`).  When set and the
    #: :attr:`form` or :attr:`files` attribute is accessed and the
    #: data in memory for post data is longer than the specified value a
    #: :exc:`~werkzeug.exceptions.RequestEntityTooLarge` exception is raised.
    #:
    #: Have a look at :doc:`/request_data` for more details.
    #:
    #: .. versionadded:: 0.5
    max_form_memory_size: t.Optional[int] = None

    #: The form data parser that shoud be used.  Can be replaced to customize
    #: the form date parsing.
    form_data_parser_class: t.Type[FormDataParser] = FormDataParser

    #: Optionally a list of hosts that is trusted by this request.  By default
    #: all hosts are trusted which means that whatever the client sends the
    #: host is will be accepted.
    #:
    #: Because `Host` and `X-Forwarded-Host` headers can be set to any value by
    #: a malicious client, it is recommended to either set this property or
    #: implement similar validation in the proxy (if application is being run
    #: behind one).
    #:
    #: .. versionadded:: 0.9
    trusted_hosts: t.Optional[t.List[str]] = None

    #: Indicates whether the data descriptor should be allowed to read and
    #: buffer up the input stream.  By default it's enabled.
    #:
    #: .. versionadded:: 0.9
    disable_data_descriptor: bool = False

    #: The WSGI environment containing HTTP headers and information from
    #: the WSGI server.
    environ: "WSGIEnvironment"

    #: Set when creating the request object. If ``True``, reading from
    #: the request body will cause a ``RuntimeException``. Useful to
    #: prevent modifying the stream from middleware.
    shallow: bool

    def __init__(
        self,
        environ: "WSGIEnvironment",
        populate_request: bool = True,
        shallow: bool = False,
    ) -> None:
        super().__init__(
            method=environ.get("REQUEST_METHOD", "GET"),
            path=_wsgi_decoding_dance(
                environ.get("PATH_INFO") or "", self.charset, self.encoding_errors
            ),
            query_string=environ.get("QUERY_STRING", "").encode("latin1"),
            headers=EnvironHeaders(environ),
            scheme=environ.get("wsgi.url_scheme", "http"),
            remote_addr=environ.get("REMOTE_ADDR"),
            root_path=_wsgi_decoding_dance(
                environ.get("SCRIPT_NAME") or "", self.charset, self.encoding_errors
            ),
        )
        self.environ = environ
        if populate_request and not shallow:
            self.environ["werkzeug.request"] = self
        self.shallow = shallow

    def __repr__(self) -> str:
        # make sure the __repr__ even works if the request was created
        # from an invalid WSGI environment.  If we display the request
        # in a debug session we don't want the repr to blow up.
        args = []
        try:
            args.append(f"'{self.url}'")
            args.append(f"[{self.method}]")
        except Exception:
            args.append("(invalid WSGI environ)")

        return f"<{type(self).__name__} {' '.join(args)}>"

    @classmethod
    def from_values(cls, *args, **kwargs) -> "Request":
        """Create a new request object based on the values provided.  If
        environ is given missing values are filled from there.  This method is
        useful for small scripts when you need to simulate a request from an URL.
        Do not use this method for unittesting, there is a full featured client
        object (:class:`Client`) that allows to create multipart requests,
        support for cookies etc.

        This accepts the same options as the
        :class:`~werkzeug.test.EnvironBuilder`.

        .. versionchanged:: 0.5
           This method now accepts the same arguments as
           :class:`~werkzeug.test.EnvironBuilder`.  Because of this the
           `environ` parameter is now called `environ_overrides`.

        :return: request object
        """
        from ..test import EnvironBuilder

        charset = kwargs.pop("charset", cls.charset)
        kwargs["charset"] = charset
        builder = EnvironBuilder(*args, **kwargs)
        try:
            return builder.get_request(cls)
        finally:
            builder.close()

    @classmethod
    def application(
        cls, f: t.Callable[["Request"], "WSGIApplication"]
    ) -> "WSGIApplication":
        """Decorate a function as responder that accepts the request as
        the last argument.  This works like the :func:`responder`
        decorator but the function is passed the request object as the
        last argument and the request object will be closed
        automatically::

            @Request.application
            def my_wsgi_app(request):
                return Response('Hello World!')

        As of Werkzeug 0.14 HTTP exceptions are automatically caught and
        converted to responses instead of failing.

        :param f: the WSGI callable to decorate
        :return: a new WSGI callable
        """
        #: return a callable that wraps the -2nd argument with the request
        #: and calls the function with all the arguments up to that one and
        #: the request.  The return value is then called with the latest
        #: two arguments.  This makes it possible to use this decorator for
        #: both standalone WSGI functions as well as bound methods and
        #: partially applied functions.
        from ..exceptions import HTTPException

        @functools.wraps(f)
        def application(*args):
            request = cls(args[-2])
            with request:
                try:
                    resp = f(*args[:-2] + (request,))
                except HTTPException as e:
                    resp = e.get_response(args[-2])
                return resp(*args[-2:])

        return application

    def _get_file_stream(
        self,
        total_content_length: int,
        content_type: t.Optional[str],
        filename: t.Optional[str] = None,
        content_length: t.Optional[int] = None,
    ):
        """Called to get a stream for the file upload.

        This must provide a file-like class with `read()`, `readline()`
        and `seek()` methods that is both writeable and readable.

        The default implementation returns a temporary file if the total
        content length is higher than 500KB.  Because many browsers do not
        provide a content length for the files only the total content
        length matters.

        :param total_content_length: the total content length of all the
                                     data in the request combined.  This value
                                     is guaranteed to be there.
        :param content_type: the mimetype of the uploaded file.
        :param filename: the filename of the uploaded file.  May be `None`.
        :param content_length: the length of this file.  This value is usually
                               not provided because webbrowsers do not provide
                               this value.
        """
        return default_stream_factory(
            total_content_length=total_content_length,
            filename=filename,
            content_type=content_type,
            content_length=content_length,
        )

    @property
    def want_form_data_parsed(self) -> bool:
        """Returns True if the request method carries content.  As of
        Werkzeug 0.9 this will be the case if a content type is transmitted.

        .. versionadded:: 0.8
        """
        return bool(self.environ.get("CONTENT_TYPE"))

    def make_form_data_parser(self) -> FormDataParser:
        """Creates the form data parser. Instantiates the
        :attr:`form_data_parser_class` with some parameters.

        .. versionadded:: 0.8
        """
        return self.form_data_parser_class(
            self._get_file_stream,
            self.charset,
            self.encoding_errors,
            self.max_form_memory_size,
            self.max_content_length,
            self.parameter_storage_class,
        )

    def _load_form_data(self) -> None:
        """Method used internally to retrieve submitted data.  After calling
        this sets `form` and `files` on the request object to multi dicts
        filled with the incoming form data.  As a matter of fact the input
        stream will be empty afterwards.  You can also call this method to
        force the parsing of the form data.

        .. versionadded:: 0.8
        """
        # abort early if we have already consumed the stream
        if "form" in self.__dict__:
            return

        _assert_not_shallow(self)

        if self.want_form_data_parsed:
            content_type = self.environ.get("CONTENT_TYPE", "")
            content_length = get_content_length(self.environ)
            mimetype, options = parse_options_header(content_type)
            parser = self.make_form_data_parser()
            data = parser.parse(
                self._get_stream_for_parsing(), mimetype, content_length, options
            )
        else:
            data = (
                self.stream,
                self.parameter_storage_class(),
                self.parameter_storage_class(),
            )

        # inject the values into the instance dict so that we bypass
        # our cached_property non-data descriptor.
        d = self.__dict__
        d["stream"], d["form"], d["files"] = data

    def _get_stream_for_parsing(self) -> t.BinaryIO:
        """This is the same as accessing :attr:`stream` with the difference
        that if it finds cached data from calling :meth:`get_data` first it
        will create a new stream out of the cached data.

        .. versionadded:: 0.9.3
        """
        cached_data = getattr(self, "_cached_data", None)
        if cached_data is not None:
            return BytesIO(cached_data)
        return self.stream

    def close(self) -> None:
        """Closes associated resources of this request object.  This
        closes all file handles explicitly.  You can also use the request
        object in a with statement which will automatically close it.

        .. versionadded:: 0.9
        """
        files = self.__dict__.get("files")
        for _key, value in iter_multi_items(files or ()):
            value.close()

    def __enter__(self) -> "Request":
        return self

    def __exit__(self, exc_type, exc_value, tb) -> None:
        self.close()

    @cached_property
    def stream(self) -> t.BinaryIO:
        """
        If the incoming form data was not encoded with a known mimetype
        the data is stored unmodified in this stream for consumption.  Most
        of the time it is a better idea to use :attr:`data` which will give
        you that data as a string.  The stream only returns the data once.

        Unlike :attr:`input_stream` this stream is properly guarded that you
        can't accidentally read past the length of the input.  Werkzeug will
        internally always refer to this stream to read data which makes it
        possible to wrap this object with a stream that does filtering.

        .. versionchanged:: 0.9
           This stream is now always available but might be consumed by the
           form parser later on.  Previously the stream was only set if no
           parsing happened.
        """
        _assert_not_shallow(self)
        return get_input_stream(self.environ)

    input_stream = environ_property(
        "wsgi.input",
        """The WSGI input stream.

        In general it's a bad idea to use this one because you can
        easily read past the boundary.  Use the :attr:`stream`
        instead.""",
    )

    @cached_property
    def data(self) -> bytes:
        """
        Contains the incoming request data as string in case it came with
        a mimetype Werkzeug does not handle.
        """

        if self.disable_data_descriptor:
            raise AttributeError("data descriptor is disabled")
        # XXX: this should eventually be deprecated.

        # We trigger form data parsing first which means that the descriptor
        # will not cache the data that would otherwise be .form or .files
        # data.  This restores the behavior that was there in Werkzeug
        # before 0.9.  New code should use :meth:`get_data` explicitly as
        # this will make behavior explicit.
        return self.get_data(parse_form_data=True)

    def get_data(
        self, cache: bool = True, as_text: bool = False, parse_form_data: bool = False
    ) -> bytes:
        """This reads the buffered incoming data from the client into one
        bytes object.  By default this is cached but that behavior can be
        changed by setting `cache` to `False`.

        Usually it's a bad idea to call this method without checking the
        content length first as a client could send dozens of megabytes or more
        to cause memory problems on the server.

        Note that if the form data was already parsed this method will not
        return anything as form data parsing does not cache the data like
        this method does.  To implicitly invoke form data parsing function
        set `parse_form_data` to `True`.  When this is done the return value
        of this method will be an empty string if the form parser handles
        the data.  This generally is not necessary as if the whole data is
        cached (which is the default) the form parser will used the cached
        data to parse the form data.  Please be generally aware of checking
        the content length first in any case before calling this method
        to avoid exhausting server memory.

        If `as_text` is set to `True` the return value will be a decoded
        string.

        .. versionadded:: 0.9
        """
        rv = getattr(self, "_cached_data", None)
        if rv is None:
            if parse_form_data:
                self._load_form_data()
            rv = self.stream.read()
            if cache:
                self._cached_data = rv
        if as_text:
            rv = rv.decode(self.charset, self.encoding_errors)
        return rv

    @cached_property
    def form(self) -> "ImmutableMultiDict[str, str]":
        """The form parameters.  By default an
        :class:`~werkzeug.datastructures.ImmutableMultiDict`
        is returned from this function.  This can be changed by setting
        :attr:`parameter_storage_class` to a different type.  This might
        be necessary if the order of the form data is important.

        Please keep in mind that file uploads will not end up here, but instead
        in the :attr:`files` attribute.

        .. versionchanged:: 0.9

            Previous to Werkzeug 0.9 this would only contain form data for POST
            and PUT requests.
        """
        self._load_form_data()
        return self.form

    @cached_property
    def values(self) -> "CombinedMultiDict[str, str]":
        """A :class:`werkzeug.datastructures.CombinedMultiDict` that combines
        :attr:`args` and :attr:`form`."""
        args = []
        for d in self.args, self.form:
            if not isinstance(d, MultiDict):
                d = MultiDict(d)
            args.append(d)
        return CombinedMultiDict(args)

    @cached_property
    def files(self) -> "ImmutableMultiDict[str, FileStorage]":
        """:class:`~werkzeug.datastructures.MultiDict` object containing
        all uploaded files.  Each key in :attr:`files` is the name from the
        ``<input type="file" name="">``.  Each value in :attr:`files` is a
        Werkzeug :class:`~werkzeug.datastructures.FileStorage` object.

        It basically behaves like a standard file object you know from Python,
        with the difference that it also has a
        :meth:`~werkzeug.datastructures.FileStorage.save` function that can
        store the file on the filesystem.

        Note that :attr:`files` will only contain data if the request method was
        POST, PUT or PATCH and the ``<form>`` that posted to the request had
        ``enctype="multipart/form-data"``.  It will be empty otherwise.

        See the :class:`~werkzeug.datastructures.MultiDict` /
        :class:`~werkzeug.datastructures.FileStorage` documentation for
        more details about the used data structure.
        """
        self._load_form_data()
        return self.files

    @cached_property
    def script_root(self) -> str:
        """The root path of the script without the trailing slash."""
        return self.root_path

    @cached_property
    def url(self) -> str:
        """The reconstructed current URL as IRI.
        See also: :attr:`trusted_hosts`.
        """
        return get_current_url(self.environ, trusted_hosts=self.trusted_hosts)

    @cached_property
    def base_url(self) -> str:
        """Like :attr:`url` but without the querystring
        See also: :attr:`trusted_hosts`.
        """
        return get_current_url(
            self.environ, strip_querystring=True, trusted_hosts=self.trusted_hosts
        )

    @cached_property
    def url_root(self) -> str:
        """The full URL root (with hostname), this is the application
        root as IRI.
        See also: :attr:`trusted_hosts`.
        """
        return get_current_url(self.environ, True, trusted_hosts=self.trusted_hosts)

    @cached_property
    def host_url(self) -> str:
        """Just the host with scheme as IRI.
        See also: :attr:`trusted_hosts`.
        """
        return get_current_url(
            self.environ, host_only=True, trusted_hosts=self.trusted_hosts
        )

    @cached_property
    def host(self) -> str:
        """Just the host including the port if available.
        See also: :attr:`trusted_hosts`.
        """
        return get_host(self.environ, trusted_hosts=self.trusted_hosts)

    remote_user = environ_property[str](
        "REMOTE_USER",
        doc="""If the server supports user authentication, and the
        script is protected, this attribute contains the username the
        user has authenticated as.""",
    )
    is_multithread = environ_property[bool](
        "wsgi.multithread",
        doc="""boolean that is `True` if the application is served by a
        multithreaded WSGI server.""",
    )
    is_multiprocess = environ_property[bool](
        "wsgi.multiprocess",
        doc="""boolean that is `True` if the application is served by a
        WSGI server that spawns multiple processes.""",
    )
    is_run_once = environ_property[bool](
        "wsgi.run_once",
        doc="""boolean that is `True` if the application will be
        executed only once in a process lifetime.  This is the case for
        CGI for example, but it's not guaranteed that the execution only
        happens one time.""",
    )

    # JSON

    #: A module or other object that has ``dumps`` and ``loads``
    #: functions that match the API of the built-in :mod:`json` module.
    json_module = json

    @property
    def json(self) -> t.Optional[t.Any]:
        """The parsed JSON data if :attr:`mimetype` indicates JSON
        (:mimetype:`application/json`, see :meth:`is_json`).

        Calls :meth:`get_json` with default arguments.
        """
        return self.get_json()

    # Cached values for ``(silent=False, silent=True)``. Initialized
    # with sentinel values.
    _cached_json: t.Tuple[t.Any, t.Any] = (Ellipsis, Ellipsis)

    def get_json(
        self, force: bool = False, silent: bool = False, cache: bool = True
    ) -> t.Optional[t.Any]:
        """Parse :attr:`data` as JSON.

        If the mimetype does not indicate JSON
        (:mimetype:`application/json`, see :meth:`is_json`), this
        returns ``None``.

        If parsing fails, :meth:`on_json_loading_failed` is called and
        its return value is used as the return value.

        :param force: Ignore the mimetype and always try to parse JSON.
        :param silent: Silence parsing errors and return ``None``
            instead.
        :param cache: Store the parsed JSON to return for subsequent
            calls.
        """
        if cache and self._cached_json[silent] is not Ellipsis:
            return self._cached_json[silent]

        if not (force or self.is_json):
            return None

        data = self.get_data(cache=cache)

        try:
            rv = self.json_module.loads(data)
        except ValueError as e:
            if silent:
                rv = None

                if cache:
                    normal_rv, _ = self._cached_json
                    self._cached_json = (normal_rv, rv)
            else:
                rv = self.on_json_loading_failed(e)

                if cache:
                    _, silent_rv = self._cached_json
                    self._cached_json = (rv, silent_rv)
        else:
            if cache:
                self._cached_json = (rv, rv)

        return rv

    def on_json_loading_failed(self, e: ValueError) -> t.Any:
        """Called if :meth:`get_json` parsing fails and isn't silenced.
        If this method returns a value, it is used as the return value
        for :meth:`get_json`. The default implementation raises
        :exc:`~werkzeug.exceptions.BadRequest`.
        """
        raise BadRequest(f"Failed to decode JSON object: {e}")


def _assert_not_shallow(request: Request) -> None:
    if request.shallow:
        raise RuntimeError(
            "A shallow request tried to consume form data. If you really"
            " want to do that, set `shallow` to False."
        )


class StreamOnlyMixin:
    """Mixin to create a ``Request`` that disables the ``data``,
    ``form``, and ``files`` properties. Only ``stream`` is available.

    .. deprecated:: 2.0
        Will be removed in 2.1. You likely want to create the request
        with ``shallow=True`` instead. Or subclass and set
        ``disable_data_descriptor`` and ``want_form_data_parsed``.

    .. versionadded:: 0.9
    """

    disable_data_descriptor = True
    want_form_data_parsed = False

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "'StreamOnlyMixin' is deprecated and will be removed in"
            " Werkzeug version 2.1. Create the request with"
            " 'shallow=True' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class PlainRequest(StreamOnlyMixin, Request):
    """A request object without ``data``, ``form``, and ``files``.

    .. deprecated:: 2.0
        Will be removed in 2.1. You likely want to create the request
        with ``shallow=True`` instead. Or subclass and set
        ``disable_data_descriptor`` and ``want_form_data_parsed``.

    .. versionadded:: 0.9
    """

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "'PlainRequest' is deprecated and will be removed in"
            " Werkzeug version 2.1. Create the request with"
            " 'shallow=True' instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        # Don't show the DeprecationWarning for StreamOnlyMixin.
        with warnings.catch_warnings():
            # Don't show the DeprecationWarning for StreamOnlyMixin.
            warnings.simplefilter("ignore", DeprecationWarning)
            super().__init__(*args, **kwargs)
