from __future__ import annotations

from itertools import chain
from typing import Awaitable, Callable, cast, Optional, Tuple, Type, Union

import h11

from .events import (
    Body,
    Data,
    EndBody,
    EndData,
    Event as StreamEvent,
    InformationalResponse,
    Request,
    Response,
    StreamClosed,
)
from .http_stream import HTTPStream
from .ws_stream import WSStream
from ..config import Config
from ..events import Closed, Event, RawData, Updated
from ..typing import AppWrapper, ConnectionState, H11SendableEvent, TaskGroup, WorkerContext

STREAM_ID = 1


HTTP_REASON_PHRASES = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",  # WebDAV
    103: "Early Hints",  # HTTP/1.1 + Link preload

    200: "OKKKKK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",  # WebDAV
    208: "Already Reported",  # WebDAV
    226: "IM Used",  # Delta encoding

    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",

    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a teapot",  # Easter egg (RFC 2324)
    421: "Misdirected Request",
    422: "Unprocessable Entity",  # WebDAV
    423: "Locked",  # WebDAV
    424: "Failed Dependency",  # WebDAV
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",

    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",  # WebDAV
    508: "Loop Detected",  # WebDAV
    510: "Not Extended",
    511: "Network Authentication Required",
}


def get_reason_phrase(status_code: int) -> str:
    return HTTP_REASON_PHRASES.get(status_code, "")


class H2CProtocolRequiredError(Exception):
    def __init__(self, data: bytes, request: h11.Request) -> None:
        settings = ""
        headers = [(b":method", request.method), (b":path", request.target)]
        for name, value in request.headers:
            if name.lower() == b"http2-settings":
                settings = value.decode()
            elif name.lower() == b"host":
                headers.append((b":authority", value))
            headers.append((name, value))

        self.data = data
        self.headers = headers
        self.settings = settings


class H2ProtocolAssumedError(Exception):
    def __init__(self, data: bytes) -> None:
        self.data = data


class H11WSConnection:
    # This class matches the h11 interface, and either passes data
    # through without altering it (for Data, EndData) or sends h11
    # events (Response, Body, EndBody).
    our_state = None  # Prevents recycling the connection
    they_are_waiting_for_100_continue = False
    their_state = None
    trailing_data = (b"", False)

    def __init__(self, h11_connection: h11.Connection) -> None:
        self.buffer = bytearray(h11_connection.trailing_data[0])
        self.h11_connection = h11_connection

    def receive_data(self, data: bytes) -> None:
        self.buffer.extend(data)

    def next_event(self) -> Union[Data, Type[h11.NEED_DATA]]:
        if self.buffer:
            event = Data(stream_id=STREAM_ID, data=bytes(self.buffer))
            self.buffer = bytearray()
            return event
        else:
            return h11.NEED_DATA

    def send(self, event: H11SendableEvent) -> bytes:
        return self.h11_connection.send(event)

    def start_next_cycle(self) -> None:
        pass


class H11Protocol:
    def __init__(
        self,
        app: AppWrapper,
        config: Config,
        context: WorkerContext,
        task_group: TaskGroup,
        connection_state: ConnectionState,
        ssl: bool,
        client: Optional[Tuple[str, int]],
        server: Optional[Tuple[str, int]],
        send: Callable[[Event], Awaitable[None]],
    ) -> None:
        self.app = app
        self.can_read = context.event_class()
        self.client = client
        self.config = config
        self.connection: Union[h11.Connection, H11WSConnection] = h11.Connection(
            h11.SERVER, max_incomplete_event_size=self.config.h11_max_incomplete_size
        )
        self.context = context
        self.keep_alive_requests = 0
        self.send = send
        self.server = server
        self.ssl = ssl
        self.stream: Optional[Union[HTTPStream, WSStream]] = None
        self.task_group = task_group
        self.connection_state = connection_state

    async def initiate(self) -> None:
        pass

    async def handle(self, event: Event) -> None:
        if isinstance(event, RawData):
            self.connection.receive_data(event.data)
            await self._handle_events()
        elif isinstance(event, Closed):
            if self.stream is not None:
                await self._close_stream()

    async def stream_send(self, event: StreamEvent) -> None:
        if isinstance(event, Response):
            if event.status_code >= 200:
                headers = list(chain(event.headers, self.config.response_headers("h11")))
                if self.keep_alive_requests >= self.config.keep_alive_max_requests:
                    headers.append((b"connection", b"close"))
                await self._send_h11_event(
                    h11.Response(
                        headers=headers,
                        status_code=event.status_code,
                        reason=get_reason_phrase(event.status_code),
                    )
                )
            else:
                await self._send_h11_event(
                    h11.InformationalResponse(
                        headers=list(chain(event.headers, self.config.response_headers("h11"))),
                        status_code=event.status_code,
                        reason=get_reason_phrase(event.status_code),
                    )
                )
        elif isinstance(event, InformationalResponse):
            pass  # Ignore for HTTP/1
        elif isinstance(event, Body):
            await self._send_h11_event(h11.Data(data=event.data))
        elif isinstance(event, EndBody):
            await self._send_h11_event(h11.EndOfMessage())
        elif isinstance(event, Data):
            await self.send(RawData(data=event.data))
        elif isinstance(event, EndData):
            pass
        elif isinstance(event, StreamClosed):
            await self._maybe_recycle()

    async def _handle_events(self) -> None:
        while True:
            if self.connection.they_are_waiting_for_100_continue:
                await self._send_h11_event(
                    h11.InformationalResponse(
                        status_code=100, headers=self.config.response_headers("h11")
                    )
                )

            try:
                event = self.connection.next_event()
            except h11.RemoteProtocolError as error:
                if self.connection.our_state in {h11.IDLE, h11.SEND_RESPONSE}:
                    await self._send_error_response(error.error_status_hint)
                await self.send(Closed())
                break
            else:
                if isinstance(event, h11.Request):
                    await self.send(Updated(idle=False))
                    await self._check_protocol(event)
                    await self._create_stream(event)
                elif event is h11.PAUSED:
                    await self.can_read.clear()
                    await self.can_read.wait()
                elif isinstance(event, h11.ConnectionClosed) or event is h11.NEED_DATA:
                    break
                elif self.stream is None:
                    break
                elif isinstance(event, h11.Data):
                    await self.stream.handle(Body(stream_id=STREAM_ID, data=event.data))
                elif isinstance(event, h11.EndOfMessage):
                    await self.stream.handle(EndBody(stream_id=STREAM_ID))
                elif isinstance(event, Data):
                    # WebSocket pass through
                    await self.stream.handle(event)

    async def _create_stream(self, request: h11.Request) -> None:
        upgrade_value = ""
        connection_value = ""
        for name, value in request.headers:
            sanitised_name = name.decode("latin1").strip().lower()
            if sanitised_name == "upgrade":
                upgrade_value = value.decode("latin1").strip()
            elif sanitised_name == "connection":
                connection_value = value.decode("latin1").strip()

        connection_tokens = connection_value.lower().split(",")
        if (
            any(token.strip() == "upgrade" for token in connection_tokens)
            and upgrade_value.lower() == "websocket"
            and request.method.decode("ascii").upper() == "GET"
        ):
            self.stream = WSStream(
                self.app,
                self.config,
                self.context,
                self.task_group,
                self.ssl,
                self.client,
                self.server,
                self.stream_send,
                STREAM_ID,
            )
            self.connection = H11WSConnection(cast(h11.Connection, self.connection))
        else:
            self.stream = HTTPStream(
                self.app,
                self.config,
                self.context,
                self.task_group,
                self.ssl,
                self.client,
                self.server,
                self.stream_send,
                STREAM_ID,
            )

        if self.config.h11_pass_raw_headers:
            headers = request.headers.raw_items()
        else:
            headers = list(request.headers)

        await self.stream.handle(
            Request(
                stream_id=STREAM_ID,
                headers=headers,
                http_version=request.http_version.decode(),
                method=request.method.decode("ascii").upper(),
                raw_path=request.target,
                state=self.connection_state,
            )
        )
        self.keep_alive_requests += 1
        await self.context.mark_request()

    async def _send_h11_event(self, event: H11SendableEvent) -> None:
        try:
            data = self.connection.send(event)
        except h11.LocalProtocolError:
            if self.connection.their_state != h11.ERROR:
                raise
        else:
            await self.send(RawData(data=data))

    async def _send_error_response(self, status_code: int) -> None:
        await self._send_h11_event(
            h11.Response(
                status_code=status_code,
                headers=list(
                    chain(
                        [(b"content-length", b"0"), (b"connection", b"close")],
                        self.config.response_headers("h11"),
                    )
                ),
            )
        )
        await self._send_h11_event(h11.EndOfMessage())

    async def _maybe_recycle(self) -> None:
        await self._close_stream()
        if (
            not self.context.terminated.is_set()
            and self.connection.our_state is h11.DONE
            and self.connection.their_state is h11.DONE
        ):
            try:
                self.connection.start_next_cycle()
            except h11.LocalProtocolError:
                await self.send(Closed())
            else:
                self.response = None
                self.scope = None
                await self.can_read.set()
                await self.send(Updated(idle=True))
        else:
            await self.can_read.set()
            await self.send(Closed())

    async def _close_stream(self) -> None:
        if self.stream is not None:
            await self.stream.handle(StreamClosed(stream_id=STREAM_ID))
            self.stream = None

    async def _check_protocol(self, event: h11.Request) -> None:
        upgrade_value = ""
        has_body = False
        for name, value in event.headers:
            sanitised_name = name.decode("latin1").strip().lower()
            if sanitised_name == "upgrade":
                upgrade_value = value.decode("latin1").strip()
            elif sanitised_name in {"content-length", "transfer-encoding"}:
                has_body = True

        # h2c Upgrade requests with a body are a pain as the body must
        # be fully recieved in HTTP/1.1 before the upgrade response
        # and HTTP/2 takes over, so Hypercorn ignores the upgrade and
        # responds in HTTP/1.1. Use a preflight OPTIONS request to
        # initiate the upgrade if really required (or just use h2).
        if upgrade_value.lower() == "h2c" and not has_body:
            await self._send_h11_event(
                h11.InformationalResponse(
                    status_code=101,
                    headers=self.config.response_headers("h11")
                    + [(b"connection", b"upgrade"), (b"upgrade", b"h2c")],
                )
            )
            raise H2CProtocolRequiredError(self.connection.trailing_data[0], event)
        elif event.method == b"PRI" and event.target == b"*" and event.http_version == b"2.0":
            raise H2ProtocolAssumedError(
                b"PRI * HTTP/2.0\r\n\r\n" + self.connection.trailing_data[0]
            )
