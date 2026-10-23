from __future__ import annotations

from http import client
import ipaddress
import socket
from typing import Any, Callable, Tuple
from urllib import request


def resolve_public_https_addresses(
    host: str,
    port: int,
    *,
    resolver: Callable[..., Any],
    error_prefix: str = "source_url",
) -> Tuple[str, ...]:
    """Resolve an HTTPS host and reject the complete answer if any IP is non-public."""

    try:
        rows = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"{error_prefix}_dns_failed") from exc
    addresses = tuple(
        dict.fromkeys(
            row[4][0]
            for row in rows
            if isinstance(row, tuple) and len(row) >= 5 and row[4]
        )
    )
    if not addresses:
        raise ValueError(f"{error_prefix}_dns_empty")
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError(f"{error_prefix}_nonpublic_dns")
    return addresses


class PinnedPublicHTTPSConnection(client.HTTPSConnection):
    """Connect to a freshly validated public IP while retaining hostname TLS checks."""

    def __init__(
        self,
        host: str,
        *,
        resolver: Callable[..., Any],
        error_prefix: str = "source_url",
        **kwargs: Any,
    ) -> None:
        self._resolver = resolver
        self._error_prefix = error_prefix
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        addresses = resolve_public_https_addresses(
            self.host,
            self.port,
            resolver=self._resolver,
            error_prefix=self._error_prefix,
        )
        last_error: OSError | None = None
        for address in addresses:
            try:
                sock = socket.create_connection(
                    (address, self.port),
                    self.timeout,
                    self.source_address,
                )
            except OSError as exc:
                last_error = exc
                continue
            break
        else:
            if last_error is not None:
                raise last_error
            raise OSError(f"{self._error_prefix}_dns_empty")

        self.sock = sock
        server_hostname = self.host
        if self._tunnel_host:
            self._tunnel()
            server_hostname = self._tunnel_host
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=server_hostname,
        )


class PinnedPublicHTTPSHandler(request.HTTPSHandler):
    def __init__(
        self,
        resolver: Callable[..., Any],
        *,
        error_prefix: str = "source_url",
    ) -> None:
        super().__init__()
        self._resolver = resolver
        self._error_prefix = error_prefix

    def https_open(self, req: Any) -> Any:
        def connection_factory(host: str, **kwargs: Any) -> PinnedPublicHTTPSConnection:
            return PinnedPublicHTTPSConnection(
                host,
                resolver=self._resolver,
                error_prefix=self._error_prefix,
                **kwargs,
            )

        return self.do_open(connection_factory, req, context=self._context)

    https_request = request.AbstractHTTPHandler.do_request_
