from socketserver import ThreadingMixIn
from typing import Callable, Optional

from pyicap import BaseICAPRequestHandler, ICAPServer


class ThreadingSimpleServer(ThreadingMixIn, ICAPServer):
    pass


class ContentAnalyzer:
    def analyze(self, content: bytes) -> None:
        pass


class ContentModifier:
    def modify(self, content: bytes) -> bytes:
        return content


class RequestAuthorizer:
    def authorize(self, request: bytes, request_headers: dict) -> bool:
        return True


class SimpleICAPHandler(BaseICAPRequestHandler):
    def __init__(
        self,
        request,
        client_address,
        server,
        analyze_func=None,
        modify_func=None,
        authorize_func=None,
    ):
        self.analyze_func = analyze_func
        self.modify_func = modify_func
        self.authorize_func = authorize_func
        super().__init__(request, client_address, server)

    def dlp_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b"Methods", b"REQMOD")
        self.set_icap_header(b"Service", b"SimpleICAP Server 1.0")
        self.set_icap_header(b"Preview", b"0")
        self.set_icap_header(b"Transfer-Preview", b"*")
        self.set_icap_header(b"Transfer-Ignore", b"jpg,jpeg,gif,png,swf,flv")
        self.set_icap_header(b"Transfer-Complete", b"")
        self.set_icap_header(b"Max-Connections", b"100")
        self.set_icap_header(b"Options-TTL", b"3600")
        self.send_headers(False)

    def dlp_REQMOD(self):
        if self.authorize_func and not self.authorize_func(
            self.enc_req, self.enc_req_headers
        ):
            self.send_enc_error(403, message="Forbidden")
            return

        self.set_icap_response(200)
        print("Se seteo la respuesta")

        self.set_enc_request(b" ".join(self.enc_req))
        for h in self.enc_req_headers:
            for v in self.enc_req_headers[h]:
                self.set_enc_header(h, v)

        print("Se pusierons los mismos encabezados con los que vino el paquete")
        if not self.has_body:
            self.send_headers(False)
            return

        print("Tiene cuerpo:", self.has_body)

        content = b""
        while True:
            chunk = self.read_chunk()
            if chunk == b"":
                break
            content += chunk

        print("Se leyo el cuerpo")

        if self.analyze_func:
            self.analyze_func(content)

        print("Se leyo la data")
        if self.modify_func:
            content = self.modify_func(content)

        print("Se modifico la data")
        self.send_headers(True)
        self.write_chunk(content)
        self.write_chunk(b"")


class SimpleICAPServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1344,
        prefix: str = "",
        content_analyzer: Optional[ContentAnalyzer] = None,
        content_modifier: Optional[ContentModifier] = None,
        request_authorizer: Optional[RequestAuthorizer] = None,
    ):
        self.host = host
        self.port = port
        self.prefix = prefix
        self.content_analyzer = content_analyzer
        self.content_modifier = content_modifier
        self.request_authorizer = request_authorizer

    def start(self):
        analyze_func = self.content_analyzer.analyze if self.content_analyzer else None
        modify_func = self.content_modifier.modify if self.content_modifier else None
        authorize_func = (
            self.request_authorizer.authorize if self.request_authorizer else None
        )

        class CustomHandler(SimpleICAPHandler):
            def __getattr__(self, name):
                if name.startswith(self.server.prefix + "_"):
                    return getattr(self, name.split("_", 1)[1])
                raise AttributeError(
                    f"'{self.__class__.__name__}' object has no attribute '{name}'"
                )

        server = ThreadingSimpleServer(
            (self.host, self.port),
            lambda *args: CustomHandler(
                *args,
                analyze_func=analyze_func,
                modify_func=modify_func,
                authorize_func=authorize_func,
            ),
        )
        server.prefix = self.prefix
        print(f"Starting ICAP server on {self.host}:{self.port}")
        try:
            while True:
                server.handle_request()
        except KeyboardInterrupt:
            print("Finished")
