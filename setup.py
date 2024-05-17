from icapserver import (
    ContentAnalyzer,
    ContentModifier,
    RequestAuthorizer,
    SimpleICAPServer,
)


class MyContentAnalyzer(ContentAnalyzer):
    def analyze(self, content: bytes) -> None:
        print("Analyzing content...")


class MyContentModifier(ContentModifier):
    def modify(self, content: bytes) -> bytes:
        modified_content = content.replace(b"example", b"modified")
        return modified_content


class MyRequestAuthorizer(RequestAuthorizer):
    def authorize(self, request: bytes, request_headers: dict) -> bool:
        if b"unauthorized" in request:
            return False
        return True


analyzer = MyContentAnalyzer()
modifier = MyContentModifier()
authorizer = MyRequestAuthorizer()

server = SimpleICAPServer(
    port=1344,
    prefix="dlp",
    content_analyzer=analyzer,
    content_modifier=modifier,
    request_authorizer=authorizer,
)
server.start()
