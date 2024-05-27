from icapserver import (
    ContentAnalyzer,
    RequestAuthorizer,
    SimpleICAPServer,
    AnalysisResult
)


class MyContentAnalyzer(ContentAnalyzer):
    def analyze(self, content: str) -> AnalysisResult:
        block = False
        censor_dict = {}
        if "censor me" in content:
            censor_dict["censor me"] = "[CENSORED]"
        if "block me" in content:
            block = True
        return AnalysisResult(censor_dict, block)
 
class MyRequestAuthorizer(RequestAuthorizer):
    def authorize(self, request: bytes, request_headers: dict) -> bool:
        if b"unauthorized" in request:
            return False
        return True

analyzer = MyContentAnalyzer()
authorizer = MyRequestAuthorizer()

server = SimpleICAPServer(
    port=1344,
    prefix="dlp",
    content_analyzer=analyzer,
    request_authorizer=authorizer,
)
server.start()
