import re
from io import BytesIO
from socketserver import ThreadingMixIn
from typing import Callable, Optional
import traceback
import logging
from file_operations.file_operations import TextOperations, PDFOperations, DOCOperations

from docx import Document

from pyicap import BaseICAPRequestHandler, ICAPServer
from typing import Dict


logging.basicConfig(
    filename='pyicap.log',
    level=logging.INFO,        # Set the logging level
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # Format of log entries
)

class ThreadingSimpleServer(ThreadingMixIn, ICAPServer):
    pass

class AnalysisResult:
    def __init__(self, censor_dict: Dict[str, str], block: bool, block_message: str = 'Request blocked by ICAP server'):
        self.censor_dict = censor_dict
        self.block = block
        self.block_message = block_message

class ContentAnalyzer():
    """
    ContentAnalyzer is responsible for analyzing plain text content and identifying sensitive information.
    
    Methods:
        analyze(content: str) -> dict:
            Analyzes the provided plain text content and returns a dictionary.
            The dictionary keys represent the sensitive information found within the content,
            and the values represent the replacement values for the sensitive information.
    """
    def analyze(self, content: str) -> AnalysisResult:
        """
        Analyzes the provided plain text content and returns a dictionary.
        
        The method identifies sensitive information within the content and creates a dictionary.
        The keys of the dictionary are the sensitive information found, and the values are the
        corresponding replacement values.
        
        Parameters:
            content (str): The plain text content to be analyzed.
        
        Returns:
            dict:   A dictionary where the keys are the sensitive information found in the content,
                    and the values are the corresponding replacement values. If no sensitive information
                    is found, it returns None.
        """
        pass

class RequestAuthorizer():
    def authorize(self, request: bytes, request_headers: dict) -> bool:
        return True

class FileHandler:
    def __init__(
        self,
        content: bytes,
        analyze_function: Callable[[bytes], None] = None
    ) -> None:
        self.content = content
        self.file_content = None
        self.op_instance = TextOperations(analyze_function)

        # Split the content based on the boundary string
        boundary = content.split(b"\r\n")[0][2:]
        parts = content.split(boundary) if boundary else [content]

        # Find the part containing the file content
        file_part = None
        for part in parts:
            if b'filename="' in part:
                file_part = part
                file_extension = None
                # Extract the filename using regex
                header = part.split(b"\r\n\r\n", 1)[0]
                match = re.search(rb'filename="(.+)"', header)
                if match:
                    filename = match.group(1).decode('utf-8')
                    file_extension = filename.split('.')[-1].lower()
                    print(f"Detected file extension: {file_extension}")
                break

        if file_part:
            # Extract the file content by removing headers and trailing newlines
            self.file_content = file_part.split(b"\r\n\r\n", 1)[1].strip()

            # Check if the content is a PDF
            if file_extension == "pdf" or self.file_content.startswith(b"%PDF"):
                self.op_instance = PDFOperations(analyze_function)
            # Check if the content is a Word document
            elif file_extension == "docx":
                try:
                    Document(BytesIO(self.file_content))
                    self.op_instance = DOCOperations(analyze_function)
                    return
                except Exception:
                    traceback.print_exc()
            # TODO: define how to manage other files

    def modify_content(self, censor_dict: dict) -> bytes:
        try:
            return self.op_instance.modify_content(self.content, self.file_content, censor_dict)
        except Exception as e:
            print(f"Error modifying document: {str(e)}")
            traceback.print_exc()
            return self.content

    def analyze_content(self) -> AnalysisResult:
        try:
            return self.op_instance.analyze_content(self.content, self.file_content)
        except Exception as e:
            print(f"Error analyzing document: {str(e)}")
            traceback.print_exc()

class SimpleICAPHandler(BaseICAPRequestHandler):
    def __init__(
        self,
        request,
        client_address,
        server,
        analyze_function=None,
        authorize_function=None,
    ) -> None:
        self.analyze_function = analyze_function
        self.authorize_function = authorize_function
        super().__init__(request, client_address, server)

    def dlp_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b"Methods", b"REQMOD")
        self.set_icap_header(b"Service", b"SimpleICAP Server 1.0")
        self.set_icap_header(b"Preview", b"0")
        self.set_icap_header(b"Transfer-Preview", b"*")
        self.set_icap_header(b"Transfer-Ignore", b"jpg,jpeg,gif,png,swf,flv, xlsx")
        self.set_icap_header(b"Transfer-Complete", b"")
        self.set_icap_header(b"Max-Connections", b"100")
        self.set_icap_header(b"Options-TTL", b"3600")
        self.send_headers(False)

    def dlp_REQMOD(self):
        if self.authorize_function and not self.authorize_function(
            self.enc_req, self.enc_req_headers
        ):
            self.send_enc_error(403, message="Forbidden")
            return

        if not self.has_body:
            self.send_headers(False)
            self.set_icap_response(200)
            return

        content = b""

        if self.preview:
            print("Handling preview mode")
            while True:
                chunk = self.read_chunk()
                if chunk == b"":
                    break
                content += chunk

            if self.ieof:
                print("End of preview")
                self.send_headers(True)
                if self.analyze_function:
                    self.analyze_function(content)
                self.write_chunk(content)
                self.write_chunk(b"")
                return

            self.cont()
            
        while True:
            chunk = self.read_chunk()
            if not chunk or chunk == b"":
                break
            content += chunk

        logging.info("Original content")
        logging.info(content)

        file_handler = FileHandler(content, self.analyze_function)
        print(f"FileHandler type {type(file_handler.op_instance)}")

        if self.analyze_function:
            result = file_handler.analyze_content()

            if result and result.block:
                response = result.block_message
                # Block the request
                self.send_enc_error(403, body=response.encode("utf-8"))
                return
            if result and result.censor_dict and result.censor_dict.keys():
                self.set_icap_response(200)
                content = file_handler.modify_content(result.censor_dict)
                logging.info("Modified request")
                logging.info(content)            
                self.set_enc_request(b' '.join(self.enc_req))
                self.set_content_length_header(str(len(content)))
                self.send_headers(True)
                self.write_chunk(content)
                self.write_chunk(b'')
                return
        self.no_adaptation_required()

    def set_content_length_header(self, content_length):
        for h in self.enc_req_headers:
            for v in self.enc_req_headers[h]:
                if h.lower() == b'content-length':
                    v = content_length.encode('utf-8')
                self.set_enc_header(h, v)

class SimpleICAPServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1344,
        prefix: str = "",
        content_analyzer: Optional[ContentAnalyzer] = None,
        request_authorizer: Optional[RequestAuthorizer] = None,
    ):
        self.host = host
        self.port = port
        self.prefix = prefix
        self.content_analyzer = content_analyzer
        self.request_authorizer = request_authorizer

    def start(self):
        analyze_function = self.content_analyzer.analyze
        authorize_function = self.request_authorizer.authorize

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
                analyze_function=analyze_function,
                authorize_function=authorize_function,
            ),
        )
        server.prefix = self.prefix
        print(f"Starting ICAP server on {self.host}:{self.port}")
        try:
            while True:
                server.handle_request()
        except KeyboardInterrupt:
            print("Finished")
