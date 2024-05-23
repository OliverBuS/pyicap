from io import BytesIO
from socketserver import ThreadingMixIn
from typing import Callable, Optional
import traceback
import logging

import fitz
from docx import Document
from PyPDF2 import PdfMerger, PdfReader, PdfWriter

from pyicap import BaseICAPRequestHandler, ICAPServer, native

logging.basicConfig(
    filename='pyicap.log',
    level=logging.INFO,        # Set the logging level
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # Format of log entries
)

class ThreadingSimpleServer(ThreadingMixIn, ICAPServer):
    pass


class ContentAnalyzer:
    def analyze(self, content: str) -> None:
        pass


class ContentModifier:
    def modify(self, content: str) -> str:
        return content


class RequestAuthorizer:
    def authorize(self, request: bytes, request_headers: dict) -> bool:
        return True


class FileHandler:
    def __init__(
        self,
        content: bytes,
        modify_fun: Callable[[bytes], bytes] = None,
        analyze_fun: Callable[[bytes], None] = None,
    ) -> None:
        self.content = content
        self.modify_fun = modify_fun
        self.analyze_fun = analyze_fun
        self.type = "text"

        print(f"Original content: {self.content[-300:]}")

        # Split the content based on the boundary string
        boundary = content.split(b"\r\n")[0][2:]
        parts = content.split(boundary) if boundary else [content]

        # Find the part containing the file content
        file_part = None
        for part in parts:
            if b'filename="' in part:
                file_part = part
                break

        if file_part:
            # Extract the file content by removing headers and trailing newlines
            self.file_content = file_part.split(b"\r\n\r\n", 1)[1].strip()

            # Check if the content is a PDF
            if self.file_content.startswith(b"%PDF"):
                self.type = "pdf"
                return

            # Check if the content is a Word document
            try:
                Document(BytesIO(self.file_content))
                self.type = "docx"
                return
            except Exception:
                traceback.print_exc()

    def modify_content(self) -> bytes:
        if not self.modify_fun:
            return self.content
        if self.type == "pdf":
            try:
                # Create a BytesIO object from the file content
                pdf_buffer = BytesIO(self.file_content)
                # Open the original PDF
                original_doc = fitz.open(stream=pdf_buffer, filetype="pdf")

                # Create a new PDF document
                modified_doc = fitz.open()

                # Iterate over each page
                for page_num in range(len(original_doc)):
                    original_page = original_doc[page_num]
                    # Add a new page to the modified document
                    modified_page = modified_doc.new_page(
                        width=original_page.rect.width, height=original_page.rect.height
                    )

                    # Copy the content from the original page to the modified page
                    modified_page.show_pdf_page(
                        modified_page.rect, original_doc, page_num
                    )

                    # Get the text blocks
                    blocks = original_page.get_text("dict")["blocks"]
                    # Iterate over each text block
                    for block in blocks:
                        if block["type"] == 0:  # Text block (type 0)
                            original_text = block["lines"][0]["spans"][0]["text"]
                            modified_text = self.modify_fun(original_text)

                            rect = fitz.Rect(block["bbox"])

                            # Add redaction annotation with the modified text
                            modified_page.add_redact_annot(
                                rect,
                                modified_text,
                                fontname=block["lines"][0]["spans"][0]["font"],
                                fontsize=block["lines"][0]["spans"][0]["size"],
                                align=fitz.TEXT_ALIGN_LEFT,
                            )  # Keep original alignment

                    modified_page.apply_redactions(
                        images=fitz.PDF_REDACT_IMAGE_NONE
                    )  # Don't touch images
                # Save the modified PDF to a BytesIO object
                modified_buffer = BytesIO()
                modified_doc.save(modified_buffer)
                modified_buffer.seek(0)
                modified_file_content = modified_buffer.getvalue()

                # Reconstruct the multipart/form-data with the modified file content
                boundary = self.content.split(b"\r\n")[0]
                modified_content = b""
                for part in self.content.split(boundary)[:-1]:
                    if b'filename="' in part:
                        headers, _ = part.split(b"\r\n\r\n", 1)
                        modified_content += (
                            boundary
                            + b"\r\n"
                            + headers
                            + b"\r\n\r\n"
                            + modified_file_content
                            + b"\r\n"
                        )
                    elif len(part) > 0:
                        modified_content += part

                # Add the closing boundary to the modified content
                modified_content += boundary + b"--\r\n"

                print(f"Modified content: {modified_content[-300:]}")
                return modified_content

            except Exception as e:
                print(f"Error modifying PDF: {str(e)}")
                traceback.print_exc()
                return self.content
        elif self.type == "docx":
            try:
                # Create a BytesIO object from the file content
                docx_buffer = BytesIO(self.file_content)

                # Load the Word document
                document = Document(docx_buffer)

                # Iterate over each paragraph
                for paragraph in document.paragraphs:
                    # Extract the text from the paragraph
                    text = paragraph.text
                    # Modify the text using the provided function
                    modified_text = self.modify_fun(text)
                    print(
                        "Original text: " + text + "\nModified text: " + modified_text
                    )

                    # Replace the paragraph text with the modified text
                    paragraph.text = modified_text

                # Create a BytesIO object to store the modified Word document
                output_buffer = BytesIO()
                document.save(output_buffer)

                # Get the modified Word document content as bytes
                modified_file_content = output_buffer.getvalue()

                # Reconstruct the multipart/form-data with the modified file content
                boundary = self.content.split(b"\r\n")[0]
                modified_content = b""
                for part in self.content.split(boundary)[:-1]:
                    if b'filename="' in part:
                        headers, _ = part.split(b"\r\n\r\n", 1)
                        modified_content += (
                            boundary
                            + headers
                            + b"\r\n\r\n"
                            + modified_file_content
                            + b"\r\n"
                        )
                    elif len(part) > 0:
                        modified_content += part

                # Add the closing boundary to the modified content
                modified_content += boundary + b"--\r\n"
                print(f"Modified content: {modified_content[-300:]}")
                return modified_content

            except Exception as e:
                print(f"Error modifying Word document: {str(e)}")
                traceback.print_exc()
                return self.content
        else:
            return self.modify_fun(self.content.decode("utf-8")).encode("utf-8")

    def analyze_content(self) -> None:
        if not self.analyze_fun:
            return
        if self.type == "pdf":
            try:
                # Create a BytesIO object from the file content
                pdf_buffer = BytesIO(self.file_content)

                # Create a PDF reader object
                pdf_reader = PdfReader(pdf_buffer)

                text = ""
                # Iterate over each page
                for page_num in range(len(pdf_reader.pages)):
                    # Get the page object
                    page = pdf_reader.pages[page_num]

                    # Extract the text from the page
                    text += page.extract_text()

                # Analyze the text using the provided function
                self.analyze_fun(text.encode("utf-8"))

            except Exception as e:
                print(f"Error analyzing PDF: {str(e)}")
                traceback.print_exc()
        elif self.type == "docx":
            try:
                # Create a BytesIO object from the file content
                docx_buffer = BytesIO(self.file_content)

                # Load the Word document
                document = Document(docx_buffer)

                # Iterate over each paragraph
                for paragraph in document.paragraphs:
                    # Extract the text from the paragraph
                    text = paragraph.text

                    # Analyze the text using the provided function
                    self.analyze_fun(text.encode("utf-8"))

            except Exception as e:
                print(f"Error analyzing Word document: {str(e)}")
                traceback.print_exc()
        else:
            self.analyze_fun(self.content.decode("utf-8"))


class SimpleICAPHandler(BaseICAPRequestHandler):
    def __init__(
        self,
        request,
        client_address,
        server,
        analyze_func=None,
        modify_func=None,
        authorize_func=None,
    ) -> None:
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
        self.set_icap_header(b"Transfer-Ignore", b"jpg,jpeg,gif,png,swf,flv, xlsx")
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
                if self.analyze_func:
                    self.analyze_func(content)
                self.write_chunk(content)
                self.write_chunk(b"")
                return

            self.cont()

        while True:
            chunk = self.read_chunk()
            if chunk == b"":
                break
            content += chunk

        logging.info("Original request")
        logging.info(content)

        print("Se leyó el cuerpo")
        fileHandler = FileHandler(content, self.modify_func, self.analyze_func)
        print(f"FileHandler type {fileHandler.type}")

        if self.analyze_func:
            fileHandler.analyze_content()

        print("Se leyo la data")
        if self.modify_func:
            content = fileHandler.modify_content()
            logging.info("Modified request")
            logging.info(content)

        print("Se modifico la data")
        self.set_content_length_header(str(len(content)))
        self.send_headers(True)
        print(f"Sending modified content: {content[:120]}")
        self.write_chunk(content)
        self.write_chunk(b"")

    def set_content_length_header(self, content_length):
         for h in self.enc_req_headers:
                for v in self.enc_req_headers[h]:
                    if h.lower() == b'content-length':
                        v = str(len(content_length)).encode('utf-8')
                        self.set_enc_header(h, v)

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
