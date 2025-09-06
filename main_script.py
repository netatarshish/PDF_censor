import streamlit as st
import pdfplumber
from presidio_analyzer import AnalyzerEngine
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
import io

# Initialize analyzer to go over the PDF text and detect PII
text_analyzer = AnalyzerEngine()
st.title("Mask sensitive data in pdf")

uploaded_file = st.file_uploader("Upload a PDF file", type="pdf")
if uploaded_file is not None:
    file_bytes = uploaded_file.read()
    file_object = io.BytesIO(file_bytes)

    # Go over pages and search for PII
    found_piis = {}
    with pdfplumber.open(file_object) as pdf:
        for page_index, page in enumerate(pdf.pages):
            page_text = page.extract_text() or ""
            pii_detections = text_analyzer.analyze(text=page_text, language="en")
            for pii in pii_detections:
                pii.text = page_text[pii.start:pii.end] #Saves pii start and end point to be blacked out
            found_piis[page_index] = pii_detections

    # Create local PDF to preform blackouts
    output_pdf = io.BytesIO()
    pdf_canvas = canvas.Canvas(output_pdf, pagesize=letter)

    # Go over the pages again to "draw" on the local PDF
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for page_index, page in enumerate(pdf.pages):
            if page_index > 0: # Handling edge case for the first page
                pdf_canvas.showPage()

            # Draw original page as image to be altered later
            pdf_to_image = page.to_image(resolution=300)
            image_bytes = io.BytesIO()
            image_bytes.original.save(image_bytes, format="PNG")
            image_bytes.seek(0) # Moves the pointer to the start
            pdf_canvas.drawImage(ImageReader(image_bytes), 0, 0, width=letter[0], height=letter[1])

            # Scaling from PDF units to ReportLab units
            scale_x = letter[0] / page.width
            scale_y = letter[1] / page.height
            all_chars = page.chars # Gets words place and size
            # Goes through found PII to find exact chars that need to be blacked out
            for found_pii in found_piis.get(page_index, []):
                pii_chars = []
                current_page_content = "".join(char['text'] for char in all_chars)
                pii_start_index = current_page_content.find(found_pii.text)
                if pii_start_index != -1:
                    pii_end_index = pii_start_index + len(found_pii.text)
                    # Going through each char in the page while checking if the char's index falls between a pii's start and end
                    char_index = 0
                    for char_object in all_chars:
                        if char_index >= pii_start_index and char_index < pii_end_index:
                            pii_chars.append(char_object)
                        char_index += len(char_object['text'])

                if pii_chars: # If pii chars were found, black them out
                    # Find rectangle size and place
                    left_corner = min(char["x0"] for char in pii_chars)
                    right_corner = max(char["x1"] for char in pii_chars)
                    rectangle_bottom = min(char["bottom"] for char in pii_chars)
                    rectangle_top = max(char["top"] for char in pii_chars)

                    # Scale to ReportLab units
                    left_corner_scaled = left_corner * scale_x
                    right_corner_scaled = right_corner * scale_x
                    rectangle_top_scaled = letter[1] - (rectangle_top * scale_y)
                    rectangle_bottom_scaled = letter[1] - (rectangle_bottom * scale_y)

                    pdf_canvas.setFillColor("black")
                    pdf_canvas.rect(left_corner_scaled, rectangle_top_scaled, right_corner_scaled - left_corner_scaled, rectangle_bottom_scaled - rectangle_top_scaled, fill=1)

    pdf_canvas.save()
    output_pdf.seek(0)
    st.download_button(label="Download Redacted PDF", data=output_pdf, file_name="redacted_document.pdf", mime="application/pdf")
