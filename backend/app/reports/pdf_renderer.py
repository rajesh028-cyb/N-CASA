"""
N-CASA PDF Report Renderer
==========================
Converts rendered HTML security reports directly into PDF documents using xhtml2pdf / ReportLab.
"""

from __future__ import annotations

import io
import logging
from xhtml2pdf import pisa

logger = logging.getLogger("ncasa.pdf_renderer")


class PDFRenderer:
    """Renders HTML content into PDF binary stream."""

    @staticmethod
    def render_html_to_pdf(html_content: str) -> bytes:
        """Convert HTML string to PDF bytes."""
        pdf_stream = io.BytesIO()
        pisa_status = pisa.CreatePDF(
            src=html_content,
            dest=pdf_stream,
            encoding="utf-8",
        )
        if pisa_status.err:
            logger.error("PDF generation encountered errors during rendering: %s", pisa_status.err)
            raise RuntimeError(f"PDF rendering failed with {pisa_status.err} errors.")
        return pdf_stream.getvalue()
