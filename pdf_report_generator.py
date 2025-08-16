"""
Professional PDF Report Generator for VirusTotal Analysis
Author: Your Name
Date: August 2025
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics import renderPDF
import datetime
import os


class VirusTotalPDFGenerator:
    """Professional PDF report generator for VirusTotal scan results."""
    
    def __init__(self):
        # Custom color scheme
        self.PRIMARY_COLOR = colors.Color(0.2, 0.3, 0.5)  # Dark blue
        self.SECONDARY_COLOR = colors.Color(0.85, 0.85, 0.85)  # Light gray
        self.SUCCESS_COLOR = colors.Color(0.2, 0.7, 0.3)  # Green
        self.WARNING_COLOR = colors.Color(1.0, 0.6, 0.0)  # Orange
        self.DANGER_COLOR = colors.Color(0.8, 0.2, 0.2)  # Red
    
    def _create_custom_styles(self):
        """Create custom paragraph styles for the report."""
        styles = getSampleStyleSheet()
        
        # Custom title style
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=self.PRIMARY_COLOR,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Custom heading styles
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=self.PRIMARY_COLOR,
            fontName='Helvetica-Bold',
            borderWidth=0,
            borderColor=self.PRIMARY_COLOR,
            borderPadding=5
        )
        
        # Custom normal style
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            textColor=colors.black,
            fontName='Helvetica'
        )
        
        return styles, title_style, heading_style, normal_style
    
    def _extract_file_info(self, attributes):
        """Extract and format file information from VirusTotal attributes."""
        return {
            "File Name": attributes.get("meaningful_name", "N/A"),
            "SHA256": attributes.get("sha256", "N/A")[:64] + "..." if attributes.get("sha256") and len(attributes.get("sha256", "")) > 64 else attributes.get("sha256", "N/A"),
            "MD5": attributes.get("md5", "N/A"),
            "SHA1": attributes.get("sha1", "N/A"),
            "File Type": attributes.get("type_description", "N/A"),
            "File Size": f"{attributes.get('size', 0):,} bytes" if attributes.get('size') else "N/A",
            "Magic": attributes.get("magic", "N/A"),
            "SSDEEP": attributes.get("ssdeep", "N/A")[:50] + "..." if attributes.get("ssdeep") and len(attributes.get("ssdeep", "")) > 50 else attributes.get("ssdeep", "N/A")
        }
    
    def _determine_threat_level(self, stats):
        """Determine threat level based on detection statistics."""
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        
        if malicious_count > 0:
            return "HIGH RISK", self.DANGER_COLOR, "🚨"
        elif suspicious_count > 0:
            return "MEDIUM RISK", self.WARNING_COLOR, "⚠️"
        else:
            return "LOW RISK", self.SUCCESS_COLOR, "✅"
    
    def _create_header_section(self, story, styles, threat_level, threat_color, threat_icon, stats, total_engines):
        """Create the header section with title and executive summary."""
        # Header with logo placeholder and title
        story.append(Spacer(1, 0.2 * inch))
        
        # Title with security badge styling
        title_text = f"""
        <para align="center">
        <font size="28" color="#{self.PRIMARY_COLOR.hexval()[2:]}"><b>🛡️ SECURITY ANALYSIS REPORT</b></font><br/>
        <font size="14" color="gray">VirusTotal Malware Detection Analysis</font><br/>
        <font size="10" color="gray">Generated on {datetime.datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</font>
        </para>
        """
        story.append(Paragraph(title_text, styles['Normal']))
        story.append(Spacer(1, 0.3 * inch))
        
        # Executive Summary Box
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        
        summary_text = f"""
        <para align="center" bgcolor="#{self.SECONDARY_COLOR.hexval()[2:]}" leftIndent="20" rightIndent="20" spaceAfter="20" spaceBefore="10">
        <font size="18" color="#{threat_color.hexval()[2:]}"><b>{threat_icon} THREAT LEVEL: {threat_level}</b></font><br/>
        <font size="12"><b>{malicious_count}</b> malicious detections out of <b>{total_engines}</b> security engines</font><br/>
        <font size="10">Suspicious: {suspicious_count} | Clean: {stats.get('undetected', 0)} | Timeout: {stats.get('timeout', 0)}</font>
        </para>
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))
    
    def _create_file_info_section(self, story, file_info, heading_style):
        """Create the file information section."""
        story.append(Paragraph("📁 FILE INFORMATION", heading_style))
        
        # Create a styled table for file info
        file_info_data = [["Property", "Value"]]
        for key, value in file_info.items():
            file_info_data.append([key, str(value)])
        
        file_info_table = Table(file_info_data, colWidths=[2*inch, 4*inch])
        file_info_table.setStyle(TableStyle([
            # Header row styling
            ('BACKGROUND', (0, 0), (-1, 0), self.PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            
            # Data rows styling
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            
            # Grid and borders
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.SECONDARY_COLOR]),
        ]))
        story.append(file_info_table)
        story.append(Spacer(1, 0.3 * inch))
    
    def _create_detection_stats_section(self, story, stats, heading_style):
        """Create the detection statistics section."""
        story.append(Paragraph("📊 DETECTION STATISTICS", heading_style))
        
        stats_data = [["Detection Type", "Count", "Percentage"]]
        total = sum(stats.values()) if stats else 1
        
        for category, count in stats.items():
            percentage = (count / total) * 100 if total > 0 else 0
            stats_data.append([category.title(), str(count), f"{percentage:.1f}%"])
        
        stats_table = Table(stats_data, colWidths=[2*inch, 1*inch, 1*inch])
        stats_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), self.PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            
            # Data styling
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        # Apply row colors based on detection type
        for i, (category, count) in enumerate(stats.items(), 1):
            if category == 'malicious':
                stats_table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.Color(1, 0.8, 0.8))]))
            elif category == 'suspicious':
                stats_table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.Color(1, 0.9, 0.7))]))
            elif category == 'undetected':
                stats_table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.Color(0.8, 1, 0.8))]))
        
        story.append(stats_table)
        story.append(Spacer(1, 0.3 * inch))
    
    def _create_engine_results_section(self, story, results, heading_style):
        """Create the security engine analysis section."""
        story.append(Paragraph("🔍 SECURITY ENGINE ANALYSIS", heading_style))
        
        # Major engines with enhanced styling
        major_engines = ["Kaspersky", "BitDefender", "ESET-NOD32", "Microsoft", "McAfee", "Symantec", "Avast", "AVG", "ClamAV", "F-Secure"]
        engine_data = [["Security Engine", "Detection Status", "Result/Signature"]]
        
        for engine in major_engines:
            engine_result = results.get(engine)
            if engine_result:
                category = engine_result.get('category', 'N/A')
                result = engine_result.get('result', 'Clean')
                
                # Status with emoji
                if category == 'malicious':
                    status = "🚨 MALICIOUS"
                elif category == 'suspicious':
                    status = "⚠️ SUSPICIOUS"
                elif category == 'undetected':
                    status = "✅ CLEAN"
                else:
                    status = f"ℹ️ {category.upper()}"
                    
                engine_data.append([engine, status, result])
            else:
                engine_data.append([engine, "❓ NO RESULT", "Not Available"])
        
        engine_table = Table(engine_data, colWidths=[1.5*inch, 1.5*inch, 2.5*inch])
        engine_table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), self.PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            
            # Data rows
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ('ALIGN', (2, 1), (2, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.SECONDARY_COLOR]),
        ]))
        
        story.append(engine_table)
        story.append(Spacer(1, 0.3 * inch))
    
    def _create_detections_section(self, story, results, heading_style, normal_style):
        """Create the detailed detections section."""
        # Detailed Detections if any
        detected = {k: v for k, v in results.items() if v.get("category") == "malicious"}
        if detected:
            story.append(Paragraph("🚨 MALICIOUS DETECTIONS FOUND", heading_style))
            
            detection_data = [["Security Engine", "Threat Classification", "Detection Confidence"]]
            for engine, result in detected.items():
                threat_name = result.get('result', 'Unknown Threat')
                confidence = "High" if result.get('category') == 'malicious' else "Medium"
                detection_data.append([engine, threat_name, confidence])
            
            detection_table = Table(detection_data, colWidths=[1.8*inch, 2.5*inch, 1.2*inch])
            detection_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.DANGER_COLOR),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                
                ('BACKGROUND', (0, 1), (-1, -1), colors.Color(1, 0.9, 0.9)),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(detection_table)
        else:
            story.append(Paragraph("✅ NO MALICIOUS THREATS DETECTED", heading_style))
            story.append(Paragraph("This file appears to be clean based on current security engine analysis.", normal_style))
        
        story.append(Spacer(1, 0.3 * inch))
    
    def _create_metadata_section(self, story, attributes, data, heading_style, normal_style):
        """Create the scan metadata section."""
        story.append(Paragraph("ℹ️ SCAN METADATA", heading_style))
        
        scan_date = attributes.get("last_analysis_date", None)
        if scan_date:
            try:
                readable_date = datetime.datetime.fromtimestamp(int(scan_date)).strftime('%B %d, %Y at %H:%M:%S UTC')
            except Exception:
                readable_date = str(scan_date)
        else:
            readable_date = "Not Available"
        
        metadata_text = f"""
        <para>
        <b>Last Analysis:</b> {readable_date}<br/>
        <b>Report Generated:</b> {datetime.datetime.now().strftime('%B %d, %Y at %H:%M:%S')}<br/>
        <b>Analysis ID:</b> {data.get('id', 'N/A')}<br/>
        <b>File Reputation:</b> {attributes.get('reputation', 'Unknown')}<br/>
        </para>
        """
        story.append(Paragraph(metadata_text, normal_style))
        
        # Footer disclaimer
        story.append(Spacer(1, 0.3 * inch))
        disclaimer = """
        <para align="center" fontSize="8" textColor="gray">
        <i>This report is generated by VirusTotal API analysis. Results may vary over time as new threat signatures are added.
        For the most current analysis, please visit virustotal.com. This tool is for educational and security research purposes.</i>
        </para>
        """
        story.append(Paragraph(disclaimer, normal_style))
    
    def generate_pdf_report(self, report_json, output_path):
        """Generate a professional PDF report from VirusTotal analysis results."""
        if not report_json or "data" not in report_json:
            print("No report data available.")
            return False
        
        try:
            data = report_json["data"]
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})
            
            # Extract file information
            file_info = self._extract_file_info(attributes)
            
            # Determine threat level
            threat_level, threat_color, threat_icon = self._determine_threat_level(stats)
            total_engines = sum(stats.values()) if stats else 0
            
            # Create custom styles
            styles, title_style, heading_style, normal_style = self._create_custom_styles()
            
            # Document setup with margins
            doc = SimpleDocTemplate(
                output_path, 
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            story = []
            
            # Create report sections
            self._create_header_section(story, styles, threat_level, threat_color, threat_icon, stats, total_engines)
            self._create_file_info_section(story, file_info, heading_style)
            self._create_detection_stats_section(story, stats, heading_style)
            self._create_engine_results_section(story, results, heading_style)
            self._create_detections_section(story, results, heading_style, normal_style)
            self._create_metadata_section(story, attributes, data, heading_style, normal_style)
            
            # Build the PDF
            doc.build(story)
            print(f"✅ Professional PDF report exported successfully to: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
            return False
