from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.units import inch
import os


def generate_pdf(
    scan_id,
    target,
    scan_date,
    results,
    recommendations,
    scan_duration=None
):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    file_path = (
        f"reports/scan_report_{scan_id}.pdf"
    )

    document = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=16,
        spaceBefore=15,
        spaceAfter=10
    )

    normal_style = styles["BodyText"]

    story = []


    # =========================================================
    # TITLE
    # =========================================================

    story.append(
        Paragraph(
            "PORT SCANNER SECURITY REPORT",
            title_style
        )
    )

    story.append(
        Spacer(1, 10)
    )


    # =========================================================
    # SCAN INFORMATION
    # =========================================================

    story.append(
        Paragraph(
            "Scan Information",
            heading_style
        )
    )


    # Format scan duration
    if scan_duration is not None:

        duration_text = (
            f"{scan_duration} seconds"
        )

    else:

        duration_text = "-"


    scan_info = [

        [
            "Scan ID",
            str(scan_id)
        ],

        [
            "Target",
            str(target)
        ],

        [
            "Scan Date",
            str(scan_date)
        ],

        [
            "Total Ports",
            str(len(results))
        ],

        [
            "Scan Duration",
            duration_text
        ]

    ]


    info_table = Table(
        scan_info,
        colWidths=[
            1.5 * inch,
            4.8 * inch
        ]
    )


    info_table.setStyle(
        TableStyle([

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),

            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            ),

        ])
    )


    story.append(
        info_table
    )

    story.append(
        Spacer(1, 20)
    )


    # =========================================================
    # PORT SCAN RESULTS
    # =========================================================

    story.append(
        Paragraph(
            "Port Scan Results",
            heading_style
        )
    )


    table_data = [

        [
            "Port",
            "Protocol",
            "State",
            "Service",
            "Version"
        ]

    ]


    for result in results:

        table_data.append([

            str(
                result.get(
                    "port",
                    "-"
                )
            ),

            str(
                result.get(
                    "protocol",
                    "-"
                )
            ),

            str(
                result.get(
                    "state",
                    "-"
                )
            ),

            str(
                result.get(
                    "service",
                    "-"
                )
            ),

            str(
                result.get(
                    "version",
                    "-"
                )
            )

        ])


    results_table = Table(
        table_data,
        repeatRows=1,
        colWidths=[

            0.7 * inch,

            0.9 * inch,

            0.9 * inch,

            1.3 * inch,

            2.5 * inch

        ]
    )


    results_table.setStyle(
        TableStyle([

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),

        ])
    )


    story.append(
        results_table
    )

    story.append(
        Spacer(1, 20)
    )


    # =========================================================
    # CVE VULNERABILITIES
    # =========================================================

    cve_results = []


    for result in results:

        for cve in result.get(
            "cves",
            []
        ):

            cve_results.append({

                "port": result.get(
                    "port",
                    "-"
                ),

                "service": result.get(
                    "service",
                    "-"
                ),

                "version": result.get(
                    "version",
                    "-"
                ),

                "cve_id": cve.get(
                    "cve_id",
                    "Unknown CVE"
                ),

                "severity": cve.get(
                    "severity",
                    "UNKNOWN"
                ),

                "score": cve.get(
                    "score",
                    "-"
                ),

                "description": cve.get(
                    "description",
                    "No description available."
                )

            })


    if cve_results:

        story.append(
            Paragraph(
                "CVE Vulnerabilities",
                heading_style
            )
        )


        for cve in cve_results:

            story.append(
                Paragraph(
                    f"<b>{cve['cve_id']}</b>",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Port:</b> {cve['port']}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Service:</b> {cve['service']}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Version:</b> {cve['version']}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Severity:</b> {cve['severity']}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>CVSS Score:</b> {cve['score']}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Description:</b> {cve['description']}",
                    normal_style
                )
            )

            story.append(
                Spacer(1, 10)
            )


        story.append(
            Spacer(1, 10)
        )


    # =========================================================
    # SECURITY RECOMMENDATIONS
    # =========================================================

    story.append(
        Paragraph(
            "Security Recommendations",
            heading_style
        )
    )


    if recommendations:

        for recommendation in recommendations:

            story.append(
                Paragraph(
                    "• " + str(
                        recommendation
                    ),
                    normal_style
                )
            )

            story.append(
                Spacer(1, 6)
            )

    else:

        story.append(
            Paragraph(
                "No specific security recommendations.",
                normal_style
            )
        )


    story.append(
        Spacer(1, 20)
    )


    # =========================================================
    # FOOTER
    # =========================================================

    story.append(
        Paragraph(
            "Generated by Port Scanner Report Generator",
            normal_style
        )
    )


    # =========================================================
    # BUILD PDF
    # =========================================================

    document.build(
        story
    )


    return file_path