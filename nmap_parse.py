import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

def parse_nmap_xml(xml_path, output_html_path='nmap.html'):
    if not os.path.exists(xml_path):
        print(f"❌ Error: Input file '{xml_path}' not found.")
        sys.exit(1)

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"❌ Error parsing XML file: {e}")
        sys.exit(1)

    ports_data = []
    vulns_data = []
    max_cvss = 0.0

    # 1. Parse Ports and Vulnerabilities
    for port_elem in root.findall(".//port"):
        port_id = port_elem.attrib.get('portid')
        protocol = port_elem.attrib.get('protocol', 'tcp')
        full_port = f"{port_id}/{protocol.upper()}"

        # State info
        state_elem = port_elem.find('state')
        state = state_elem.attrib.get('state', 'unknown') if state_elem is not None else 'unknown'

        # Service / Version info
        service_elem = port_elem.find('service')
        service_name = 'unknown'
        version_info = 'N/A'
        if service_elem is not None:
            service_name = service_elem.attrib.get('name', 'unknown')
            product = service_elem.attrib.get('product', '')
            version = service_elem.attrib.get('version', '')
            extrainfo = service_elem.attrib.get('extrainfo', '')
            
            parts = [p for p in [product, version, extrainfo] if p]
            if parts:
                version_info = " ".join(parts)

        ports_data.append({
            'port': full_port,
            'state': state,
            'service': service_name,
            'version': version_info
        })

        # Process script security vulnerabilities
        for script in port_elem.findall('script'):
            script_id = script.attrib.get('id')

            # Handle structured "vulners" script outputs
            if script_id == 'vulners':
                for cpe_table in script.findall('.//table'):
                    for vuln_table in cpe_table.findall('table'):
                        id_elem = vuln_table.find("./elem[@key='id']")
                        cvss_elem = vuln_table.find("./elem[@key='cvss']")
                        
                        if id_elem is not None:
                            cve_id = id_elem.text
                            cvss_val = float(cvss_elem.text) if cvss_elem is not None else 0.0
                            
                            if cvss_val > max_cvss:
                                max_cvss = cvss_val

                            vulns_data.append({
                                'port': full_port,
                                'id': cve_id,
                                'title': f"Vulnerability detected via engine match ({service_name})",
                                'cvss': cvss_val
                            })

            # Handle direct vulnerability verification scripts (e.g., slowloris)
            else:
                state_elem = script.find(".//elem[@key='state']")
                if state_elem is not None and "VULNERABLE" in state_elem.text.upper():
                    title_elem = script.find(".//elem[@key='title']")
                    title = title_elem.text if title_elem is not None else script_id
                    
                    # Try to locate an explicitly assigned CVE tracking ID
                    cve_id = script_id
                    id_elem = script.find(".//table[@key='ids']/elem")
                    if id_elem is not None and id_elem.text:
                        cve_id = id_elem.text
                    
                    # Assign standard risk baseline if numerical matrix isn't present
                    default_cvss = 5.0  
                    if default_cvss > max_cvss:
                        max_cvss = default_cvss

                    vulns_data.append({
                        'port': full_port,
                        'id': cve_id,
                        'title': title,
                        'cvss': default_cvss
                    })

    # 2. Compute Security Rating Score out of 100
    # Map maximum detected CVSS score (0.0 - 10.0 scale) directly onto a 0 - 100 risk score
    security_score = int(max_cvss * 10)

    # Determine visual styling profiles based on threat metric levels
    if security_score == 0:
        score_class = "safe"
        score_desc = "System is Safe"
    elif security_score < 40:
        score_class = "low"
        score_desc = "Low Risk Factors Found"
    elif security_score < 70:
        score_class = "medium"
        score_desc = "Medium Risk Threats Identified"
    else:
        score_class = "critical"
        score_desc = "Very Critical Vulnerabilities Active!"

    # 3. Assemble Dynamic HTML Report
    repo = os.environ.get('GITHUB_REPOSITORY', 'Security Audit Workspace')
    commit = os.environ.get('GITHUB_SHA', 'Local-Execution')[:7]
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Nmap Audit Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; color: #333; margin: 0; padding: 40px 20px; }}
        .wrapper {{ max-width: 1000px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
        h1, h2 {{ color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
        .meta-box {{ display: flex; justify-content: space-between; background: #f8fafc; padding: 15px; border-radius: 6px; margin-bottom: 30px; font-size: 14px; border-left: 4px solid #64748b; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0 40px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f1f5f9; color: #475569; font-weight: 600; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .badge.open {{ background: #dcfce7; color: #166534; }}
        .badge.filtered {{ background: #fef9c3; color: #854d0e; }}
        .score-container {{ text-align: center; padding: 30px; border-radius: 8px; margin-top: 20px; }}
        .score-container.safe {{ background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }}
        .score-container.low {{ background: #fff3e0; color: #ef6c00; border: 1px solid #ffe0b2; }}
        .score-container.medium {{ background: #fff3e0; color: #e65100; border: 1px solid #ffe0b2; }}
        .score-container.critical {{ background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }}
        .score-value {{ font-size: 48px; font-weight: 800; margin: 10px 0; }}
        .cvss-high {{ color: #c62828; font-weight: bold; }}
        .cvss-med {{ color: #ef6c00; font-weight: bold; }}
        .no-data {{ color: #64748b; font-style: italic; text-align: center; padding: 20px; }}
    </style>
</head>
<body>
<div class="wrapper">
    <h1>Network Scan Report (Nmap)</h1>
    <div class="meta-box">
        <div><strong>Target Repository:</strong> {repo}<br><strong>Reference Commit:</strong> {commit}</div>
        <div style="text-align: right;"><strong>Scan Execution Timestamp:</strong><br>{date_str}</div>
    </div>

    <h2>1. Monitored Ports &amp; Infrastructure Services</h2>
    <table>
        <thead>
            <tr>
                <th>Port Interface</th>
                <th>Network State</th>
                <th>Core Service</th>
                <th>Software Version / Signature</th>
            </tr>
        </thead>
        <tbody>"""

    for p in ports_data:
        badge_cls = "open" if p['state'] == 'open' else "filtered"
        html_content += f"""
            <tr>
                <td><strong>{p['port']}</strong></td>
                <td><span class="badge {badge_cls}">{p['state']}</span></td>
                <td>{p['service']}</td>
                <td><code>{p['version']}</code></td>
            </tr>"""

    html_content += """
        </tbody>
    </table>

    <h2>2. Identified Target Vulnerabilities</h2>
    <table>
        <thead>
            <tr>
                <th>Interface</th>
                <th>Vulnerability ID</th>
                <th>Threat Summary Details</th>
                <th>Assigned CVSS Base</th>
            </tr>
        </thead>
        <tbody>"""

    if not vulns_data:
        html_content += """<tr><td colspan="4" class="no-data">No distinct software vulnerabilities discovered on open interfaces.</td></tr>"""
    else:
        # Sort vulnerabilities from highest risk to lowest
        for v in sorted(vulns_data, key=lambda x: x['cvss'], reverse=True):
            cvss_class = "cvss-high" if v['cvss'] >= 7.0 else ("cvss-med" if v['cvss'] >= 4.0 else "")
            html_content += f"""
                <tr>
                    <td>{v['port']}</td>
                    <td><code>{v['id']}</code></td>
                    <td>{v['title']}</td>
                    <td class="{cvss_class}">{v['cvss']}</td>
                </tr>"""

    html_content += f"""
        </tbody>
    </table>

    <h2>3. Automated Pipeline Risk Assessment Score</h2>
    <div class="score-container {score_class}">
        <div style="font-size: 18px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Overall Security Severity Metric</div>
        <div class="score-value">{security_score} / 100</div>
        <div style="font-size: 20px; font-weight: 700;">{score_desc}</div>
    </div>
</div>
</body>
</html>
"""

    with open(output_html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"✅ Clean Nmap HTML report successfully saved to: {output_html_path}")
    print(f"📊 Calculated Threat Evaluation Level: {security_score}/100")

if __name__ == "__main__":
    target_xml = sys.argv[1] if len(sys.argv) > 1 else 'nmap.xml'
    parse_nmap_xml(target_xml)