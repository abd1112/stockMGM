import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

def parse_whatweb_xml(xml_path, output_html_path='whatweb_dashboard.html'):
    if not os.path.exists(xml_path):
        print(f"❌ Error: Input file '{xml_path}' not found.")
        sys.exit(1)

    # WhatWeb XML might contain fragments or nested logs.
    # We read and safely wrap it in a single root element if standard parsing fails.
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        try:
            with open(xml_path, 'r', encoding='utf-8') as f:
                xml_data = f.read()
            # Wrap standard fragment data in a single results element
            if not xml_data.strip().startswith("<results>"):
                xml_data = f"<results>{xml_data}</results>"
            root = ET.fromstring(xml_data)
        except Exception as e:
            print(f"❌ Error reading/parsing XML fragment: {e}")
            sys.exit(1)

    targets_data = []

    # Process all parsed target entries
    for target in root.findall(".//target"):
        uri = target.findtext("uri", "Unknown URL")
        status = target.findtext("http-status", "Unknown")
        
        # Parse plugins into a lookup dictionary
        plugins_dict = {}
        all_plugins_list = []
        for plugin in target.findall("plugin"):
            name = plugin.findtext("name")
            if not name:
                continue
            string_val = plugin.findtext("string", "")
            version_val = plugin.findtext("version", "")
            
            plugins_dict[name.lower()] = {
                'name': name,
                'string': string_val,
                'version': version_val
            }
            all_plugins_list.append({
                'name': name,
                'string': string_val,
                'version': version_val
            })

        # --- Security Assessment Logic ---
        score = 0
        checks = []

        # 1. SSL/TLS Usage Check
        is_https = uri.lower().startswith("https://")
        if is_https:
            checks.append({
                "metric": "HTTPS Encryption",
                "status": "✓ Active",
                "severity": "Secure",
                "desc": "Traffic is securely encrypted via HTTPS.",
                "class": "status-pass"
            })
        else:
            score += 25
            checks.append({
                "metric": "HTTPS Encryption",
                "status": "❌ Missing",
                "severity": "High",
                "desc": "Plain HTTP protocol detected. Connection is susceptible to MiTM attacks.",
                "class": "status-fail"
            })

        # 2. HttpOnly Cookie Flag Check
        has_cookies = 'cookies' in plugins_dict
        has_httponly = 'httponly' in plugins_dict
        if has_cookies:
            if has_httponly:
                checks.append({
                    "metric": "HttpOnly Cookies",
                    "status": "✓ Enforced",
                    "severity": "Secure",
                    "desc": "Cookies are hidden from client-side script access, mitigating XSS extraction.",
                    "class": "status-pass"
                })
            else:
                score += 15
                checks.append({
                    "metric": "HttpOnly Cookies",
                    "status": "❌ Missing",
                    "severity": "Medium",
                    "desc": "Cookies detected without the HttpOnly attribute.",
                    "class": "status-fail"
                })
        else:
            checks.append({
                "metric": "HttpOnly Cookies",
                "status": "N/A",
                "severity": "Informational",
                "desc": "No active application cookies detected during scan.",
                "class": "status-info"
            })

        # 3. Clickjacking Protection Check (X-Frame-Options)
        has_x_frame = 'x-frame-options' in plugins_dict
        if has_x_frame:
            x_frame_val = plugins_dict['x-frame-options']['string'] or "SAMEORIGIN"
            checks.append({
                "metric": "Clickjacking Protection",
                "status": f"✓ Active ({x_frame_val})",
                "severity": "Secure",
                "desc": "X-Frame-Options header restricts unauthorized framing of page content.",
                "class": "status-pass"
            })
        else:
            score += 15
            checks.append({
                "metric": "Clickjacking Protection",
                "status": "❌ Missing",
                "severity": "Medium",
                "desc": "Missing X-Frame-Options; page could be framed by malicious sites.",
                "class": "status-fail"
            })

        # 4. Content Security Policy (CSP) Check
        uncommon_str = plugins_dict.get('uncommonheaders', {}).get('string', '').lower()
        has_csp = 'content-security-policy' in uncommon_str or 'content-security-policy' in plugins_dict
        if has_csp:
            checks.append({
                "metric": "Content Security Policy (CSP)",
                "status": "✓ Present",
                "severity": "Secure",
                "desc": "CSP rule mappings block unauthorized resource loading scripts.",
                "class": "status-pass"
            })
        else:
            score += 15
            checks.append({
                "metric": "Content Security Policy (CSP)",
                "status": "❌ Missing",
                "severity": "Medium",
                "desc": "No active CSP defined; lacks foundational defense against injection attacks.",
                "class": "status-fail"
            })

        # 5. MIME-Sniffing Protection Check (X-Content-Type-Options)
        has_x_content_type = 'x-content-type-options' in uncommon_str or 'x-content-type-options' in plugins_dict
        if has_x_content_type:
            checks.append({
                "metric": "MIME-Sniffing Protection",
                "status": "✓ Active",
                "severity": "Secure",
                "desc": "X-Content-Type-Options set to nosniff prevents file MIME-type tampering.",
                "class": "status-pass"
            })
        else:
            score += 10
            checks.append({
                "metric": "MIME-Sniffing Protection",
                "status": "❌ Missing",
                "severity": "Low",
                "desc": "Missing nosniff attribute; browsers might run stylesheet uploads as scripts.",
                "class": "status-fail"
            })

        # 6. XSS Header Check (X-XSS-Protection)
        has_xss = 'x-xss-protection' in plugins_dict
        if has_xss:
            xss_val = plugins_dict['x-xss-protection']['string'] or "1; mode=block"
            checks.append({
                "metric": "Cross-Site Scripting Filter",
                "status": f"✓ Enforced ({xss_val})",
                "severity": "Secure",
                "desc": "Browser built-in reflection filters are engaged.",
                "class": "status-pass"
            })
        else:
            score += 10
            checks.append({
                "metric": "Cross-Site Scripting Filter",
                "status": "❌ Missing",
                "severity": "Low",
                "desc": "Legacy XSS protection disabled or not defined.",
                "class": "status-fail"
            })

        # 7. Information Disclosure (Server Headers)
        server_signature = plugins_dict.get('httpserver', {}).get('string', '')
        if server_signature.strip():
            score += 10
            checks.append({
                "metric": "Server Banner Exposure",
                "status": "⚠️ Exposed",
                "severity": "Low",
                "desc": f"Web server exposed details: '{server_signature}'. Unnecessary exposure of core stack details.",
                "class": "status-warn"
            })
        else:
            checks.append({
                "metric": "Server Banner Exposure",
                "status": "✓ Hidden",
                "severity": "Secure",
                "desc": "The server banner is hidden, minimal, or obscured.",
                "class": "status-pass"
            })

        final_score = min(max(score, 0), 100)
        targets_data.append({
            'uri': uri,
            'status': status,
            'plugins': all_plugins_list,
            'checks': checks,
            'score': final_score
        })

    # Fallback default values if no targets are found
    if not targets_data:
        print("⚠️ No target blocks identified in the WhatWeb XML file.")
        sys.exit(1)

    # Select the primary audited target details for the summary
    primary_target = targets_data[0]
    security_score = primary_target['score']

    if security_score == 0:
        score_class = "safe"
        score_desc = "Excellent Web Server Hardening (0/100)"
    elif security_score < 30:
        score_class = "low"
        score_desc = "Good Hygiene, Low Risk Adjustments Needed"
    elif security_score < 60:
        score_class = "medium"
        score_desc = "Moderate Risk Exposure Detected"
    else:
        score_class = "critical"
        score_desc = "Insecure Exposure / Critical Missing Controls"

    # Assemble dynamic HTML structure
    repo = os.environ.get('GITHUB_REPOSITORY', 'Security Workspace')
    commit = os.environ.get('GITHUB_SHA', 'Local-Run')[:7]
    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>WhatWeb Footprint Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; color: #333; margin: 0; padding: 40px 20px; }}
        .wrapper {{ max-width: 1000px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
        h1, h2 {{ color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
        .meta-box {{ display: flex; justify-content: space-between; background: #f8fafc; padding: 15px; border-radius: 6px; margin-bottom: 30px; font-size: 14px; border-left: 4px solid #3b82f6; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0 40px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f1f5f9; color: #475569; font-weight: 600; }}
        
        .status-pass {{ color: #166534; font-weight: bold; background: #dcfce7; padding: 3px 8px; border-radius: 4px; }}
        .status-warn {{ color: #854d0e; font-weight: bold; background: #fef9c3; padding: 3px 8px; border-radius: 4px; }}
        .status-fail {{ color: #991b1b; font-weight: bold; background: #fee2e2; padding: 3px 8px; border-radius: 4px; }}
        .status-info {{ color: #1e3a8a; font-weight: bold; background: #dbeafe; padding: 3px 8px; border-radius: 4px; }}

        .score-container {{ text-align: center; padding: 30px; border-radius: 8px; margin-top: 20px; }}
        .score-container.safe {{ background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }}
        .score-container.low {{ background: #e3f2fd; color: #1565c0; border: 1px solid #bbdefb; }}
        .score-container.medium {{ background: #fff3e0; color: #e65100; border: 1px solid #ffe0b2; }}
        .score-container.critical {{ background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }}
        .score-value {{ font-size: 48px; font-weight: 800; margin: 10px 0; }}
        
        .plugin-tag {{ display: inline-block; background: #f1f5f9; color: #334155; padding: 4px 10px; border-radius: 4px; margin: 4px; font-size: 13px; font-family: monospace; border: 1px solid #cbd5e1; }}
    </style>
</head>
<body>
<div class="wrapper">
    <h1>Web Application Signature Profile (WhatWeb)</h1>
    <div class="meta-box">
        <div>
            <strong>Repository:</strong> {repo}<br>
            <strong>Commit:</strong> {commit}<br>
            <strong>Target URI:</strong> <code style="color: #2563eb;">{primary_target['uri']}</code> (HTTP {primary_target['status']})
        </div>
        <div style="text-align: right;"><strong>Scan Date:</strong><br>{date_str}</div>
    </div>

    <h2>1. Security Policy &amp; Header Checklist</h2>
    <table>
        <thead>
            <tr>
                <th>Evaluated Defense</th>
                <th>Check Status</th>
                <th>Baseline Severity</th>
                <th>Assessment Context</th>
            </tr>
        </thead>
        <tbody>"""

    for check in primary_target['checks']:
        html_content += f"""
            <tr>
                <td><strong>{check['metric']}</strong></td>
                <td><span class="{check['class']}">{check['status']}</span></td>
                <td><strong>{check['severity']}</strong></td>
                <td><span style="font-size: 13.5px; color: #475569;">{check['desc']}</span></td>
            </tr>"""

    html_content += """
        </tbody>
    </table>

    <h2>2. Technology &amp; Plugin Mappings</h2>
    <div style="background: #f8fafc; padding: 20px; border-radius: 6px; border: 1px solid #e2e8f0; margin-bottom: 45px;">"""

    for plugin in primary_target['plugins']:
        detail_txt = plugin['name']
        if plugin['version']:
            detail_txt += f" ({plugin['version']})"
        elif plugin['string']:
            detail_txt += f" [{plugin['string'][:40]}]"
            
        html_content += f"""<span class="plugin-tag">{detail_txt}</span>"""

    html_content += f"""
    </div>

    <h2>3. Web Configuration Security Score</h2>
    <div class="score-container {score_class}">
        <div style="font-size: 18px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Infrastructure Security Index</div>
        <div class="score-value">{security_score} / 100</div>
        <div style="font-size: 20px; font-weight: 700;">{score_desc}</div>
    </div>
</div>
</body>
</html>
"""

    with open(output_html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"✅ WhatWeb HTML Report successfully generated at: {output_html_path}")
    print(f"📊 Calculated Configuration Hygiene Score: {security_score}/100")

if __name__ == "__main__":
    target_xml = sys.argv[1] if len(sys.argv) > 1 else 'whatweb.xml'
    parse_whatweb_xml(target_xml)
