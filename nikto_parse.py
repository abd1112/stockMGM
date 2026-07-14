#!/usr/bin/env python3
import os
import sys
import re
import html

def polish_links(html_string):
    """Adds security targets and CSS styling to raw HTML anchor links."""
    if not html_string:
        return "<em>None</em>"
    # Transform references and links to open in a new tab securely with styled dashboard utility classes
    html_string = re.sub(
        r'<a\s+href=', 
        r'<a class="dashboard-link" target="_blank" rel="noopener noreferrer" href=', 
        html_string
    )
    # Fix instances where double/single quotes might conflict
    html_string = html_string.replace("<a href='", "<a class=\"dashboard-link\" target=\"_blank\" rel=\"noopener noreferrer\" href='")
    return html_string

def classify_finding(description):
    """
    Analyzes the description text of a Nikto finding to classify its severity
    and compute a dynamic threat risk score penalty.
    """
    desc_lower = description.lower()
    
    # High Severity Indicators (Critical Flaws, Arbitrary Access, Code Execution)
    high_indicators = [
        "vulnerable to", "exploit", "rce", "remote code execution", "sql injection", 
        "sqli", "arbitrary file", "backdoor", "shell", "default password", 
        "private key", "directory traversal", "path traversal", "command injection"
    ]
    
    # Medium Severity Indicators (Missing critical HTTP headers, SSL issues, major configuration exposures)
    med_indicators = [
        "breach attack", "clickjacking", "xss", "cross-site scripting", 
        "strict-transport-security", "x-frame-options", "x-content-type-options", 
        "certificate", "mismatched", "not defined", "weak cipher", "old version",
        "out of date", "vulnerable"
    ]
    
    for ind in high_indicators:
        if ind in desc_lower:
            return "High", 25, "severity-high"
            
    for ind in med_indicators:
        if ind in desc_lower:
            return "Medium", 12, "severity-med"
            
    # Informational or low configuration adjustments
    return "Low", 5, "severity-low"

def parse_nikto_html(input_filepath, output_filepath):
    if not os.path.exists(input_filepath):
        print(f"[-] Error: Input file '{input_filepath}' not found.")
        sys.exit(1)
        
    print(f"[*] Parsing Nikto report: {input_filepath}...")
    
    with open(input_filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
        
    # Split by the raw <table> tags (resilient against unclosed/malformed tags)
    tables = re.split(r'<table', content, flags=re.IGNORECASE)
    
    target_info = {}
    findings = []
    host_summary = {}
    scan_summary = {}
    
    # Key-value extraction regex focusing purely on the cell contents
    pattern = re.compile(r'<td class="column-head">(.*?)</td>\s*<td>(.*?)</td>', re.DOTALL | re.IGNORECASE)
    
    for block in tables:
        pairs = pattern.findall(block)
        if not pairs:
            continue
            
        data_dict = {}
        for k, v in pairs:
            clean_k = re.sub(r'<[^>]+>', '', k).strip()
            data_dict[clean_k] = v.strip()
            
        if "Target IP" in data_dict:
            target_info.update(data_dict)
        elif "URI" in data_dict and "Description" in data_dict:
            findings.append(data_dict)
        elif "Statistics" in data_dict:
            host_summary.update(data_dict)
        elif "Software Details" in data_dict:
            scan_summary.update(data_dict)

    # Calculate dynamically assessed security score metrics
    total_penalty = 0
    classified_findings = []
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    
    for f in findings:
        desc = f.get('Description', 'No description.')
        severity, penalty, badge_class = classify_finding(desc)
        total_penalty += penalty
        severity_counts[severity] += 1
        
        classified_findings.append({
            'uri': html.escape(f.get('URI', '/')),
            'method': html.escape(f.get('HTTP Method', 'GET')),
            'description': html.escape(desc),
            'test_links': polish_links(f.get('Test Links', '')),
            'references': polish_links(f.get('References', '')),
            'severity': severity,
            'badge_class': badge_class
        })
        
    security_score = max(100 - total_penalty, 0)
    
    if security_score == 100:
        score_class = "safe"
        score_desc = "Excellent Web Server Hardening (No Findings)"
    elif security_score >= 80:
        score_class = "low"
        score_desc = "Low Risk Factors Identified"
    elif security_score >= 50:
        score_class = "medium"
        score_desc = "Moderate Threat Profile Activated"
    else:
        score_class = "critical"
        score_desc = "Critical Vulnerability Actions Required"

    # HTML Dashboard Template Generation
    dashboard_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nikto Security Dashboard</title>
    <style>
        :root {{
            --primary: #0f172a;
            --secondary: #1e293b;
            --accent: #2563eb;
            --bg-main: #f8fafc;
            --card-bg: #ffffff;
            --border: #e2e8f0;
            --text-dark: #0f172a;
            --text-muted: #64748b;
            
            --safe-bg: #f0fdf4;
            --safe-text: #16a34a;
            --safe-border: #bbf7d0;
            
            --low-bg: #eff6ff;
            --low-text: #2563eb;
            --low-border: #bfdbfe;
            
            --med-bg: #fff7ed;
            --med-text: #ea580c;
            --med-border: #fed7aa;
            
            --high-bg: #fef2f2;
            --high-text: #dc2626;
            --high-border: #fca5a5;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-dark);
            line-height: 1.5;
            padding: 40px 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}

        h1 {{
            font-size: 28px;
            font-weight: 800;
            color: var(--primary);
        }}

        .engine-tag {{
            background: var(--secondary);
            color: #fff;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
        }}

        /* Grid Layout */
        .dashboard-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }}

        @media (max-width: 900px) {{
            .dashboard-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
        }}

        .card-title {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 20px;
            color: var(--secondary);
        }}

        /* Target Meta Info */
        .meta-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .meta-table tr {{
            border-bottom: 1px solid var(--border);
        }}

        .meta-table tr:last-child {{
            border-bottom: none;
        }}

        .meta-table td {{
            padding: 12px 8px;
            font-size: 14px;
        }}

        .meta-table td.label {{
            font-weight: 600;
            color: var(--text-muted);
            width: 35%;
        }}

        .meta-table td.value {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            color: var(--text-dark);
        }}

        /* Score Card Styling */
        .score-card {{
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
        }}

        .score-card.safe {{ background: var(--safe-bg); border-color: var(--safe-border); color: var(--safe-text); }}
        .score-card.low {{ background: var(--low-bg); border-color: var(--low-border); color: var(--low-text); }}
        .score-card.medium {{ background: var(--med-bg); border-color: var(--med-border); color: var(--med-text); }}
        .score-card.critical {{ background: var(--high-bg); border-color: var(--high-border); color: var(--high-text); }}

        .score-circle {{
            width: 140px;
            height: 140px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            border: 8px solid currentColor;
            margin-bottom: 15px;
        }}

        .score-number {{
            font-size: 42px;
            font-weight: 900;
        }}

        .score-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: bold;
        }}

        .score-desc {{
            font-weight: 700;
            font-size: 16px;
        }}

        /* Severity Breakdown Badges */
        .severity-summary {{
            display: flex;
            justify-content: space-around;
            width: 100%;
            margin-top: 20px;
            border-top: 1px solid var(--border);
            padding-top: 15px;
        }}

        .summary-badge {{
            display: flex;
            flex-direction: column;
            align-items: center;
        }}

        .summary-count {{
            font-size: 20px;
            font-weight: 800;
        }}

        .summary-label {{
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
        }}

        /* Findings Table Styling */
        .filter-controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            gap: 15px;
            flex-wrap: wrap;
        }}

        .search-bar {{
            padding: 8px 16px;
            font-size: 14px;
            border: 1px solid var(--border);
            border-radius: 8px;
            width: 100%;
            max-width: 300px;
            outline: none;
        }}

        .search-bar:focus {{
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
        }}

        .filter-buttons {{
            display: flex;
            gap: 8px;
        }}

        .btn {{
            padding: 6px 14px;
            font-size: 13px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            border: 1px solid var(--border);
            background: #fff;
            color: var(--text-muted);
            transition: all 0.2s ease;
        }}

        .btn:hover {{
            background: var(--bg-main);
        }}

        .btn.active {{
            background: var(--primary);
            color: #fff;
            border-color: var(--primary);
        }}

        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}

        .findings-table th {{
            background: var(--bg-main);
            color: var(--text-muted);
            padding: 12px 16px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--border);
        }}

        .findings-table td {{
            padding: 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}

        .finding-row:hover {{
            background: #fafafa;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            text-align: center;
        }}

        .badge.severity-high {{ background: var(--high-bg); color: var(--high-text); border: 1px solid var(--high-border); }}
        .badge.severity-med {{ background: var(--med-bg); color: var(--med-text); border: 1px solid var(--med-border); }}
        .badge.severity-low {{ background: var(--low-bg); color: var(--low-text); border: 1px solid var(--low-border); }}

        .uri-cell {{
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-weight: 600;
            color: var(--accent);
            word-break: break-all;
        }}

        .method-badge {{
            background: #e2e8f0;
            color: #334155;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 11px;
            font-weight: bold;
        }}

        .desc-text {{
            color: var(--text-dark);
            margin-bottom: 8px;
        }}

        .links-group {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 6px;
        }}

        .dashboard-link {{
            color: var(--accent);
            text-decoration: none;
            word-break: break-all;
        }}

        .dashboard-link:hover {{
            text-decoration: underline;
        }}

        /* Scan Summary Card */
        .scan-stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }}

        .stat-card {{
            background: #fff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}

        .stat-num {{
            font-size: 22px;
            font-weight: 800;
            color: var(--primary);
        }}

        .stat-lbl {{
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-top: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Nikto Vulnerability Dashboard</h1>
                <p style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">Interactive assessment of target posture and missing headers</p>
            </div>
            <div class="engine-tag">{html.escape(scan_summary.get('Software Details', 'Nikto Security Engine'))}</div>
        </header>

        <div class="dashboard-grid">
            <!-- Left Side: Target Information -->
            <div class="card">
                <div class="card-title">Target Information</div>
                <table class="meta-table">
                    <tr>
                        <td class="label">Target IP</td>
                        <td class="value">{html.escape(target_info.get('Target IP', 'Unknown'))}</td>
                    </tr>
                    <tr>
                        <td class="label">Target Hostname</td>
                        <td class="value">{html.escape(target_info.get('Target hostname', 'Unknown'))}</td>
                    </tr>
                    <tr>
                        <td class="label">Target Port</td>
                        <td class="value">{html.escape(target_info.get('Target Port', 'Unknown'))}</td>
                    </tr>
                    <tr>
                        <td class="label">HTTP Server Header</td>
                        <td class="value">{html.escape(target_info.get('HTTP Server', 'No response signature'))}</td>
                    </tr>
                    <tr>
                        <td class="label">Web Application Path</td>
                        <td class="value">{polish_links(target_info.get('Site Link (Name)', ''))}</td>
                    </tr>
                </table>
            </div>

            <!-- Right Side: Security Score Summary -->
            <div class="card score-card {score_class}">
                <div class="score-circle">
                    <span class="score-number">{security_score}</span>
                    <span class="score-label">Score</span>
                </div>
                <div class="score-desc">{score_desc}</div>
                
                <div class="severity-summary">
                    <div class="summary-badge">
                        <span class="summary-count" style="color: var(--high-text);">{severity_counts['High']}</span>
                        <span class="summary-label">High</span>
                    </div>
                    <div class="summary-badge">
                        <span class="summary-count" style="color: var(--med-text);">{severity_counts['Medium']}</span>
                        <span class="summary-label">Medium</span>
                    </div>
                    <div class="summary-badge">
                        <span class="summary-count" style="color: var(--low-text);">{severity_counts['Low']}</span>
                        <span class="summary-label">Low/Info</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Vulnerability Finding Panel -->
        <div class="card" style="margin-bottom: 40px;">
            <div class="filter-controls">
                <div class="card-title" style="margin-bottom: 0;">Vulnerability Findings & Exposed Resources</div>
                <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <input type="text" id="search-input" class="search-bar" placeholder="Filter findings..." oninput="searchFindings()">
                    <div class="filter-buttons">
                        <button class="btn active" id="btn-all" onclick="filterSeverity('all')">All</button>
                        <button class="btn" id="btn-high" onclick="filterSeverity('High')">High</button>
                        <button class="btn" id="btn-med" onclick="filterSeverity('Medium')">Medium</button>
                        <button class="btn" id="btn-low" onclick="filterSeverity('Low')">Low</button>
                    </div>
                </div>
            </div>

            <table class="findings-table">
                <thead>
                    <tr>
                        <th style="width: 12%;">Severity</th>
                        <th style="width: 25%;">Target URI / Method</th>
                        <th style="width: 63%;">Description / References</th>
                    </tr>
                </thead>
                <tbody id="findings-body">
                """
                
    if not classified_findings:
        dashboard_html += """
                    <tr>
                        <td colspan="3" class="no-data" style="text-align: center; padding: 40px; color: var(--text-muted);">
                            No security findings identified by Nikto. Excellent server defense state!
                        </td>
                    </tr>
        """
    else:
        for f in classified_findings:
            dashboard_html += f"""
                    <tr class="finding-row" data-severity="{f['severity']}">
                        <td><span class="badge {f['badge_class']}">{f['severity']}</span></td>
                        <td>
                            <span class="method-badge">{f['method']}</span>
                            <div class="uri-cell">{f['uri']}</div>
                        </td>
                        <td>
                            <div class="desc-text">{f['description']}</div>
                            {f'<div class="links-group"><strong>Verification:</strong> {f["test_links"]}</div>' if f["test_links"] != '<em>None</em>' else ''}
                            {f'<div class="links-group"><strong>References:</strong> {f["references"]}</div>' if f["references"] != '<em>None</em>' else ''}
                        </td>
                    </tr>
            """

    dashboard_html += f"""
                </tbody>
            </table>
        </div>

        <!-- CLI Output Meta Stats -->
        <div class="card">
            <div class="card-title">Scan Metadata & Execution Details</div>
            <div class="meta-table-container">
                <table class="meta-table">
                    <tr>
                        <td class="label">Command Line Parameters</td>
                        <td class="value" style="font-size: 12px;">{html.escape(scan_summary.get('CLI Options', 'N/A'))}</td>
                    </tr>
                    <tr>
                        <td class="label">Duration Metrics</td>
                        <td class="value">{html.escape(host_summary.get('Elapsed Time', 'N/A'))} ({html.escape(host_summary.get('Statistics', 'Unknown packets sent'))})</td>
                    </tr>
                    <tr>
                        <td class="label">Scan Commenced</td>
                        <td class="value">{html.escape(host_summary.get('Start Time', 'N/A'))}</td>
                    </tr>
                    <tr>
                        <td class="label">Scan Concluded</td>
                        <td class="value">{html.escape(host_summary.get('End Time', 'N/A'))}</td>
                    </tr>
                </table>
            </div>
            
            <div class="scan-stats-grid">
                <div class="stat-card">
                    <div class="stat-num">{html.escape(host_summary.get('Statistics', '').split(',')[0].replace('requests', '').strip() if ',' in host_summary.get('Statistics', '') else 'N/A')}</div>
                    <div class="stat-lbl">Requests Executed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-num">{html.escape(host_summary.get('Statistics', '').split(',')[1].replace('errors', '').strip() if ',' in host_summary.get('Statistics', '') else 'N/A')}</div>
                    <div class="stat-lbl">Errors Encountered</div>
                </div>
                <div class="stat-card">
                    <div class="stat-num">{len(classified_findings)}</div>
                    <div class="stat-lbl">Identified Findings</div>
                </div>
            </div>
        </div>
        
        <p style="text-align: center; color: var(--text-muted); font-size: 11px; margin-top: 40px; font-style: italic;">
            &copy; Chris Sullo - Nikto Report converted via Modern Automated Engine Parser.
        </p>
    </div>

    <!-- Live Client Filtering Mechanics -->
    <script>
        function filterSeverity(severity) {{
            // Toggle active button state
            document.querySelectorAll('.filter-buttons .btn').forEach(btn => {{
                btn.classList.remove('active');
            }});
            
            const activeBtn = document.getElementById('btn-' + severity.toLowerCase());
            if (activeBtn) activeBtn.classList.add('active');

            // Toggle rows
            const rows = document.querySelectorAll('.finding-row');
            rows.forEach(row => {{
                if (severity === 'all' || row.dataset.severity === severity) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}

        function searchFindings() {{
            const input = document.getElementById('search-input').value.toLowerCase();
            const rows = document.querySelectorAll('.finding-row');
            rows.forEach(row => {{
                const text = row.innerText.toLowerCase();
                if (text.includes(input)) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.write(dashboard_html)
        
    print(f"[+] Success! Modern dashboard written to: '{output_filepath}'")

if __name__ == "__main__":
    input_file = sys.argv[1] if len(sys.argv) > 1 else 'nikto.htm'
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'nikto_dashboard.html'
    parse_nikto_html(input_file, output_file)
