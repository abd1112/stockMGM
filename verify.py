import os
import sys
import zipfile
from datetime import datetime

def generate_report(zip_filepath, output_html_path='security-summary.html'):
    # Mapping of Scanner Name to the expected file inside the zip (from your first prompt)
    expected_files = {
        'Nmap': 'nmap-artifacts.html',
        'WhatWeb': 'whatweb-artifacts.html',
        'Nikto': 'nikto-artifact.html'
    }

    # Gather GitHub metadata dynamically
    repo = os.environ.get('GITHUB_REPOSITORY', 'Local-Test')
    commit = os.environ.get('GITHUB_SHA', 'unknown_commit')[:7] # Short hash
    current_date = datetime.now().strftime('%Y-%m-%d')

    # Default statuses
    statuses = {scanner: {'status': '❌', 'file': file_name, 'found': False} for scanner, file_name in expected_files.items()}
    all_successful = True

    # Check zip contents if the file exists
    if os.path.exists(zip_filepath):
        try:
            with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
                zip_contents = [os.path.basename(f) for f in zip_ref.namelist()]
                
                for scanner, info in statuses.items():
                    if info['file'] in zip_contents:
                        statuses[scanner]['status'] = '✓'
                        statuses[scanner]['found'] = True
                    else:
                        all_successful = False
        except zipfile.BadZipFile:
            all_successful = False
            print(f"Error: {zip_filepath} is a corrupted zip file.")
    else:
        all_successful = False
        print(f"Error: Zip file {zip_filepath} not found.")

    # Determine overall status text
    if all_successful:
        overall_status_text = "✓ All scans completed successfully"
        overall_class = "status-pass"
    else:
        overall_status_text = "❌ One or more scans failed or are missing reports"
        overall_class = "status-fail"

    # Generate HTML content with basic CSS styling for organization
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {repo}</title>
    <style>
        body {{ font-family: 'Courier New', Courier, monospace; line-height: 1.6; padding: 20px; background-color: #f9f9f9; color: #333; }}
        .container {{ max-width: 650px; background: white; padding: 30px; border: 1px solid #ddd; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
        h1 {{ margin-top: 0; color: #111; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .metadata {{ margin-bottom: 20px; color: #555; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ border-bottom: 2px solid #ddd; }}
        .status-pass {{ color: #2e7d32; font-weight: bold; }}
        .status-fail {{ color: #c62828; font-weight: bold; }}
        .divider {{ border-top: 1px dashed #bbb; margin: 20px 0; }}
        .summary-box {{ padding: 12px; background: #f0f0f0; border-radius: 4px; font-weight: bold; }}
        .summary-box.status-pass {{ background: #e8f5e9; }}
        .summary-box.status-fail {{ background: #ffebee; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Security Report</h1>
    
    <div class="metadata">
        <strong>Repository :</strong> {repo}<br>
        <strong>Commit     :</strong> {commit}<br>
        <strong>Date       :</strong> {current_date}
    </div>

    <div class="divider"></div>

    <table>
        <thead>
            <tr>
                <th>Scanner</th>
                <th>Status</th>
                <th>Report File</th>
            </tr>
        </thead>
        <tbody>
    """

    for scanner, info in statuses.items():
        status_class = "status-pass" if info['found'] else "status-fail"
        html_content += f"""
            <tr>
                <td><strong>{scanner}</strong></td>
                <td class="{status_class}">{info['status']}</td>
                <td>{info['file']}</td>
            </tr>"""

    html_content += f"""
        </tbody>
    </table>

    <div class="divider"></div>

    <h3>Overall Status</h3>
    <div class="summary-box {overall_class}">
        {overall_status_text}
    </div>
</div>
</body>
</html>
"""

    # Write the report file
    with open(output_html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"📊 Dashboard generated at: {output_html_path}")

    # Still enforce the pipeline failure if things went wrong
    if not all_successful:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    zip_file = sys.argv[1] if len(sys.argv) > 1 else 'merged-reports.zip'
    generate_report(zip_file)