#!/usr/bin/env python3
"""
SQLiPwn Report Generator
Professional HTML and JSON reporting for SQL injection vulnerabilities
Optimized version with improved performance and functionality
"""

import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from dataclasses import asdict
from typing import List, Dict
from colorama import Fore

class ReportGenerator:
    """Professional reporting system with HTML dashboard and JSON export"""
    
    def __init__(self, target_url: str):
        self.vulnerabilities = []
        self.start_time = datetime.now()
        self.target_url = target_url
        self.target_domain = self._extract_domain(target_url)
        self.scan_stats = {
            'urls_crawled': 0,
            'parameters_tested': 0,
            'requests_made': 0
        }
    
    def _extract_domain(self, url: str) -> str:
        """Extract clean domain name from URL for filename"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Remove www. prefix and clean up
            if domain.startswith('www.'):
                domain = domain[4:]
            # Replace dots and colons with underscores for filename
            return domain.replace('.', '_').replace(':', '_')
        except:
            return "target"
    
    def add_vulnerability(self, vuln):
        """Add vulnerability and display real-time"""
        self.vulnerabilities.append(vuln)
        self._display_vulnerability(vuln)
    
    def _display_vulnerability(self, vuln):
        """Display vulnerability in real-time with color coding"""
        colors = {'HIGH': Fore.RED, 'MEDIUM': Fore.YELLOW, 'LOW': Fore.CYAN}
        color = colors.get(vuln.confidence, Fore.WHITE)
        
        print(f"\n{color}{'='*70}")
        print(f"{color}[!] VULNERABILITY DETECTED - {vuln.confidence} CONFIDENCE")
        print(f"{color}{'='*70}")
        print(f"{Fore.WHITE}URL:        {vuln.url}")
        print(f"{Fore.WHITE}Parameter:  {vuln.parameter}")
        print(f"{Fore.WHITE}Method:     {vuln.method}")
        print(f"{Fore.WHITE}Type:       {vuln.injection_type}")
        print(f"{Fore.WHITE}Payload:    {vuln.payload}")
        print(f"{Fore.WHITE}Response:   {vuln.response_time:.2f}s")
        print(f"{Fore.WHITE}Error:      {vuln.error_message}")
        print(f"{Fore.WHITE}Auth:       {'Yes' if vuln.authenticated else 'No'}")
        print(f"{Fore.GREEN}SQLMap:     {vuln.sqlmap_command}")
        print(f"{color}{'='*70}\n")
    
    def generate_html_report(self, filename: str = None) -> str:
        """Generate professional HTML dashboard report"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"sqlipwn_report_{self.target_domain}_{timestamp}.html"
        
        duration = datetime.now() - self.start_time
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self._generate_html_content(duration))
            print(f"{Fore.GREEN}[+] HTML dashboard saved: {filename}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving HTML report: {e}")
        
        return filename
    
    def _generate_html_content(self, duration) -> str:
        """Generate the complete HTML content for the report"""
        # Generate vulnerability cards
        vuln_html = ""
        if self.vulnerabilities:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                risk_class = f"{vuln.confidence.lower()}-risk"
                confidence_class = f"confidence-{vuln.confidence.lower()}"
                auth_badge = "auth-yes" if vuln.authenticated else "auth-no"
                
                # Properly escape quotes and special characters for JavaScript
                escaped_sqlmap = (vuln.sqlmap_command
                                .replace('\\', '\\\\')
                                .replace("'", "\\'")
                                .replace('"', '\\"')
                                .replace('\n', '\\n')
                                .replace('\r', '\\r'))
                
                # Escape HTML content
                def html_escape(text):
                    return (str(text)
                           .replace('&', '&amp;')
                           .replace('<', '&lt;')
                           .replace('>', '&gt;')
                           .replace('"', '&quot;')
                           .replace("'", '&#x27;'))
                
                vuln_html += f"""
                <div class="vulnerability {risk_class}">
                    <div class="vuln-header">
                        <h3>
                            <span class="vuln-number">#{i}</span>
                            {html_escape(vuln.injection_type)}
                            <span class="confidence-badge {confidence_class}">{vuln.confidence}</span>
                            <span class="auth-badge {auth_badge}">
                                {'Auth' if vuln.authenticated else 'No Auth'}
                            </span>
                        </h3>
                    </div>
                    <div class="vuln-details">
                        <div class="detail-item">
                            <span class="label">URL:</span>
                            <span class="value url-value">{html_escape(vuln.url)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Parameter:</span>
                            <span class="value code">{html_escape(vuln.parameter)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Method:</span>
                            <span class="value method-badge">{vuln.method}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Payload:</span>
                            <span class="value code payload-value">{html_escape(vuln.payload)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Response Time:</span>
                            <span class="value">{vuln.response_time:.2f}s</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Error:</span>
                            <span class="value error-details">{html_escape(vuln.error_message)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Detected:</span>
                            <span class="value">{vuln.timestamp}</span>
                        </div>
                    </div>
                    <div class="exploitation-section">
                        <h4>SQLMap Exploitation Command</h4>
                        <div class="sqlmap-container">
                            <div class="sqlmap-command" id="sqlmap-{i}">
                                <code>{html_escape(vuln.sqlmap_command)}</code>
                            </div>
                            <button class="copy-btn" onclick="copyToClipboard('{escaped_sqlmap}', this, 'sqlmap-{i}')">
                                <span class="copy-icon">📋</span> Copy
                            </button>
                        </div>
                    </div>
                </div>
                """
        else:
            vuln_html = '''
            <div class="no-vulns">
                <div class="success-icon">✓</div>
                <h3>No SQL Injection Vulnerabilities Detected!</h3>
                <p>The security scan completed without finding any SQL injection vulnerabilities.</p>
            </div>
            '''
        
        # Build complete HTML document
        current_time = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
        duration_str = str(duration).split('.')[0]
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLiPwn Security Report - {self.target_domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #2d3748; 
            line-height: 1.6; 
            min-height: 100vh;
        }}
        
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        
        .header {{ 
            background: rgba(255, 255, 255, 0.95); 
            backdrop-filter: blur(10px);
            color: #2d3748; 
            padding: 30px; 
            border-radius: 20px; 
            margin-bottom: 30px; 
            text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{ 
            font-size: 2.5em; 
            margin-bottom: 10px;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
        }}
        
        .header .subtitle {{
            color: #e53e3e;
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 10px;
        }}
        
        .header p {{ font-size: 1em; opacity: 0.8; }}
        
        .summary {{ 
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 25px; 
            border-radius: 15px; 
            margin-bottom: 25px; 
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }}
        
        .summary h2 {{ color: #2d3748; margin-bottom: 20px; }}
        
        .stats-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
        }}
        
        .stat-card {{ 
            text-align: center; 
            padding: 20px; 
            background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
            border-radius: 12px; 
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .stat-card:hover {{ 
            transform: translateY(-3px); 
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }}
        
        .stat-number {{ 
            font-size: 2em; 
            font-weight: 700; 
            margin-bottom: 8px;
            display: block;
        }}
        
        .stat-label {{ color: #718096; font-weight: 500; }}
        
        .confidence-high {{ color: #e53e3e; }}
        .confidence-medium {{ color: #dd6b20; }}
        .confidence-low {{ color: #3182ce; }}
        
        .vulnerabilities {{ margin-top: 25px; }}
        .vulnerabilities h2 {{ 
            color: #2d3748; 
            margin-bottom: 20px; 
            background: rgba(255, 255, 255, 0.95);
            padding: 20px;
            border-radius: 12px;
            backdrop-filter: blur(10px);
        }}
        
        .vulnerability {{ 
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            margin: 20px 0; 
            border-radius: 15px; 
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            overflow: hidden;
            transition: transform 0.3s ease;
        }}
        
        .vulnerability:hover {{ transform: translateY(-2px); }}
        
        .high-risk {{ border-left: 5px solid #e53e3e; }}
        .medium-risk {{ border-left: 5px solid #dd6b20; }}
        .low-risk {{ border-left: 5px solid #3182ce; }}
        
        .vuln-header {{
            background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
            padding: 20px;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .vuln-header h3 {{ 
            color: #2d3748; 
            font-size: 1.3em;
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }}
        
        .vuln-number {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .confidence-badge {{
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .confidence-badge.confidence-high {{ background: #fed7d7; color: #c53030; }}
        .confidence-badge.confidence-medium {{ background: #feebc8; color: #c05621; }}
        .confidence-badge.confidence-low {{ background: #bee3f8; color: #2c5282; }}
        
        .auth-badge {{
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.75em;
            font-weight: 600;
        }}
        
        .auth-badge.auth-yes {{ background: #c6f6d5; color: #22543d; }}
        .auth-badge.auth-no {{ background: #fed7d7; color: #c53030; }}
        
        .vuln-details {{ padding: 20px; }}
        
        .detail-item {{
            display: flex;
            align-items: flex-start;
            padding: 10px 0;
            border-bottom: 1px solid #f1f5f9;
        }}
        
        .detail-item:last-child {{ border-bottom: none; }}
        
        .label {{ 
            font-weight: 600; 
            color: #4a5568; 
            min-width: 120px;
            margin-right: 15px;
        }}
        
        .value {{ 
            flex: 1; 
            word-break: break-all;
        }}
        
        .code {{ 
            font-family: 'Monaco', 'Consolas', monospace; 
            background: #f7fafc; 
            padding: 3px 6px; 
            border-radius: 4px; 
            font-size: 0.9em;
            border: 1px solid #e2e8f0;
        }}
        
        .method-badge {{
            background: #bee3f8;
            color: #2c5282;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        
        .url-value {{ color: #3182ce; }}
        .payload-value {{ color: #c53030; }}
        .error-details {{ color: #d69e2e; }}
        
        .exploitation-section {{ 
            background: #1a202c; 
            color: #e2e8f0; 
            padding: 20px;
        }}
        
        .exploitation-section h4 {{ 
            margin-bottom: 15px; 
            color: #90cdf4;
        }}
        
        .sqlmap-container {{
            display: flex;
            align-items: center;
            gap: 15px;
            background: #2d3748;
            padding: 15px;
            border-radius: 8px;
        }}
        
        .sqlmap-command {{ 
            flex: 1;
            overflow-x: auto;
        }}
        
        .sqlmap-command code {{ 
            color: #68d391; 
            font-family: 'Monaco', 'Consolas', monospace; 
            font-size: 0.85em;
            line-height: 1.4;
        }}
        
        .copy-btn {{
            background: #4299e1;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.8em;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 5px;
            min-width: 70px;
            justify-content: center;
        }}
        
        .copy-btn:hover {{ 
            background: #3182ce; 
            transform: translateY(-1px);
        }}
        
        .copy-btn.copied {{ 
            background: #38a169; 
            transform: scale(1.05);
        }}
        
        .copy-btn:active {{
            transform: scale(0.95);
        }}
        
        .copy-icon {{
            font-size: 0.9em;
        }}
        
        .notification {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: #38a169;
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            font-weight: 600;
            z-index: 1000;
            transform: translateX(100%);
            transition: transform 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        
        .notification.show {{
            transform: translateX(0);
        }}
        
        .notification.error {{
            background: #e53e3e;
        }}
        
        .no-vulns {{ 
            text-align: center; 
            padding: 50px 30px;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }}
        
        .success-icon {{ 
            font-size: 3em; 
            margin-bottom: 15px;
            color: #38a169;
        }}
        
        .no-vulns h3 {{ 
            color: #38a169; 
            font-size: 1.5em; 
            margin-bottom: 10px;
        }}
        
        .no-vulns p {{ 
            color: #4a5568; 
            font-size: 1em; 
        }}
        
        .footer {{ 
            text-align: center; 
            margin-top: 40px; 
            padding: 25px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            color: white;
        }}
        
        .footer .brand {{
            font-weight: 700;
            font-size: 1.1em;
            margin-bottom: 5px;
        }}
        
        .footer .creator {{
            font-size: 0.9em;
            opacity: 0.8;
            margin-bottom: 10px;
        }}
        
        @media (max-width: 768px) {{
            .container {{ padding: 15px; }}
            .stats-grid {{ grid-template-columns: 1fr; }}
            .sqlmap-container {{ flex-direction: column; align-items: stretch; }}
            .vuln-header h3 {{ flex-direction: column; align-items: flex-start; }}
            .copy-btn {{ width: 100%; }}
            .notification {{ right: 10px; left: 10px; transform: translateY(-100%); }}
            .notification.show {{ transform: translateY(0); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SQLiPwn</h1>
            <div class="subtitle">SQL Injection Security Scanner</div>
            <p>Target: <strong>{self.target_url}</strong> | Generated on {current_time}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <span class="stat-number">{len(self.vulnerabilities)}</span>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number confidence-high">{len([v for v in self.vulnerabilities if v.confidence == 'HIGH'])}</span>
                    <div class="stat-label">High Risk</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number confidence-medium">{len([v for v in self.vulnerabilities if v.confidence == 'MEDIUM'])}</span>
                    <div class="stat-label">Medium Risk</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number confidence-low">{len([v for v in self.vulnerabilities if v.confidence == 'LOW'])}</span>
                    <div class="stat-label">Low Risk</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number">{duration_str}</span>
                    <div class="stat-label">Scan Duration</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number">{self.scan_stats.get('parameters_tested', 0)}</span>
                    <div class="stat-label">Parameters Tested</div>
                </div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>Vulnerability Details</h2>
            {vuln_html}
        </div>
        
        <div class="footer">
            <p class="brand">SQLiPwn - SQL Injection Security Scanner</p>
            <p class="creator">SQLiPwn by syfi</p>
            <p>Report generated for authorized security testing purposes</p>
        </div>
    </div>

    <div id="notification" class="notification">
        <span id="notification-text">Copied to clipboard!</span>
    </div>

    <script>
        // Enhanced clipboard functionality with better error handling and fallbacks
        async function copyToClipboard(text, button, elementId) {{
            const originalContent = button.innerHTML;
            const notification = document.getElementById('notification');
            const notificationText = document.getElementById('notification-text');
            
            try {{
                // Method 1: Modern Clipboard API (preferred)
                if (navigator.clipboard && window.isSecureContext) {{
                    await navigator.clipboard.writeText(text);
                    showSuccess();
                }} else {{
                    // Method 2: Fallback using document.execCommand (deprecated but widely supported)
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    textArea.style.position = 'fixed';
                    textArea.style.opacity = '0';
                    textArea.style.left = '-9999px';
                    document.body.appendChild(textArea);
                    textArea.select();
                    textArea.setSelectionRange(0, text.length);
                    
                    const successful = document.execCommand('copy');
                    document.body.removeChild(textArea);
                    
                    if (successful) {{
                        showSuccess();
                    }} else {{
                        throw new Error('execCommand failed');
                    }}
                }}
            }} catch (err) {{
                console.error('Copy failed:', err);
                
                // Method 3: Final fallback - show text in a modal/alert for manual copy
                try {{
                    // Try to select text in the element for manual copying
                    const element = document.getElementById(elementId);
                    if (element) {{
                        const range = document.createRange();
                        range.selectNode(element);
                        window.getSelection().removeAllRanges();
                        window.getSelection().addRange(range);
                        
                        notificationText.textContent = 'Text selected - press Ctrl+C to copy';
                        notification.className = 'notification show';
                        setTimeout(() => {{
                            notification.className = 'notification';
                        }}, 3000);
                    }} else {{
                        throw new Error('Element not found');
                    }}
                }} catch (selectErr) {{
                    // Ultimate fallback - prompt with text
                    const userAgent = navigator.userAgent.toLowerCase();
                    const isMobile = /android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini/.test(userAgent);
                    
                    if (isMobile) {{
                        // On mobile, create a temporary input for better UX
                        const input = document.createElement('input');
                        input.type = 'text';
                        input.value = text;
                        input.style.position = 'fixed';
                        input.style.top = '50%';
                        input.style.left = '50%';
                        input.style.transform = 'translate(-50%, -50%)';
                        input.style.zIndex = '10000';
                        input.style.padding = '10px';
                        input.style.border = '2px solid #4299e1';
                        input.style.borderRadius = '4px';
                        input.style.fontSize = '16px';
                        
                        document.body.appendChild(input);
                        input.select();
                        input.setSelectionRange(0, text.length);
                        
                        setTimeout(() => {{
                            if (document.body.contains(input)) {{
                                document.body.removeChild(input);
                            }}
                        }}, 5000);
                        
                        notificationText.textContent = 'Text selected - tap and hold to copy';
                        notification.className = 'notification show';
                        setTimeout(() => {{
                            notification.className = 'notification';
                        }}, 5000);
                    }} else {{
                        // Desktop fallback - use prompt
                        prompt('Copy the SQLMap command below:', text);
                    }}
                }}
                
                button.innerHTML = '<span class="copy-icon">⚠️</span> Retry';
                button.className = 'copy-btn error';
                setTimeout(() => {{
                    button.innerHTML = originalContent;
                    button.className = 'copy-btn';
                }}, 2000);
                return;
            }}
            
            function showSuccess() {{
                button.innerHTML = '<span class="copy-icon">✓</span> Copied!';
                button.classList.add('copied');
                
                notificationText.textContent = 'SQLMap command copied to clipboard!';
                notification.className = 'notification show';
                
                setTimeout(() => {{
                    button.innerHTML = originalContent;
                    button.classList.remove('copied');
                    notification.className = 'notification';
                }}, 2000);
            }}
        }}
        
        // Add keyboard shortcuts
        document.addEventListener('keydown', function(e) {{
            if (e.ctrlKey || e.metaKey) {{
                if (e.key === 'a' && e.target.closest('.sqlmap-command')) {{
                    e.preventDefault();
                    const range = document.createRange();
                    range.selectNodeContents(e.target.closest('.sqlmap-command'));
                    const selection = window.getSelection();
                    selection.removeAllRanges();
                    selection.addRange(range);
                }}
            }}
        }});
        
        // Enhance mobile experience
        if ('ontouchstart' in window) {{
            document.addEventListener('DOMContentLoaded', function() {{
                const sqlmapCommands = document.querySelectorAll('.sqlmap-command');
                sqlmapCommands.forEach(function(cmd) {{
                    cmd.style.userSelect = 'text';
                    cmd.style.webkitUserSelect = 'text';
                    cmd.addEventListener('touchstart', function() {{
                        this.style.backgroundColor = '#4a5568';
                    }});
                    cmd.addEventListener('touchend', function() {{
                        this.style.backgroundColor = 'transparent';
                    }});
                }});
            }});
        }}
    </script>
</body>
</html>"""
    
    def generate_json_report(self, filename: str = None) -> str:
        """Generate JSON report for machine processing"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"sqlipwn_report_{self.target_domain}_{timestamp}.json"
        
        duration = datetime.now() - self.start_time
        
        report_data = {
            'scan_metadata': {
                'tool_name': 'SQLiPwn',
                'version': '2.1',
                'target_url': self.target_url,
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': duration.total_seconds()
            },
            'scan_summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'high_confidence': len([v for v in self.vulnerabilities if v.confidence == 'HIGH']),
                'medium_confidence': len([v for v in self.vulnerabilities if v.confidence == 'MEDIUM']),
                'low_confidence': len([v for v in self.vulnerabilities if v.confidence == 'LOW'])
            },
            'scan_statistics': self.scan_stats,
            'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities]
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            print(f"{Fore.GREEN}[+] JSON report saved: {filename}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving JSON report: {e}")
        
        return filename
    
    def display_summary(self):
        """Display final scan summary"""
        duration = datetime.now() - self.start_time
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}SCAN COMPLETED - SUMMARY")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.WHITE}Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"{Fore.RED}High Confidence: {len([v for v in self.vulnerabilities if v.confidence == 'HIGH'])}")
        print(f"{Fore.YELLOW}Medium Confidence: {len([v for v in self.vulnerabilities if v.confidence == 'MEDIUM'])}")
        print(f"{Fore.CYAN}Low Confidence: {len([v for v in self.vulnerabilities if v.confidence == 'LOW'])}")
        print(f"{Fore.WHITE}Scan Duration: {str(duration).split('.')[0]}")
        print(f"{Fore.WHITE}URLs Crawled: {self.scan_stats.get('urls_crawled', 0)}")
        print(f"{Fore.WHITE}Parameters Tested: {self.scan_stats.get('parameters_tested', 0)}")
        print(f"{Fore.CYAN}{'='*70}\n")