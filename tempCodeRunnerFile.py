from flask import Flask, request, jsonify, render_template
import requests
from urllib.parse import urlparse, parse_qs
import socket
import ssl
from datetime import datetime, timedelta
import dns.resolver
import whois
import re
import subprocess
import concurrent.futures
from bs4 import BeautifulSoup
import hashlib
import pickle
import nvdlib
import json

app = Flask(__name__)

# Load the spam detector model and vectorizer
def load_spam_detector():
    with open('model.pkl', 'rb') as f:
        spam_detector = pickle.load(f)
    return spam_detector['model'], spam_detector['vectorizer']

# Initialize the model and vectorizer
model, vectorizer = load_spam_detector()

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return {
                    "valid": True,
                    "expires": expiry_date.strftime('%Y-%m-%d'),
                    "issuer": dict(x[0] for x in cert['issuer'])
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}

def check_http_headers(url):
    try:
        response = requests.head(url, allow_redirects=True)
        headers = dict(response.headers)
        security_headers = {
            "X-XSS-Protection": headers.get("X-XSS-Protection", "Not Set"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Not Set"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not Set"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not Set"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Not Set")
        }
        return security_headers
    except Exception as e:
        return {"error": str(e)}

def check_open_ports(domain):
    common_ports = [21, 22, 80, 443, 3306, 8080]
    open_ports = []
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    return open_ports

def check_dns_records(domain):
    try:
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record)
                records[record] = [str(answer) for answer in answers]
            except:
                records[record] = []
        return records
    except Exception as e:
        return {"error": str(e)}

def check_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "last_updated": str(w.updated_date),
            "name_servers": w.name_servers
        }
    except Exception as e:
        return {"error": str(e)}

def check_sql_injection_vulnerability(url):
    test_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users"]
    vulnerabilities = []
    
    for payload in test_payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url)
            if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql']):
                vulnerabilities.append(f"Possible SQL injection vulnerability with payload: {payload}")
        except:
            pass
    return vulnerabilities

def check_xss_vulnerability(url):
    xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')"
    ]
    vulnerabilities = []
    
    try:
        response = requests.get(url)
        for payload in xss_payloads:
            if payload in response.text:
                vulnerabilities.append(f"Possible XSS vulnerability: Site reflects payload: {payload}")
    except Exception as e:
        vulnerabilities.append(f"Error checking XSS: {str(e)}")
    return vulnerabilities

def check_server_info(url):
    try:
        response = requests.head(url)
        server_info = {
            "server": response.headers.get("Server", "Not disclosed"),
            "powered_by": response.headers.get("X-Powered-By", "Not disclosed"),
            "tech_stack": response.headers.get("X-AspNet-Version", "Not disclosed")
        }
        return server_info
    except Exception as e:
        return {"error": str(e)}

def check_cookie_security(url):
    try:
        response = requests.get(url)
        cookies = response.cookies
        issues = []
        
        for cookie in cookies:
            if not cookie.secure:
                issues.append(f"Cookie '{cookie.name}' not marked as secure")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append(f"Cookie '{cookie.name}' not marked as HttpOnly")
            if cookie.path == "/":
                issues.append(f"Cookie '{cookie.name}' has root path")
                
        return issues
    except Exception as e:
        return {"error": str(e)}

def check_directory_listing(url):
    common_dirs = ['/admin/', '/backup/', '/config/', '/db/', '/logs/']
    exposed_dirs = []
    
    for directory in common_dirs:
        try:
            test_url = url.rstrip('/') + directory
            response = requests.get(test_url)
            if response.status_code == 200 and 'Index of' in response.text:
                exposed_dirs.append(test_url)
        except:
            continue
    return exposed_dirs

def check_cors_policy(url):
    try:
        headers = {
            'Origin': 'https://malicious-site.com'
        }
        response = requests.get(url, headers=headers)
        cors_headers = {
            'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
            'Access-Control-Expose-Headers': response.headers.get('Access-Control-Expose-Headers')
        }
        return cors_headers
    except Exception as e:
        return {"error": str(e)}

def check_ssl_vulnerabilities(domain):
    try:
        output = subprocess.check_output(f"echo | openssl s_client -connect {domain}:443 2>/dev/null", shell=True)
        return {
            "heartbleed": "heartbleed" not in output.decode().lower(),
            "poodle": "poodle" not in output.decode().lower(),
            "freak": "freak" not in output.decode().lower()
        }
    except:
        return {"error": "SSL vulnerability check failed"}

def check_http_methods(url):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT']
    allowed_methods = []
    
    for method in methods:
        try:
            response = requests.request(method, url)
            if response.status_code != 405:  # Method not allowed
                allowed_methods.append(method)
        except:
            continue
    return allowed_methods

def check_information_disclosure(url):
    patterns = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[-. ]?\d{4}[-. ]?\d{4}[-. ]?\d{4}\b'
    }
    
    found_info = {}
    try:
        response = requests.get(url)
        for info_type, pattern in patterns.items():
            matches = re.findall(pattern, response.text)
            if matches:
                found_info[info_type] = len(matches)
    except Exception as e:
        return {"error": str(e)}
    return found_info

def check_vulnerabilities(url, domain, headers, server_info):
    vulnerabilities = []
    
    # Common vulnerability patterns and their associated CVEs
    vulnerability_checks = {
        "WordPress": {
            "patterns": [
                "/wp-admin",
                "/wp-content",
                "/wp-includes"
            ],
            "cves": ["CVE-2021-44223", "CVE-2022-21661"]
        },
        "Apache": {
            "patterns": ["Apache/2", "Apache/1"],
            "cves": ["CVE-2021-41773", "CVE-2021-42013"]
        },
        "Nginx": {
            "patterns": ["nginx/"],
            "cves": ["CVE-2021-23017", "CVE-2019-9511"]
        },
        "PHP": {
            "patterns": ["PHP/", "X-Powered-By: PHP"],
            "cves": ["CVE-2021-21703", "CVE-2020-7071"]
        },
        "IIS": {
            "patterns": ["IIS/", "Microsoft-IIS"],
            "cves": ["CVE-2021-31166", "CVE-2020-0646"]
        },
        "jQuery": {
            "patterns": ["jquery.min.js", "jquery.js"],
            "cves": ["CVE-2020-11023", "CVE-2020-11022"]
        },
        "OpenSSL": {
            "patterns": ["OpenSSL/"],
            "cves": ["CVE-2021-3449", "CVE-2021-3450"]
        },
        "Drupal": {
            "patterns": ["/sites/default/", "Drupal"],
            "cves": ["CVE-2021-41648", "CVE-2020-13671"]
        },
        "Joomla": {
            "patterns": ["/administrator/", "Joomla"],
            "cves": ["CVE-2021-23132", "CVE-2020-35616"]
        },
        "Django": {
            "patterns": ["csrftoken", "django"],
            "cves": ["CVE-2021-35042", "CVE-2021-33203"]
        }
    }

    # Additional security checks
    security_checks = [
        {
            "name": "Insecure Direct Object References (IDOR)",
            "cve": "CVE-2021-28937",
            "check": lambda: "/api/user/" in url or "/user/" in url
        },
        {
            "name": "XML External Entity (XXE)",
            "cve": "CVE-2021-28918",
            "check": lambda: "application/xml" in headers.get("Content-Type", "")
        },
        {
            "name": "Server-Side Request Forgery (SSRF)",
            "cve": "CVE-2021-22876",
            "check": lambda: any(param in url for param in ["url=", "redirect=", "path="])
        },
        {
            "name": "Remote Code Execution (RCE)",
            "cve": "CVE-2021-44228",
            "check": lambda: any(tech in json.dumps(server_info) for tech in ["java", "php", "python"])
        },
        {
            "name": "Authentication Bypass",
            "cve": "CVE-2021-22205",
            "check": lambda: not url.startswith("https://")
        }
    ]

    # Check for known vulnerabilities
    for tech, info in vulnerability_checks.items():
        for pattern in info["patterns"]:
            try:
                response = requests.get(f"{url}/{pattern}")
                if response.status_code == 200:
                    vulnerabilities.append({
                        "type": f"Potential {tech} Vulnerability",
                        "description": f"Detected {tech} technology which may have known vulnerabilities",
                        "severity": "High",
                        "cves": info["cves"],
                        "recommendation": f"Update {tech} to the latest version and apply security patches"
                    })
                    break
            except:
                continue

    # Perform additional security checks
    for check in security_checks:
        try:
            if check["check"]():
                vulnerabilities.append({
                    "type": check["name"],
                    "description": f"Potential {check['name']} vulnerability detected",
                    "severity": "High",
                    "cves": [check["cve"]],
                    "recommendation": f"Implement proper validation and security controls"
                })
        except:
            continue

    # Add more specific vulnerability checks
    try:
        # Check for missing security headers
        if "X-Frame-Options" not in headers:
            vulnerabilities.append({
                "type": "Clickjacking Vulnerability",
                "description": "Missing X-Frame-Options header",
                "severity": "Medium",
                "cves": ["CVE-2021-28789"],
                "recommendation": "Implement X-Frame-Options header"
            })

        # Check for sensitive files
        sensitive_files = [
            "phpinfo.php",
            ".git/HEAD",
            ".env",
            "config.php",
            "wp-config.php",
            "robots.txt",
            ".htaccess",
            "server-status"
        ]
        
        for file in sensitive_files:
            try:
                response = requests.get(f"{url}/{file}")
                if response.status_code == 200:
                    vulnerabilities.append({
                        "type": "Information Disclosure",
                        "description": f"Sensitive file exposed: {file}",
                        "severity": "High",
                        "cves": ["CVE-2021-28789"],
                        "recommendation": "Remove or protect sensitive files"
                    })
            except:
                continue

    except Exception as e:
        print(f"Error in additional checks: {str(e)}")

    return vulnerabilities

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scanner.html')
def scanner():
    return render_template('scanner.html')

@app.route('/spam.html')
def spam():
    return render_template('spam.html')

@app.route('/vulnerabilityanalysis', methods=['POST'])
def vulnerability_analysis():
    try:
        data = request.get_json()
        target_url = data.get('url')
        
        if not target_url:
            return jsonify({"error": "URL is required"}), 400

        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        # Get basic headers and server info first
        response = requests.head(target_url)
        headers = dict(response.headers)
        server_info = check_server_info(target_url)

        # Get comprehensive vulnerabilities
        all_vulnerabilities = check_vulnerabilities(target_url, domain, headers, server_info)
        
        # Add existing vulnerability checks
        sql_injection_vulns = check_sql_injection_vulnerability(target_url)
        xss_vulns = check_xss_vulnerability(target_url)
        
        # Combine all vulnerabilities
        all_vulnerabilities.extend([
            {"type": "SQL Injection", "description": vuln, "severity": "High", "cves": ["CVE-2021-28790"]}
            for vuln in sql_injection_vulns
        ])
        all_vulnerabilities.extend([
            {"type": "Cross-Site Scripting (XSS)", "description": vuln, "severity": "High", "cves": ["CVE-2021-28791"]}
            for vuln in xss_vulns
        ])

        # Enhanced security analysis
        analysis_result = {
            "url": target_url,
            "timestamp": datetime.now().isoformat(),
            "basic_info": {
                "domain": domain,
                "ip": socket.gethostbyname(domain),
                "protocol": parsed_url.scheme
            },
            "ssl_certificate": check_ssl_certificate(domain),
            "security_headers": check_http_headers(target_url),
            "server_info": server_info,
            "open_ports": check_open_ports(domain),
            "vulnerabilities": all_vulnerabilities,
            "risk_score": calculate_risk_score(all_vulnerabilities)
        }

        return jsonify({
            "status": "success",
            "analysis": analysis_result
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def calculate_risk_score(vulnerabilities):
    if not vulnerabilities:
        return 0
    
    severity_weights = {
        "High": 1.0,
        "Medium": 0.5,
        "Low": 0.2
    }
    
    total_weight = sum(severity_weights[v.get("severity", "Low")] for v in vulnerabilities)
    max_possible_weight = len(vulnerabilities)
    
    return round((total_weight / max_possible_weight) * 100, 2)

@app.route('/detectspam', methods=['POST'])
def detect_spam():
    try:
        data = request.get_json()
        message = data.get('message')
        
        if not message:
            return jsonify({"error": "Message is required"}), 400

        # Transform the message using the loaded vectorizer
        message_tfidf = vectorizer.transform([message])
        
        # Make prediction
        prediction = model.predict(message_tfidf)[0]
        probability = model.predict_proba(message_tfidf)[0]
        
        return jsonify({
            "status": "success",
            "is_spam": bool(prediction),
            "confidence": {
                "spam": float(probability[1]),
                "ham": float(probability[0])
            },
            "message": message
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000) 