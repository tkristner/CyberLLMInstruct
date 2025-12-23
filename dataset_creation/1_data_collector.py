#!/usr/bin/env python3

import os
import json
import logging
import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from typing import Dict, List, Union, Optional
from pathlib import Path
import feedparser
import pandas as pd
import yaml
import time
import shutil
import argparse
from github import Github

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberDataCollector:
    def __init__(self, output_dir: str = "raw_data"):
        """Initialize the data collector with output directory configuration.
        
        Required API Keys (set as environment variables):
        - VIRUSTOTAL_API_KEY: Required for VirusTotal API access
        - ALIENVAULT_API_KEY: Required for AlienVault OTX API
        - HTB_API_KEY: Required for HackTheBox API
        
        Rate Limits:
        - CTFtime API: 30 requests per minute
        - NVD API: 5 requests per 30 seconds
        - VirusTotal API: Depends on subscription tier
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize API clients
        from github import Auth
        github_token = os.getenv('GITHUB_TOKEN')
        self.github_client = Github(auth=Auth.Token(github_token)) if github_token else None
        # OpenCVE uses username (not email) for basic auth
        opencve_user = os.getenv('OPENCVE_USERNAME') or os.getenv('OPENCVE_EMAIL')
        opencve_pass = os.getenv('OPENCVE_PASSWORD')
        self.opencve_auth = (opencve_user, opencve_pass) if opencve_user and opencve_pass else None
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        
        # Load API keys from environment variables
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'alienvault': os.getenv('ALIENVAULT_API_KEY'),
            'hackthebox': os.getenv('HTB_API_KEY'),
            'malpedia': os.getenv('MALPEDIA_API_KEY'),
            'malshare': os.getenv('MALSHARE_API_KEY'),
            'shodan': os.getenv('SHODAN_API_KEY'),
            'phishtank': os.getenv('PHISHTANK_API_KEY'),
        }
        
        # Initialize rate limiting
        self.rate_limits = {
            'nvd_cve': {'requests': 5, 'period': 30},
            'ctftime': {'requests': 30, 'period': 60},
            'github': {'requests': 60, 'period': 3600},  # GitHub API limit
            'virustotal': {'requests': 4, 'period': 60},
            'shodan': {'requests': 1, 'period': 1},
            'malshare': {'requests': 25, 'period': 60},
        }
        self.last_request_time = {}
        
        # Add request timeout settings
        self.timeouts = {
            'default': 30,
            'download': 180,  # Longer timeout for downloading larger files
            'scraping': 60,   # Longer timeout for web scraping
        }
        
        # Add retry configurations
        self.retry_config = {
            'max_retries': 3,
            'base_delay': 5,
            'max_delay': 60,
            'exponential_backoff': True,
        }
        
        # API endpoints and configurations
        self.endpoints = {
            # NIST and CVE Sources
            'nvd_cve': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'opencve': 'https://app.opencve.io/api/cve',
            'nist_standards': 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.json',
            'mitre_attack': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
            'mitre_capec': 'https://capec.mitre.org/data/xml/views/3000.xml',
            
            # Threat Intelligence Feeds
            'alienvault_otx': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
            'threatfox_api': 'https://threatfox-api.abuse.ch/api/v1/',
            
            # Security Advisories
            'microsoft_security': 'https://api.msrc.microsoft.com/cvrf/v2.0/updates',
            'ubuntu_usn': 'https://ubuntu.com/security/notices/rss.xml',
            'redhat_security': 'https://access.redhat.com/hydra/rest/securitydata/cve.json',
            
            # Research and Reports
            'arxiv_cs_crypto': 'http://export.arxiv.org/api/query?search_query=cat:cs.CR&max_results=100',
            'exploit_db': 'https://www.exploit-db.com/download/',
            
            # Malware Information
            'malware_bazaar': 'https://mb-api.abuse.ch/api/v1/',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/',
            'malpedia': 'https://malpedia.caad.fkie.fraunhofer.de/api/v1/',
            'malshare': 'https://malshare.com/api.php',
            'thezoo': 'https://github.com/ytisf/theZoo/raw/master/malware.yml',
            'vxug': 'https://vx-underground.org/samples.html',
            
            # CTF Resources
            'ctftime': 'https://ctftime.org/api/v1/events/',
            'root_me': 'https://api.www.root-me.org/challenges',
            'hackthebox': 'https://www.hackthebox.com/api/v4/challenge/list',
            
            # Security Testing Resources
            'metasploit_modules': 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/',
            'pentesterlab': 'https://pentesterlab.com/exercises/api/v1/',
            'vulnhub': 'https://www.vulnhub.com/api/v1/entries/',
            'offensive_security': 'https://offsec.tools/api/tools',
            'securitytube': 'https://www.securitytube.net/api/v1/videos',
            'pentestmonkey': 'https://github.com/pentestmonkey/php-reverse-shell/raw/master/php-reverse-shell.php',
            'payloadsallthethings': 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/',
            
            # Social Engineering Resources
            'phishtank': 'https://phishtank.org/phish_search.php?valid=y&active=all&Search=Search',
            'openphish': 'https://openphish.com/feed.txt',
            'social_engineer_toolkit': 'https://github.com/trustedsec/social-engineer-toolkit/raw/master/src/templates/',
            'gophish': 'https://github.com/gophish/gophish/raw/master/templates/',
            
            # DoS/DDoS Resources
            'ddosdb': 'https://ddosdb.org/api/v1/',
            'netscout_atlas': 'https://atlas.netscout.com/api/v2/',
            
            # MITM & Injection Resources
            'bettercap': 'https://raw.githubusercontent.com/bettercap/bettercap/master/modules/',
            'sqlmap': 'https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/',
            'nosqlmap': 'https://raw.githubusercontent.com/codingo/NoSQLMap/master/attacks/',
            
            # Zero-Day & Password Resources
            'zerodayinitiative': 'https://www.zerodayinitiative.com/rss/published/',
            'project_zero': 'https://bugs.chromium.org/p/project-zero/issues/list?rss=true',
            'rockyou': 'https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/',
            'hashcat': 'https://hashcat.net/hashcat/',
            
            # IoT Security Resources
            'iot_vulndb': 'https://www.exploit-db.com/download/iot/',
            'iot_sentinel': 'https://iotsentinel.csec.ch/api/v1/',
            'shodan_iot': 'https://api.shodan.io/shodan/host/search?key={}&query=iot',
        }
        
        # Initialize session for better performance
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberLLMInstruct-DataCollector/1.0'
        })

    def _check_rate_limit(self, endpoint: str) -> None:
        """
        Implement rate limiting for APIs.
        Sleeps if necessary to respect rate limits.
        """
        if endpoint not in self.rate_limits:
            return
            
        current_time = time.time()
        if endpoint in self.last_request_time:
            elapsed = current_time - self.last_request_time[endpoint]
            limit = self.rate_limits[endpoint]
            if elapsed < (limit['period'] / limit['requests']):
                sleep_time = (limit['period'] / limit['requests']) - elapsed
                logger.debug(f"Rate limiting {endpoint}, sleeping for {sleep_time:.2f}s")
                time.sleep(sleep_time)
                
        self.last_request_time[endpoint] = current_time

    def _make_request(self, endpoint: str, url: str, params: Dict = None, headers: Dict = None, 
                     timeout: int = None, method: str = 'get', data: Dict = None, auth = None) -> Optional[requests.Response]:
        """
        Enhanced request method with better error handling and retries.
        """
        self._check_rate_limit(endpoint)
        
        if headers is None:
            headers = {}
        
        # Set auth for OpenCVE
        if endpoint == 'opencve' and not auth:
            auth = self.opencve_auth
            
        # Add API keys to headers based on endpoint
        for key, value in self.api_keys.items():
            if endpoint.startswith(key) and value:
                if key == 'virustotal':
                    headers['x-apikey'] = value
                elif key == 'alienvault':
                    headers['X-OTX-API-KEY'] = value
                # ... add other API key headers as needed
        
        timeout = timeout or self.timeouts['default']
        retry_count = 0
        last_error = None
        
        while retry_count < self.retry_config['max_retries']:
            try:
                if method.lower() == 'get':
                    response = self.session.get(url, params=params, headers=headers, timeout=timeout, auth=auth)
                elif method.lower() == 'post':
                    # Check if we need to send form data or JSON data
                    content_type = headers.get('Content-Type', '')
                    if 'application/x-www-form-urlencoded' in content_type:
                        response = self.session.post(url, params=params, headers=headers, data=data, timeout=timeout, auth=auth)
                    else:
                        response = self.session.post(url, params=params, headers=headers, json=data, timeout=timeout, auth=auth)
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                last_error = e
                retry_count += 1
                
                if retry_count == self.retry_config['max_retries']:
                    break
                    
                # Calculate delay with exponential backoff
                if self.retry_config['exponential_backoff']:
                    delay = min(
                        self.retry_config['base_delay'] * (2 ** (retry_count - 1)),
                        self.retry_config['max_delay']
                    )
                else:
                    delay = self.retry_config['base_delay']
                    
                logger.warning(f"Request failed (attempt {retry_count}/{self.retry_config['max_retries']}): {str(e)}")
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
        
        logger.error(f"All retry attempts failed for {url}: {str(last_error)}")
        return None

    def fetch_cve_data(
        self,
        start_index: int = 0,
        results_per_page: int = 2000,
        start_year: int = None,
        end_year: int = None,
    ) -> Optional[Dict]:
        """
        Fetch CVE data from NVD database.

        Args:
            start_index: Starting index for pagination
            results_per_page: Number of results per page (max 2000)
            start_year: Start year for CVE filter (e.g., 2021)
            end_year: End year for CVE filter (e.g., 2025)

        Note: Implements rate limiting of 5 requests per 30 seconds
        """
        try:
            params = {
                'startIndex': start_index,
                'resultsPerPage': results_per_page,
            }

            # Add date range filter if specified
            if start_year and end_year:
                params['pubStartDate'] = f'{start_year}-01-01T00:00:00.000'
                params['pubEndDate'] = f'{end_year}-12-31T23:59:59.999'

            response = self._make_request('nvd_cve', self.endpoints['nvd_cve'], params=params)
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE data: {str(e)}")
            return None

    def fetch_cve_data_stratified(
        self,
        min_per_period: int = 5000,
        period_ratio: Dict[str, float] = None,
        severity_ratio: Dict[str, float] = None,
        only_period: str = None,
    ) -> Dict[str, List]:
        """
        Fetch CVE data with stratified sampling across years and severity.

        Periods with ratios (default):
        - old: 1999-2010 (20%)
        - mid: 2011-2020 (30%)
        - recent: 2021-2025 (50%)

        Severity distribution (default):
        - CRITICAL: 40%
        - HIGH: 35%
        - MEDIUM: 20%
        - LOW: 5%

        Args:
            min_per_period: Minimum CVEs per period (smallest period gets this)
            period_ratio: Dict with period weights (default: old=0.2, mid=0.3, recent=0.5)
            severity_ratio: Dict with severity weights (default favors critical/high)

        Returns:
            Dict with 'old', 'mid', 'recent' keys containing CVE lists
        """
        if period_ratio is None:
            period_ratio = {
                'old': 0.20,      # 20%
                'mid': 0.30,      # 30%
                'recent': 0.50,   # 50%
            }

        if severity_ratio is None:
            # Prioritize high severity but keep realistic ratios
            # CRITICAL + HIGH = 60%, allows flexibility if not enough critical
            severity_ratio = {
                'CRITICAL': 0.30,
                'HIGH': 0.40,
                'MEDIUM': 0.25,
                'LOW': 0.05,
            }

        periods = {
            'old': list(range(1999, 2011)),      # 12 years
            'mid': list(range(2011, 2021)),      # 10 years
            'recent': list(range(2021, 2026)),   # 5 years
        }

        # Calculate target per period based on ratios
        # min_per_period applies to the smallest ratio, others scale up
        min_ratio = min(period_ratio.values())
        period_targets = {
            name: max(min_per_period, int(min_per_period * (ratio / min_ratio)))
            for name, ratio in period_ratio.items()
        }

        logger.info("=== CVE Stratified Collection ===")
        logger.info(f"Period targets: old={period_targets['old']}, mid={period_targets['mid']}, recent={period_targets['recent']}")
        logger.info(f"Severity distribution: CRITICAL={severity_ratio['CRITICAL']:.0%}, HIGH={severity_ratio['HIGH']:.0%}, MEDIUM={severity_ratio['MEDIUM']:.0%}, LOW={severity_ratio['LOW']:.0%}")

        results = {'old': [], 'mid': [], 'recent': []}

        # Filter periods if only_period specified
        periods_to_process = {only_period: periods[only_period]} if only_period else periods

        for period_name, years in periods_to_process.items():
            target_for_period = period_targets[period_name]
            logger.info(f"\n=== Period '{period_name}': {years[0]}-{years[-1]} (target: {target_for_period}) ===")

            period_cves = []

            # Fetch by severity level
            for severity, ratio in severity_ratio.items():
                target_count = int(target_for_period * ratio)
                per_year = max(1, target_count // len(years))

                logger.info(f"\nSeverity {severity}: target {target_count} CVEs (~{per_year}/year)")

                severity_cves = []

                for year in years:
                    data = self._fetch_cve_by_severity(
                        year=year,
                        severity=severity,
                        max_results=per_year,
                    )

                    if data:
                        severity_cves.extend(data)
                        logger.info(f"  {year} [{severity}]: {len(data)} CVEs")

                    if len(severity_cves) >= target_count:
                        break

                period_cves.extend(severity_cves[:target_count])
                logger.info(f"  {severity} total: {len(severity_cves[:target_count])} CVEs")

            results[period_name] = period_cves
            logger.info(f"\nPeriod '{period_name}' total: {len(period_cves)} CVEs")

        total = sum(len(v) for v in results.values())
        logger.info(f"\n=== TOTAL: {total} CVEs ===")
        for name, cves in results.items():
            pct = len(cves) / total * 100 if total > 0 else 0
            logger.info(f"  {name}: {len(cves)} ({pct:.1f}%)")

        return results

    def _fetch_cve_by_severity(
        self,
        year: int,
        severity: str,
        max_results: int = 500,
    ) -> List[Dict]:
        """
        Fetch CVEs for a specific year and severity level.

        Uses CVSSv3 for 2015+ and CVSSv2 for older years.
        CVSSv2 mapping: CRITICAL->HIGH (no critical in v2), HIGH->HIGH, MEDIUM->MEDIUM, LOW->LOW

        NVD API limits date range to 120 days, so we query by quarter.
        For recent years (2021+), queries all 4 quarters to get more variety.

        Args:
            year: Year to fetch
            severity: CRITICAL, HIGH, MEDIUM, or LOW
            max_results: Max CVEs to fetch

        Returns:
            List of CVE entries
        """
        import random
        import time

        quarter_dates = {
            1: (f'{year}-01-01T00:00:00.000', f'{year}-03-31T23:59:59.999'),
            2: (f'{year}-04-01T00:00:00.000', f'{year}-06-30T23:59:59.999'),
            3: (f'{year}-07-01T00:00:00.000', f'{year}-09-30T23:59:59.999'),
            4: (f'{year}-10-01T00:00:00.000', f'{year}-12-31T23:59:59.999'),
        }

        # For recent years, query all quarters; for older years, pick one random
        if year >= 2021:
            quarters_to_fetch = [1, 2, 3, 4]
            per_quarter = max(1, max_results // 4)
        else:
            quarters_to_fetch = [random.randint(1, 4)]
            per_quarter = max_results

        all_cves = []

        for quarter in quarters_to_fetch:
            if len(all_cves) >= max_results:
                break

            start_date, end_date = quarter_dates[quarter]

            try:
                # Build params
                params = {
                    'startIndex': 0,
                    'resultsPerPage': min(500, per_quarter),
                    'pubStartDate': start_date,
                    'pubEndDate': end_date,
                }

                if year >= 2015:
                    params['cvssV3Severity'] = severity
                else:
                    v2_severity = 'HIGH' if severity == 'CRITICAL' else severity
                    params['cvssV2Severity'] = v2_severity

                # Rate limit: wait 6 seconds between requests
                time.sleep(6)

                response = self._make_request('nvd_cve', self.endpoints['nvd_cve'], params=params)
                if not response:
                    continue

                data = response.json()
                cves = data.get('vulnerabilities', [])
                all_cves.extend(cves)

            except Exception as e:
                logger.error(f"Error fetching CVEs for {year} Q{quarter} {severity}: {e}")
                continue

        return all_cves[:max_results]

    def fetch_opencve_data(self, limit: int = 100) -> Optional[Dict]:
        """
        Fetch CVE data from the OpenCVE API.
        
        Args:
            limit: Maximum number of CVEs to fetch
            
        Returns:
            Dictionary containing CVE data or None if failed
        
        Note: Uses basic authentication with the provided OpenCVE credentials.
        """
        try:
            all_cves = []
            page = 1
            
            # Fetch pages until we reach the limit or there are no more pages
            while len(all_cves) < limit:
                params = {
                    'page': page
                }
                response = self._make_request('opencve', self.endpoints['opencve'], params=params)
                
                if not response:
                    break
                    
                data = response.json()
                results = data.get('results', [])
                
                if not results:
                    break
                    
                all_cves.extend(results)
                
                # Check if there's a next page
                if not data.get('next'):
                    break
                    
                page += 1
                
                # Limit the number of CVEs
                if len(all_cves) >= limit:
                    all_cves = all_cves[:limit]
                    break
            
            # Get detailed information for each CVE
            detailed_cves = []
            for cve in all_cves[:10]:  # Limit detailed lookups to avoid rate limiting
                cve_id = cve.get('cve_id')
                if cve_id:
                    detailed_url = f"{self.endpoints['opencve']}/{cve_id}"
                    detailed_response = self._make_request('opencve', detailed_url)
                    
                    if detailed_response:
                        detailed_cves.append(detailed_response.json())
            
            return {
                'summary': all_cves,
                'detailed': detailed_cves,
                'count': len(all_cves),
                'timestamp': datetime.now().isoformat()
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching OpenCVE data: {str(e)}")
            return None

    def fetch_nist_standards(self) -> Optional[Dict]:
        """
        Fetch NIST SP 800-53 Rev 5 security controls from OSCAL GitHub repository.

        Returns:
            Dictionary containing NIST security controls or None if failed
        """
        try:
            url = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
            logger.info("Fetching NIST SP 800-53 Rev 5 controls...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            catalog = data.get('catalog', {})
            groups = catalog.get('groups', [])

            # Extract controls into flat list
            controls = []
            for group in groups:
                family_id = group.get('id', '')
                family_title = group.get('title', '')

                for control in group.get('controls', []):
                    control_data = {
                        'id': control.get('id', ''),
                        'title': control.get('title', ''),
                        'family_id': family_id,
                        'family_title': family_title,
                        'class': control.get('class', ''),
                    }

                    # Extract guidance and statement from parts
                    for part in control.get('parts', []):
                        part_name = part.get('name', '')
                        if part_name == 'statement':
                            control_data['statement'] = part.get('prose', '')
                        elif part_name == 'guidance':
                            control_data['guidance'] = part.get('prose', '')

                    # Extract properties
                    for prop in control.get('props', []):
                        if prop.get('name') == 'label':
                            control_data['label'] = prop.get('value', '')

                    controls.append(control_data)

            logger.info(f"Fetched {len(controls)} NIST SP 800-53 controls from {len(groups)} families")

            return {
                'source': 'NIST SP 800-53 Rev 5',
                'version': catalog.get('metadata', {}).get('version', 'unknown'),
                'controls': controls
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching NIST standards: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing NIST standards: {str(e)}")
            return None

    def fetch_nist_csf(self) -> Optional[Dict]:
        """
        Fetch NIST Cybersecurity Framework 2.0 from OSCAL GitHub repository.

        Returns:
            Dictionary containing CSF 2.0 functions, categories, and subcategories
        """
        try:
            url = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json"
            logger.info("Fetching NIST CSF 2.0...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            catalog = data.get('catalog', {})
            groups = catalog.get('groups', [])

            # Extract functions, categories, and subcategories
            functions = []
            for group in groups:
                function_data = {
                    'id': group.get('id', ''),
                    'title': group.get('title', ''),
                    'categories': []
                }

                for control in group.get('controls', []):
                    category_data = {
                        'id': control.get('id', ''),
                        'title': control.get('title', ''),
                        'subcategories': []
                    }

                    # Extract subcategories from nested controls
                    for subcontrol in control.get('controls', []):
                        subcategory = {
                            'id': subcontrol.get('id', ''),
                            'title': subcontrol.get('title', ''),
                        }
                        # Get implementation examples from parts
                        for part in subcontrol.get('parts', []):
                            if part.get('name') == 'implementation-examples':
                                subcategory['examples'] = part.get('prose', '')
                        category_data['subcategories'].append(subcategory)

                    function_data['categories'].append(category_data)
                functions.append(function_data)

            total_subcategories = sum(
                len(cat['subcategories'])
                for func in functions
                for cat in func['categories']
            )
            logger.info(f"Fetched NIST CSF 2.0: {len(functions)} functions, {total_subcategories} subcategories")

            return {
                'source': 'NIST Cybersecurity Framework 2.0',
                'version': catalog.get('metadata', {}).get('version', 'unknown'),
                'functions': functions
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching NIST CSF: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing NIST CSF: {str(e)}")
            return None

    def fetch_nist_sp800_171(self) -> Optional[Dict]:
        """
        Fetch NIST SP 800-171 Rev 3 - Protecting Controlled Unclassified Information.

        Returns:
            Dictionary containing SP 800-171 security requirements
        """
        try:
            url = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json"
            logger.info("Fetching NIST SP 800-171 Rev 3...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            catalog = data.get('catalog', {})
            groups = catalog.get('groups', [])

            # Extract requirements into flat list
            requirements = []
            for group in groups:
                family_id = group.get('id', '')
                family_title = group.get('title', '')

                for control in group.get('controls', []):
                    req_data = {
                        'id': control.get('id', ''),
                        'title': control.get('title', ''),
                        'family_id': family_id,
                        'family_title': family_title,
                    }

                    # Extract requirement text and discussion from parts
                    for part in control.get('parts', []):
                        part_name = part.get('name', '')
                        if part_name == 'statement':
                            req_data['requirement'] = part.get('prose', '')
                        elif part_name == 'discussion':
                            req_data['discussion'] = part.get('prose', '')
                        elif part_name == 'assessment':
                            req_data['assessment'] = part.get('prose', '')

                    # Extract properties
                    for prop in control.get('props', []):
                        if prop.get('name') == 'label':
                            req_data['label'] = prop.get('value', '')

                    requirements.append(req_data)

            logger.info(f"Fetched {len(requirements)} NIST SP 800-171 requirements from {len(groups)} families")

            return {
                'source': 'NIST SP 800-171 Rev 3',
                'version': catalog.get('metadata', {}).get('version', 'unknown'),
                'requirements': requirements
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching NIST SP 800-171: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing NIST SP 800-171: {str(e)}")
            return None

    def fetch_nist_ssdf(self) -> Optional[Dict]:
        """
        Fetch NIST SP 800-218 SSDF - Secure Software Development Framework.

        Returns:
            Dictionary containing SSDF practices and tasks
        """
        try:
            url = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-218/ver1/json/NIST_SP800-218_ver1_catalog.json"
            logger.info("Fetching NIST SP 800-218 SSDF...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            catalog = data.get('catalog', {})
            groups = catalog.get('groups', [])

            # Extract practices and tasks
            practice_groups = []
            for group in groups:
                group_data = {
                    'id': group.get('id', ''),
                    'title': group.get('title', ''),
                    'practices': []
                }

                for control in group.get('controls', []):
                    practice = {
                        'id': control.get('id', ''),
                        'title': control.get('title', ''),
                        'tasks': []
                    }

                    # Extract practice description from parts
                    for part in control.get('parts', []):
                        if part.get('name') == 'statement':
                            practice['description'] = part.get('prose', '')

                    # Extract tasks from nested controls
                    for task in control.get('controls', []):
                        task_data = {
                            'id': task.get('id', ''),
                            'title': task.get('title', ''),
                        }
                        for part in task.get('parts', []):
                            if part.get('name') == 'statement':
                                task_data['description'] = part.get('prose', '')
                        practice['tasks'].append(task_data)

                    # Extract properties (label)
                    for prop in control.get('props', []):
                        if prop.get('name') == 'label':
                            practice['label'] = prop.get('value', '')

                    group_data['practices'].append(practice)
                practice_groups.append(group_data)

            total_practices = sum(len(g['practices']) for g in practice_groups)
            total_tasks = sum(
                len(p['tasks'])
                for g in practice_groups
                for p in g['practices']
            )
            logger.info(f"Fetched NIST SSDF: {len(practice_groups)} groups, {total_practices} practices, {total_tasks} tasks")

            return {
                'source': 'NIST SP 800-218 SSDF v1.1',
                'version': catalog.get('metadata', {}).get('version', 'unknown'),
                'practice_groups': practice_groups
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching NIST SSDF: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing NIST SSDF: {str(e)}")
            return None

    def fetch_mitre_attack_ics(self) -> Optional[Dict]:
        """
        Fetch MITRE ATT&CK for ICS (Industrial Control Systems) in STIX format.

        Returns:
            Dictionary containing ICS-specific attack techniques, groups, and software
        """
        try:
            url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
            logger.info("Fetching MITRE ATT&CK for ICS...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            objects = data.get('objects', [])

            # Categorize objects by type
            techniques = []
            groups = []
            software = []
            mitigations = []

            for obj in objects:
                obj_type = obj.get('type', '')

                if obj_type == 'attack-pattern':
                    tech = {
                        'id': obj.get('id', ''),
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'platforms': obj.get('x_mitre_platforms', []),
                        'kill_chain_phases': [
                            phase.get('phase_name', '')
                            for phase in obj.get('kill_chain_phases', [])
                        ],
                    }
                    # Extract external ID (T####)
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            tech['mitre_id'] = ref.get('external_id', '')
                            tech['url'] = ref.get('url', '')
                            break
                    techniques.append(tech)

                elif obj_type == 'intrusion-set':
                    grp = {
                        'id': obj.get('id', ''),
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'aliases': obj.get('aliases', []),
                    }
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            grp['mitre_id'] = ref.get('external_id', '')
                            break
                    groups.append(grp)

                elif obj_type in ['malware', 'tool']:
                    sw = {
                        'id': obj.get('id', ''),
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'type': obj_type,
                        'platforms': obj.get('x_mitre_platforms', []),
                    }
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            sw['mitre_id'] = ref.get('external_id', '')
                            break
                    software.append(sw)

                elif obj_type == 'course-of-action':
                    mit = {
                        'id': obj.get('id', ''),
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                    }
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            mit['mitre_id'] = ref.get('external_id', '')
                            break
                    mitigations.append(mit)

            logger.info(f"Fetched MITRE ATT&CK ICS: {len(techniques)} techniques, {len(groups)} groups, {len(software)} software, {len(mitigations)} mitigations")

            return {
                'source': 'MITRE ATT&CK for ICS',
                'version': data.get('spec_version', 'unknown'),
                'techniques': techniques,
                'groups': groups,
                'software': software,
                'mitigations': mitigations
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching MITRE ATT&CK ICS: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing MITRE ATT&CK ICS: {str(e)}")
            return None

    def fetch_mitre_attack(self) -> Optional[Dict]:
        """Fetch MITRE ATT&CK framework data."""
        try:
            response = self.session.get(self.endpoints['mitre_attack'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching MITRE ATT&CK data: {str(e)}")
            return None

    def fetch_capec_data(self) -> Optional[Dict]:
        """Fetch MITRE CAPEC (Common Attack Pattern Enumeration and Classification) data."""
        try:
            import zipfile
            import io

            response = self.session.get(self.endpoints['mitre_capec'], timeout=60)
            response.raise_for_status()

            # CAPEC URL returns a ZIP file containing the XML
            content_type = response.headers.get('Content-Type', '')
            if 'zip' in content_type or response.content[:2] == b'PK':
                # Extract XML from ZIP
                with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                    xml_files = [f for f in zf.namelist() if f.endswith('.xml')]
                    if xml_files:
                        xml_content = zf.read(xml_files[0]).decode('utf-8')
                        logger.info(f"Extracted {xml_files[0]} from CAPEC ZIP ({len(xml_content)} chars)")
                        return self._parse_capec_xml(xml_content)
                    else:
                        logger.error("No XML file found in CAPEC ZIP")
                        return None
            else:
                # Direct XML response (fallback)
                return self._parse_capec_xml(response.text)

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CAPEC data: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error processing CAPEC data: {str(e)}")
            return None

    def _parse_capec_xml(self, xml_content: str) -> Optional[Dict]:
        """Parse CAPEC XML and extract attack patterns."""
        try:
            root = ET.fromstring(xml_content)

            # CAPEC namespace
            ns = {'capec': 'http://capec.mitre.org/capec-3'}

            attack_patterns = []
            for ap in root.findall('.//capec:Attack_Pattern', ns):
                pattern = {
                    'id': ap.get('ID'),
                    'name': ap.get('Name'),
                    'status': ap.get('Status'),
                    'abstraction': ap.get('Abstraction'),
                }

                # Extract description
                desc = ap.find('.//capec:Description', ns)
                if desc is not None:
                    pattern['description'] = ''.join(desc.itertext()).strip()

                # Extract likelihood
                likelihood = ap.find('.//capec:Likelihood_Of_Attack', ns)
                if likelihood is not None:
                    pattern['likelihood'] = likelihood.text

                # Extract severity
                severity = ap.find('.//capec:Typical_Severity', ns)
                if severity is not None:
                    pattern['severity'] = severity.text

                # Extract related weaknesses (CWE)
                weaknesses = []
                for cwe in ap.findall('.//capec:Related_Weakness', ns):
                    weaknesses.append(cwe.get('CWE_ID'))
                if weaknesses:
                    pattern['related_cwe'] = weaknesses

                # Extract mitigations
                mitigations = []
                for mit in ap.findall('.//capec:Mitigation', ns):
                    mitigations.append(''.join(mit.itertext()).strip())
                if mitigations:
                    pattern['mitigations'] = mitigations

                attack_patterns.append(pattern)

            logger.info(f"Parsed {len(attack_patterns)} CAPEC attack patterns")
            return {
                'Attack_Patterns': attack_patterns,
                'count': len(attack_patterns),
                'timestamp': datetime.now().isoformat(),
                'source': 'MITRE CAPEC'
            }

        except ET.ParseError as e:
            logger.error(f"Error parsing CAPEC XML: {str(e)}")
            return None

    def fetch_ubuntu_security_notices(self) -> Optional[Dict]:
        """Fetch Ubuntu Security Notices."""
        for attempt in range(3):
            try:
                response = self.session.get(self.endpoints['ubuntu_usn'], timeout=10)
                response.raise_for_status()
                feed = feedparser.parse(response.text)
                return {'entries': feed.entries}
            except Exception as e:
                logger.warning(f"Ubuntu Security attempt {attempt + 1}/3 failed: {str(e)}")
                if attempt < 2:
                    time.sleep(2)
        logger.error("Failed to fetch Ubuntu Security Notices after 3 attempts")
        return None

    def fetch_arxiv_papers(self) -> Optional[Dict]:
        """Fetch recent cyber security papers from arXiv."""
        try:
            response = self.session.get(self.endpoints['arxiv_cs_crypto'])
            response.raise_for_status()
            feed = feedparser.parse(response.text)
            return {'papers': feed.entries}
        except Exception as e:
            logger.error(f"Error fetching arXiv papers: {str(e)}")
            return None

    def fetch_redhat_security(self) -> Optional[Dict]:
        """Fetch Red Hat Security Data."""
        try:
            response = self.session.get(self.endpoints['redhat_security'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Red Hat Security data: {str(e)}")
            return None

    def fetch_microsoft_security(self) -> Optional[Dict]:
        """Fetch Microsoft Security Updates."""
        try:
            response = self.session.get(self.endpoints['microsoft_security'])
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching Microsoft Security Updates: {str(e)}")
            return None

    def fetch_malware_data(self) -> Optional[Dict]:
        """
        Fetch malware data from MalwareBazaar API.

        Returns:
            Dictionary containing recent malware samples or None if failed
        """
        try:
            # MalwareBazaar API requires Auth-Key header
            abuse_ch_key = os.getenv('ABUSE_CH_AUTH_KEY')
            if not abuse_ch_key:
                logger.warning("ABUSE_CH_AUTH_KEY not set - MalwareBazaar requires authentication. Get a key at https://auth.abuse.ch/")
                return None

            headers = {'Auth-Key': abuse_ch_key}
            response = self.session.post(
                self.endpoints['malware_bazaar'],
                data={'query': 'get_recent', 'selector': '100'},
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                return {
                    'samples': result.get('data', []),
                    'query_status': result.get('query_status'),
                    'timestamp': datetime.now().isoformat(),
                    'source': 'MalwareBazaar'
                }
            else:
                logger.warning(f"MalwareBazaar returned status {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error fetching MalwareBazaar data: {str(e)}")
            return None

    def fetch_social_engineering_data(self) -> Optional[Dict]:
        """
        Fetch phishing data from OpenPhish (free feed, no API key required).

        Returns:
            Dictionary containing phishing URLs or None if failed
        """
        try:
            # OpenPhish free feed
            response = self.session.get(self.endpoints['openphish'], timeout=30)
            if response.status_code == 200:
                phishing_urls = [url.strip() for url in response.text.split('\n') if url.strip()]
                return {
                    'phishing_urls': phishing_urls[:500],  # Limit to 500 URLs
                    'total_count': len(phishing_urls),
                    'timestamp': datetime.now().isoformat(),
                    'source': 'OpenPhish'
                }
            return None
        except Exception as e:
            logger.error(f"Error fetching OpenPhish data: {str(e)}")
            return None

    def scrape_security_articles(self, url: str) -> Optional[Dict]:
        """
        Scrape cyber security articles from provided URL.
        
        Args:
            url: URL to scrape
            
        Returns:
            Dictionary containing scraped data or None if failed
        """
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract relevant information (customize based on website structure)
            data = {
                'title': soup.title.string if soup.title else None,
                'text': soup.get_text(),
                'url': url,
                'timestamp': datetime.now().isoformat()
            }
            return data
        except (requests.exceptions.RequestException, AttributeError) as e:
            logger.error(f"Error scraping article from {url}: {str(e)}")
            return None

    def save_data(self, data: Union[Dict, List], source: str, format: str = 'json') -> bool:
        """
        Enhanced save_data method with better error handling and backup.
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = self.output_dir / f"{source}_{timestamp}.{format}"
            
            # Create backup directory
            backup_dir = self.output_dir / 'backups'
            backup_dir.mkdir(exist_ok=True)
            
            # Save data with proper encoding and error handling
            if format == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())  # Ensure data is written to disk
                    
            elif format == 'xml':
                # Improved XML handling
                root = ET.Element("data")
                self._dict_to_xml(data, root)
                tree = ET.ElementTree(root)
                tree.write(filename, encoding='utf-8', xml_declaration=True)
                
            elif format == 'yaml':
                with open(filename, 'w', encoding='utf-8') as f:
                    yaml.dump(data, f, allow_unicode=True, default_flow_style=False)
                    f.flush()
                    os.fsync(f.fileno())
                    
            elif format == 'csv':
                df = pd.DataFrame(data)
                df.to_csv(filename, index=False, encoding='utf-8')
            
            # Create backup
            backup_file = backup_dir / f"{source}_{timestamp}_backup.{format}"
            shutil.copy2(filename, backup_file)
            
            logger.info(f"Successfully saved data to {filename} with backup at {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return False

    def _dict_to_xml(self, data: Union[Dict, List, str, int, float], parent: ET.Element):
        """Helper method for converting dictionary to XML."""
        if isinstance(data, dict):
            for key, value in data.items():
                child = ET.SubElement(parent, str(key))
                self._dict_to_xml(value, child)
        elif isinstance(data, (list, tuple)):
            for item in data:
                child = ET.SubElement(parent, 'item')
                self._dict_to_xml(item, child)
        else:
            parent.text = str(data)

    def fetch_ctf_data(self) -> Optional[Dict]:
        """
        Fetch CTF event data and challenges from various platforms.

        Returns:
            Dictionary containing CTF data or None if failed
        """
        try:
            # Get PAST CTF events (more valuable for training - have writeups, solutions)
            end_time = datetime.now()
            start_time = end_time - timedelta(days=365)  # Past year of events

            params = {
                'start': int(start_time.timestamp()),
                'finish': int(end_time.timestamp()),
                'limit': 500  # Get more events
            }

            # CTFtime requires a proper User-Agent
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; CyberLLMInstruct/1.0; +https://github.com/Adelsamir01/CyberLLMInstruct)',
                'Accept': 'application/json'
            }

            response = self.session.get(self.endpoints['ctftime'], params=params, headers=headers)
            response.raise_for_status()
            ctftime_events = response.json()

            logger.info(f"Fetched {len(ctftime_events)} CTF events from the past year")

            # Compile CTF data from different sources
            ctf_data = {
                'ctftime_events': ctftime_events,
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'source': 'CTFtime API',
                    'event_timeframe': f"{start_time.date()} to {end_time.date()}"
                }
            }

            return ctf_data

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CTF data: {str(e)}")
            return None

    def fetch_security_testing_resources(self) -> Optional[Dict]:
        """
        Fetch OWASP Cheat Sheets - security best practices and testing guides.

        Returns:
            Dictionary containing OWASP cheatsheets or None if failed
        """
        try:
            logger.info("Fetching OWASP Cheat Sheets...")

            # Get list of cheatsheets from GitHub API
            api_url = "https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets"
            response = self.session.get(api_url, timeout=30)
            response.raise_for_status()
            files = response.json()

            # Filter markdown files only
            cheatsheet_files = [f for f in files if f['name'].endswith('.md')]
            logger.info(f"Found {len(cheatsheet_files)} OWASP cheatsheets")

            cheatsheets = []
            # Fetch content of each cheatsheet
            for i, file_info in enumerate(cheatsheet_files):
                try:
                    name = file_info['name'].replace('.md', '').replace('_', ' ')
                    raw_url = file_info['download_url']

                    # Fetch content
                    content_response = self.session.get(raw_url, timeout=30)
                    content_response.raise_for_status()
                    content = content_response.text

                    # Extract title and introduction
                    lines = content.split('\n')
                    title = name
                    introduction = ""

                    for j, line in enumerate(lines):
                        if line.startswith('# '):
                            title = line[2:].strip()
                        elif line.startswith('## Introduction') or line.startswith('## Overview'):
                            # Get next non-empty lines as introduction
                            intro_lines = []
                            for k in range(j + 1, min(j + 10, len(lines))):
                                if lines[k].startswith('## '):
                                    break
                                if lines[k].strip():
                                    intro_lines.append(lines[k].strip())
                            introduction = ' '.join(intro_lines)
                            break

                    cheatsheets.append({
                        'id': file_info['name'].replace('.md', ''),
                        'title': title,
                        'introduction': introduction[:1000] if introduction else '',
                        'content': content[:5000],  # Limit content size
                        'url': f"https://cheatsheetseries.owasp.org/cheatsheets/{file_info['name'].replace('.md', '.html')}",
                        'source': 'OWASP Cheat Sheet Series'
                    })

                    if (i + 1) % 20 == 0:
                        logger.info(f"Fetched {i + 1}/{len(cheatsheet_files)} cheatsheets")

                    # Rate limiting
                    time.sleep(0.5)

                except Exception as e:
                    logger.debug(f"Error fetching {file_info['name']}: {e}")
                    continue

            logger.info(f"Successfully fetched {len(cheatsheets)} OWASP cheatsheets")

            return {
                'source': 'OWASP Cheat Sheet Series',
                'cheatsheets': cheatsheets
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching OWASP cheatsheets: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing OWASP cheatsheets: {str(e)}")
            return None

    def fetch_alienvault_otx(self) -> Optional[Dict]:
        """
        Fetch threat intelligence pulses from AlienVault OTX.
        Uses search API to get diverse public pulses across threat categories.

        Returns:
            Dictionary containing threat pulses or None if failed
        """
        try:
            if not self.api_keys.get('alienvault'):
                logger.warning("AlienVault OTX API key not configured - set ALIENVAULT_API_KEY")
                return None

            headers = {'X-OTX-API-KEY': self.api_keys['alienvault']}
            all_pulses = []
            seen_ids = set()

            # Search for pulses across multiple threat categories
            search_terms = [
                'ransomware', 'malware', 'APT', 'phishing', 'botnet',
                'trojan', 'backdoor', 'exploit', 'CVE', 'threat',
                'attack', 'campaign', 'intrusion', 'IOC', 'C2'
            ]

            for term in search_terms:
                try:
                    response = self.session.get(
                        'https://otx.alienvault.com/api/v1/search/pulses',
                        headers=headers,
                        params={'q': term, 'limit': 200, 'sort': '-modified'},
                        timeout=30
                    )

                    if response.status_code == 200:
                        data = response.json()
                        results = data.get('results', [])
                        for pulse in results:
                            pulse_id = pulse.get('id')
                            if pulse_id and pulse_id not in seen_ids:
                                seen_ids.add(pulse_id)
                                all_pulses.append(pulse)

                        logger.info(f"OTX search '{term}': {len(results)} pulses (total unique: {len(all_pulses)})")

                        if len(all_pulses) >= 2000:
                            break

                    time.sleep(0.5)  # Rate limiting

                except Exception as e:
                    logger.warning(f"OTX search error for '{term}': {e}")
                    continue

            # Also get subscribed pulses
            try:
                response = self.session.get(
                    self.endpoints['alienvault_otx'],
                    headers=headers,
                    params={'limit': 100},
                    timeout=30
                )
                if response.status_code == 200:
                    data = response.json()
                    for pulse in data.get('results', []):
                        pulse_id = pulse.get('id')
                        if pulse_id and pulse_id not in seen_ids:
                            seen_ids.add(pulse_id)
                            all_pulses.append(pulse)
                    logger.info(f"OTX subscribed: added {len(data.get('results', []))} pulses")
            except Exception as e:
                logger.warning(f"OTX subscribed error: {e}")

            logger.info(f"Total unique OTX pulses collected: {len(all_pulses)}")

            return {
                'pulses': all_pulses[:2000],  # Limit to 2000 pulses
                'count': len(all_pulses),
                'timestamp': datetime.now().isoformat(),
                'source': 'AlienVault OTX'
            }
        except Exception as e:
            logger.error(f"Error fetching AlienVault OTX data: {str(e)}")
            return None

    def fetch_threatfox_iocs(self) -> Optional[Dict]:
        """
        Fetch recent IOCs from ThreatFox.

        Returns:
            Dictionary containing IOCs or None if failed
        """
        try:
            # ThreatFox API also requires Auth-Key header (same as MalwareBazaar)
            abuse_ch_key = os.getenv('ABUSE_CH_AUTH_KEY')
            if not abuse_ch_key:
                logger.warning("ABUSE_CH_AUTH_KEY not set - ThreatFox requires authentication. Get a key at https://auth.abuse.ch/")
                return None

            headers = {'Auth-Key': abuse_ch_key}
            response = self.session.post(
                self.endpoints['threatfox_api'],
                json={'query': 'get_iocs', 'days': 7},
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                return {
                    'iocs': result.get('data', [])[:500],  # Limit to 500 IOCs
                    'query_status': result.get('query_status'),
                    'timestamp': datetime.now().isoformat(),
                    'source': 'ThreatFox'
                }
            else:
                logger.warning(f"ThreatFox returned status {response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error fetching ThreatFox data: {str(e)}")
            return None

    def fetch_github_security_advisories(self) -> Optional[Dict]:
        """
        Fetch security advisories from GitHub Security Advisory Database.

        Returns:
            Dictionary containing security advisories or None if failed
        """
        try:
            # Use the official GitHub Advisories API (not repo search)
            advisories = []
            headers = {
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
            }

            # Add auth token if available for higher rate limits
            github_token = os.getenv('GITHUB_TOKEN')
            if github_token:
                headers['Authorization'] = f'Bearer {github_token}'

            # Fetch multiple pages of advisories
            for page in range(1, 6):  # Get up to 500 advisories (5 pages x 100)
                response = self.session.get(
                    'https://api.github.com/advisories',
                    headers=headers,
                    params={'per_page': 100, 'page': page},
                    timeout=30
                )

                if response.status_code != 200:
                    logger.warning(f"GitHub Advisories API returned {response.status_code}")
                    break

                page_advisories = response.json()
                if not page_advisories:
                    break

                advisories.extend(page_advisories)
                logger.info(f"Fetched page {page}: {len(page_advisories)} advisories")

                # Check if there are more pages
                if 'Link' not in response.headers or 'next' not in response.headers.get('Link', ''):
                    break

            logger.info(f"Total GitHub advisories fetched: {len(advisories)}")

            return {
                'advisories': advisories,
                'count': len(advisories),
                'timestamp': datetime.now().isoformat(),
                'source': 'GitHub Security Advisory Database'
            }
        except Exception as e:
            logger.error(f"Error fetching GitHub Security Advisories: {str(e)}")
            return None

    def fetch_lolbas(self) -> Optional[Dict]:
        """
        Fetch LOLBAS (Living Off The Land Binaries And Scripts) data.
        Windows binaries that can be used for post-exploitation.

        Returns:
            Dictionary containing LOLBAS entries or None if failed
        """
        try:
            url = "https://lolbas-project.github.io/api/lolbas.json"
            logger.info("Fetching LOLBAS data...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            # Data is a list of LOLBAS entries
            entries = data if isinstance(data, list) else []

            # Categorize entries by type
            categories = {}
            for entry in entries:
                entry_type = entry.get('Type', 'Unknown')
                if entry_type not in categories:
                    categories[entry_type] = 0
                categories[entry_type] += 1

            logger.info(f"Fetched {len(entries)} LOLBAS entries: {categories}")

            return {
                'source': 'LOLBAS Project',
                'description': 'Living Off The Land Binaries And Scripts - Windows binaries for post-exploitation',
                'entries': entries,
                'count': len(entries),
                'categories': categories,
                'timestamp': datetime.now().isoformat()
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching LOLBAS data: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing LOLBAS data: {str(e)}")
            return None

    def fetch_loldrivers(self) -> Optional[Dict]:
        """
        Fetch LOLDrivers (Living Off The Land Drivers) data.
        Vulnerable and malicious Windows drivers.

        Returns:
            Dictionary containing LOLDrivers entries or None if failed
        """
        try:
            url = "https://www.loldrivers.io/api/drivers.json"
            logger.info("Fetching LOLDrivers data...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            # Data is a list of driver entries
            entries = data if isinstance(data, list) else []

            # Categorize by category
            categories = {}
            for entry in entries:
                cat = entry.get('Category', 'Unknown')
                if cat not in categories:
                    categories[cat] = 0
                categories[cat] += 1

            logger.info(f"Fetched {len(entries)} LOLDrivers entries: {categories}")

            return {
                'source': 'LOLDrivers Project',
                'description': 'Living Off The Land Drivers - Vulnerable and malicious Windows drivers',
                'entries': entries,
                'count': len(entries),
                'categories': categories,
                'timestamp': datetime.now().isoformat()
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching LOLDrivers data: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing LOLDrivers data: {str(e)}")
            return None

    def fetch_hijacklibs(self) -> Optional[Dict]:
        """
        Fetch HijackLibs DLL hijacking data.
        Mappings between DLLs and vulnerable executables.

        Returns:
            Dictionary containing HijackLibs entries or None if failed
        """
        try:
            url = "https://hijacklibs.net/api/hijacklibs.json"
            logger.info("Fetching HijackLibs data...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            # Data is a list of hijack entries
            entries = data if isinstance(data, list) else []

            # Categorize by type
            hijack_types = {}
            for entry in entries:
                h_type = entry.get('Type', 'Unknown')
                if h_type not in hijack_types:
                    hijack_types[h_type] = 0
                hijack_types[h_type] += 1

            logger.info(f"Fetched {len(entries)} HijackLibs entries: {hijack_types}")

            return {
                'source': 'HijackLibs',
                'description': 'DLL Hijacking opportunities - mappings between DLLs and vulnerable executables',
                'entries': entries,
                'count': len(entries),
                'hijack_types': hijack_types,
                'timestamp': datetime.now().isoformat()
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching HijackLibs data: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing HijackLibs data: {str(e)}")
            return None

    def fetch_osint_framework(self) -> Optional[Dict]:
        """
        Fetch OSINT Framework data - categorized OSINT tools and resources.

        Returns:
            Dictionary containing OSINT Framework categories and tools or None if failed
        """
        try:
            url = "https://osintframework.com/arf.json"
            logger.info("Fetching OSINT Framework data...")

            response = self.session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()

            def count_tools(node, depth=0):
                """Recursively count tools in the tree structure."""
                count = 0
                if isinstance(node, dict):
                    if node.get('type') == 'url':
                        count = 1
                    for child in node.get('children', []):
                        count += count_tools(child, depth + 1)
                elif isinstance(node, list):
                    for item in node:
                        count += count_tools(item, depth + 1)
                return count

            def extract_categories(node, parent_path=""):
                """Extract top-level categories with tool counts."""
                categories = []
                if isinstance(node, dict):
                    name = node.get('name', '')
                    current_path = f"{parent_path}/{name}" if parent_path else name

                    if node.get('children'):
                        tool_count = count_tools(node)
                        if parent_path == "":  # Top-level category
                            categories.append({
                                'name': name,
                                'tool_count': tool_count
                            })
                        for child in node.get('children', []):
                            categories.extend(extract_categories(child, current_path))
                elif isinstance(node, list):
                    for item in node:
                        categories.extend(extract_categories(item, parent_path))
                return categories

            # Get categories from root
            root_children = data.get('children', []) if isinstance(data, dict) else data
            categories = []
            total_tools = 0

            for child in root_children:
                if isinstance(child, dict) and child.get('name'):
                    tool_count = count_tools(child)
                    total_tools += tool_count
                    categories.append({
                        'name': child.get('name'),
                        'tool_count': tool_count
                    })

            logger.info(f"Fetched OSINT Framework: {len(categories)} categories, {total_tools} tools")

            return {
                'source': 'OSINT Framework',
                'description': 'Categorized collection of OSINT tools and resources',
                'framework_data': data,
                'categories_summary': categories,
                'total_tools': total_tools,
                'timestamp': datetime.now().isoformat()
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching OSINT Framework data: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing OSINT Framework data: {str(e)}")
            return None

def main():
    """Main function to process command-line arguments and run data collection."""
    description = """
    Collect cybersecurity data from various sources.

    Working sources:
    - cve_data: CVE vulnerability data from NVD
    - opencve_data: CVE vulnerability data from OpenCVE API
    - mitre_attack: MITRE ATT&CK framework data
    - capec_data: Common Attack Pattern Enumeration and Classification data
    - ubuntu_security: Ubuntu Security Notices
    - arxiv_papers: Recent cybersecurity papers from arXiv
    - redhat_security: Red Hat Security Data
    - microsoft_security: Microsoft Security Updates
    - ctf_data: CTF event data and challenges
    - malware_data: Malware samples from MalwareBazaar
    - social_engineering: Phishing URLs from OpenPhish
    - alienvault_otx: Threat intelligence from AlienVault OTX
    - threatfox_iocs: IOCs from ThreatFox
    - github_security: Security advisories from GitHub
    - lolbas: Living Off The Land Binaries (Windows post-exploitation)
    - loldrivers: Vulnerable/malicious Windows drivers
    - hijacklibs: DLL hijacking opportunities
    - osint_framework: OSINT tools and resources catalog

    Disabled sources (use --sources to enable):
    - nist_standards: NIST SP 800-53 Rev 5 security controls
    - nist_csf: NIST Cybersecurity Framework 2.0
    - nist_sp800_171: NIST SP 800-171 Rev 3 (CUI protection)
    - nist_ssdf: NIST SP 800-218 SSDF (Secure Software Development)
    - mitre_attack_ics: MITRE ATT&CK for ICS/OT
    - security_testing: OWASP Cheat Sheets
    """

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sources", nargs="+", help="List of sources to fetch data from, space-separated")
    parser.add_argument("--output-dir", default="raw_data", help="Directory to save collected data")
    parser.add_argument("--cve-stratified", action="store_true", help="Use stratified CVE collection (by period and severity)")
    parser.add_argument("--cve-min-period", type=int, default=5000, help="Minimum CVEs for smallest period (old=20%%, mid=30%%, recent=50%%)")
    parser.add_argument("--cve-period", choices=['old', 'mid', 'recent', 'all'], default='all', help="Which period to collect (default: all)")

    args = parser.parse_args()

    collector = CyberDataCollector(output_dir=args.output_dir)

    # Define all available sources
    all_sources = {
        'cve_data': collector.fetch_cve_data,
        'opencve_data': collector.fetch_opencve_data,
        'mitre_attack': collector.fetch_mitre_attack,
        'capec_data': collector.fetch_capec_data,
        'ubuntu_security': collector.fetch_ubuntu_security_notices,
        'arxiv_papers': collector.fetch_arxiv_papers,
        'redhat_security': collector.fetch_redhat_security,
        'microsoft_security': collector.fetch_microsoft_security,
        'ctf_data': collector.fetch_ctf_data,
        'malware_data': collector.fetch_malware_data,
        'social_engineering': collector.fetch_social_engineering_data,
        'alienvault_otx': collector.fetch_alienvault_otx,
        'threatfox_iocs': collector.fetch_threatfox_iocs,
        'github_security': collector.fetch_github_security_advisories,
        # Offensive/Pentest sources
        'lolbas': collector.fetch_lolbas,
        'loldrivers': collector.fetch_loldrivers,
        'hijacklibs': collector.fetch_hijacklibs,
        # OSINT sources
        'osint_framework': collector.fetch_osint_framework,
    }

    # Disabled sources (need special handling or have known issues)
    disabled_sources = {
        'nist_standards': collector.fetch_nist_standards,
        'nist_csf': collector.fetch_nist_csf,
        'nist_sp800_171': collector.fetch_nist_sp800_171,
        'nist_ssdf': collector.fetch_nist_ssdf,
        'mitre_attack_ics': collector.fetch_mitre_attack_ics,
        'security_testing': collector.fetch_security_testing_resources,
    }
    
    # If specific sources are provided, use only those
    sources_to_fetch = {}
    if args.sources:
        for source in args.sources:
            if source in all_sources:
                sources_to_fetch[source] = all_sources[source]
            elif source in disabled_sources:
                sources_to_fetch[source] = disabled_sources[source]
                logger.warning(f"Including disabled source: {source}")
            elif source == "all":
                sources_to_fetch = all_sources
                break
            else:
                logger.warning(f"Unknown source: {source}, ignoring")
    else:
        # If no sources specified, use all working ones
        sources_to_fetch = all_sources
    
    # Handle stratified CVE collection
    if args.cve_stratified:
        cve_data = collector.fetch_cve_data_stratified(
            min_per_period=args.cve_min_period,
            only_period=args.cve_period if args.cve_period != 'all' else None,
        )

        for period_name, cves in cve_data.items():
            if cves:
                filename = f"cve_data_{period_name}"
                collector.save_data({'vulnerabilities': cves, 'period': period_name}, filename)
                logger.info(f"Saved {len(cves)} CVEs for period '{period_name}'")

        # Remove cve_data from sources to avoid double-fetching
        sources_to_fetch.pop('cve_data', None)

    logger.info(f"Collecting data from {len(sources_to_fetch)} sources")

    for source_name, fetch_function in sources_to_fetch.items():
        logger.info(f"Fetching data from {source_name}...")
        data = fetch_function()
        if data:
            collector.save_data(data, source_name)
        else:
            logger.warning(f"No data retrieved from {source_name}")

if __name__ == "__main__":
    main() 