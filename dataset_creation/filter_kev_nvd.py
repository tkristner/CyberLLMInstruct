#!/usr/bin/env python3
"""
Filter and process VulnCheck KEV and NVD data for causal graph integration.

This script:
1. Filters VulnCheck KEV to extract exploited vulnerabilities with ATT&CK relevance
2. Filters NVD to extract critical CVEs (CVSS >= 9.0) with CWE mappings
3. Creates unified output for causal graph integration
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# CWE to ATT&CK mapping based on MITRE and security research
# Extended mapping for improved coverage (Issue #16)
CWE_TO_ATTACK = {
    # Injection vulnerabilities
    'CWE-78': ['T1059'],       # OS Command Injection -> Command Execution
    'CWE-77': ['T1059'],       # Command Injection
    'CWE-89': ['T1190'],       # SQL Injection -> Exploit Public-Facing App
    'CWE-94': ['T1059'],       # Code Injection -> Execution
    'CWE-95': ['T1059'],       # Eval Injection
    'CWE-79': ['T1189'],       # XSS -> Drive-by Compromise
    'CWE-74': ['T1059'],       # Improper Neutralization of Special Elements
    'CWE-917': ['T1059'],      # Server-Side Template Injection (SSTI)
    'CWE-1236': ['T1059'],     # CSV Injection
    'CWE-611': ['T1005', 'T1190'],  # XML External Entity (XXE)
    'CWE-1321': ['T1059'],     # Prototype Pollution (JavaScript)

    # Memory corruption
    'CWE-787': ['T1203'],      # Out-of-bounds Write -> Exploitation for Client Execution
    'CWE-416': ['T1203'],      # Use After Free
    'CWE-119': ['T1203'],      # Buffer Overflow
    'CWE-120': ['T1203'],      # Classic Buffer Overflow
    'CWE-121': ['T1203'],      # Stack-based Buffer Overflow
    'CWE-122': ['T1203'],      # Heap-based Buffer Overflow
    'CWE-123': ['T1203'],      # Write-what-where Condition
    'CWE-124': ['T1203'],      # Buffer Underwrite
    'CWE-125': ['T1203'],      # Out-of-bounds Read
    'CWE-126': ['T1203'],      # Buffer Over-read
    'CWE-127': ['T1203'],      # Buffer Under-read
    'CWE-190': ['T1203'],      # Integer Overflow
    'CWE-191': ['T1203'],      # Integer Underflow
    'CWE-415': ['T1203'],      # Double Free
    'CWE-476': ['T1203'],      # NULL Pointer Dereference
    'CWE-704': ['T1203'],      # Incorrect Type Conversion
    'CWE-824': ['T1203'],      # Access of Uninitialized Pointer
    'CWE-843': ['T1203'],      # Type Confusion

    # Authentication/Authorization
    'CWE-287': ['T1078'],      # Improper Authentication -> Valid Accounts
    'CWE-288': ['T1078'],      # Authentication Bypass Using Alternate Path
    'CWE-289': ['T1078'],      # Authentication Bypass by Alternate Name
    'CWE-290': ['T1078'],      # Authentication Bypass by Spoofing
    'CWE-306': ['T1190'],      # Missing Authentication -> Exploit Public App
    'CWE-284': ['T1548'],      # Improper Access Control -> Abuse Elevation
    'CWE-269': ['T1548'],      # Improper Privilege Management
    'CWE-264': ['T1548'],      # Permissions/Privileges
    'CWE-863': ['T1548'],      # Incorrect Authorization
    'CWE-862': ['T1548'],      # Missing Authorization
    'CWE-307': ['T1110'],      # Improper Restriction of Excessive Authentication Attempts -> Brute Force
    'CWE-798': ['T1078'],      # Hard-coded Credentials -> Valid Accounts
    'CWE-522': ['T1078', 'T1552'],  # Insufficiently Protected Credentials
    'CWE-521': ['T1078'],      # Weak Password Requirements
    'CWE-259': ['T1078'],      # Use of Hard-coded Password
    'CWE-256': ['T1552'],      # Plaintext Storage of Password

    # Session management
    'CWE-352': ['T1185'],      # Cross-Site Request Forgery (CSRF)
    'CWE-384': ['T1185'],      # Session Fixation
    'CWE-613': ['T1185'],      # Insufficient Session Expiration
    'CWE-1021': ['T1185'],     # Improper Restriction of Rendered UI Layers (Clickjacking)

    # File operations
    'CWE-22': ['T1083', 'T1005'],   # Path Traversal -> File Discovery, Collection
    'CWE-23': ['T1083', 'T1005'],   # Relative Path Traversal
    'CWE-36': ['T1083', 'T1005'],   # Absolute Path Traversal
    'CWE-434': ['T1105'],      # Unrestricted File Upload -> Ingress Tool Transfer
    'CWE-59': ['T1574'],       # Symlink Following -> Hijack Execution Flow
    'CWE-426': ['T1574'],      # Untrusted Search Path
    'CWE-427': ['T1574'],      # Uncontrolled Search Path

    # Deserialization
    'CWE-502': ['T1059', 'T1190'],  # Deserialization -> Execution, Exploit App

    # Input validation
    'CWE-20': ['T1190'],       # Improper Input Validation

    # Cryptography
    'CWE-327': ['T1557'],      # Broken Crypto -> Adversary-in-the-Middle
    'CWE-295': ['T1557'],      # Improper Cert Validation
    'CWE-319': ['T1557', 'T1040'],  # Cleartext Transmission -> Network Sniffing
    'CWE-326': ['T1557'],      # Inadequate Encryption Strength
    'CWE-328': ['T1557'],      # Reversible One-Way Hash
    'CWE-330': ['T1557'],      # Use of Insufficiently Random Values
    'CWE-757': ['T1557'],      # Selection of Less-Secure Algorithm During Negotiation
    'CWE-311': ['T1557', 'T1552'],  # Missing Encryption of Sensitive Data

    # Information disclosure
    'CWE-200': ['T1005'],      # Information Exposure -> Data from Local System
    'CWE-209': ['T1005'],      # Error Message Info Leak
    'CWE-532': ['T1005', 'T1552'],  # Insertion of Sensitive Info into Log
    'CWE-538': ['T1005'],      # Insertion of Sensitive Info into Externally-Accessible File
    'CWE-312': ['T1552'],      # Cleartext Storage of Sensitive Information

    # SSRF
    'CWE-918': ['T1090'],      # SSRF -> Proxy

    # Resource exhaustion / DoS
    'CWE-400': ['T1499'],      # Uncontrolled Resource Consumption
    'CWE-770': ['T1499'],      # Allocation of Resources Without Limits
    'CWE-674': ['T1499'],      # Uncontrolled Recursion
    'CWE-835': ['T1499'],      # Loop with Unreachable Exit Condition

    # Phishing/Social Engineering related
    'CWE-601': ['T1566'],      # URL Redirection to Untrusted Site (Open Redirect)
}

# Techniques commonly associated with ransomware
RANSOMWARE_TECHNIQUES = [
    'T1486',  # Data Encrypted for Impact
    'T1490',  # Inhibit System Recovery
    'T1489',  # Service Stop
    'T1491',  # Defacement
]


@dataclass
class FilteredCVE:
    """Filtered CVE entry with ATT&CK relevance."""
    cve_id: str
    description: str
    cwes: List[str]
    attack_techniques: List[str]
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    vendor: Optional[str]
    product: Optional[str]
    is_exploited: bool
    is_ransomware: bool
    exploit_refs: List[str]
    date_added: Optional[str]
    source: str  # 'kev' or 'nvd'


class KEVNVDFilter:
    """Filter VulnCheck KEV and NVD data for causal graph integration."""

    def __init__(self, raw_data_dir: str = "raw_data", output_dir: str = "filtered_data"):
        self.raw_data_dir = Path(raw_data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.stats = {
            'kev_total': 0,
            'kev_with_attack': 0,
            'kev_ransomware': 0,
            'nvd_total': 0,
            'nvd_critical': 0,
            'nvd_with_attack': 0,
        }

    def map_cwe_to_attack(self, cwes: List[str]) -> List[str]:
        """Map CWE IDs to ATT&CK technique IDs."""
        techniques = set()
        for cwe in cwes:
            # Normalize CWE format
            cwe_normalized = cwe.upper()
            if not cwe_normalized.startswith('CWE-'):
                cwe_normalized = f'CWE-{cwe_normalized}'

            if cwe_normalized in CWE_TO_ATTACK:
                techniques.update(CWE_TO_ATTACK[cwe_normalized])

        return sorted(list(techniques))

    def filter_kev(self) -> List[FilteredCVE]:
        """Filter VulnCheck KEV data."""
        kev_file = self.raw_data_dir / "CISA_vulncheck_known_exploited_vulnerabilities.json"

        if not kev_file.exists():
            logger.warning(f"KEV file not found: {kev_file}")
            return []

        logger.info(f"Loading KEV data from {kev_file}")
        with open(kev_file, 'r') as f:
            kev_data = json.load(f)

        self.stats['kev_total'] = len(kev_data)
        logger.info(f"Loaded {len(kev_data)} KEV entries")

        filtered = []

        for entry in kev_data:
            cve_ids = entry.get('cve', [])
            if not cve_ids:
                continue

            cve_id = cve_ids[0]  # Primary CVE
            cwes = entry.get('cwes', [])

            # Map to ATT&CK techniques
            attack_techniques = self.map_cwe_to_attack(cwes)

            # Check ransomware association
            is_ransomware = entry.get('knownRansomwareCampaignUse') == 'Known'
            if is_ransomware:
                self.stats['kev_ransomware'] += 1
                # Add ransomware techniques
                attack_techniques = list(set(attack_techniques + RANSOMWARE_TECHNIQUES))

            # Extract exploit references
            exploit_refs = []
            for xdb in entry.get('vulncheck_xdb', []):
                if xdb.get('xdb_url'):
                    exploit_refs.append(xdb['xdb_url'])

            # Create filtered entry
            filtered_cve = FilteredCVE(
                cve_id=cve_id,
                description=entry.get('shortDescription', ''),
                cwes=cwes,
                attack_techniques=attack_techniques,
                cvss_score=None,  # KEV doesn't include CVSS
                cvss_severity=None,
                vendor=entry.get('vendorProject'),
                product=entry.get('product'),
                is_exploited=True,  # All KEV entries are exploited
                is_ransomware=is_ransomware,
                exploit_refs=exploit_refs,
                date_added=entry.get('cisa_date_added'),
                source='kev'
            )

            filtered.append(filtered_cve)

            if attack_techniques:
                self.stats['kev_with_attack'] += 1

        logger.info(f"KEV: {len(filtered)} entries, {self.stats['kev_with_attack']} with ATT&CK mapping, {self.stats['kev_ransomware']} ransomware")
        return filtered

    def filter_nvd(self, min_cvss: float = 9.0, years: List[int] = None) -> List[FilteredCVE]:
        """Filter NVD data for critical CVEs."""
        if years is None:
            years = [2020, 2021, 2022, 2023, 2024, 2025]

        filtered = []

        for year in years:
            nvd_file = self.raw_data_dir / f"nvdcve-2.0-{year}.json"

            if not nvd_file.exists():
                logger.warning(f"NVD file not found: {nvd_file}")
                continue

            logger.info(f"Loading NVD {year} data from {nvd_file}")
            with open(nvd_file, 'r') as f:
                nvd_data = json.load(f)

            vulnerabilities = nvd_data.get('vulnerabilities', [])
            self.stats['nvd_total'] += len(vulnerabilities)
            logger.info(f"Loaded {len(vulnerabilities)} CVEs from {year}")

            for vuln in vulnerabilities:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', '')

                # Extract CVSS score
                cvss_score = None
                cvss_severity = None

                metrics = cve.get('metrics', {})

                # Try CVSS 3.1 first, then 3.0, then 2.0
                for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss_data = metrics[metric_key][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_severity = cvss_data.get('baseSeverity')
                        break

                # Filter by CVSS score
                if cvss_score is None or cvss_score < min_cvss:
                    continue

                self.stats['nvd_critical'] += 1

                # Extract CWEs
                cwes = []
                for weakness in cve.get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        cwe_value = desc.get('value', '')
                        if cwe_value.startswith('CWE-'):
                            cwes.append(cwe_value)

                # Map to ATT&CK
                attack_techniques = self.map_cwe_to_attack(cwes)

                # Extract description
                description = ''
                for desc in cve.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                # Create filtered entry
                filtered_cve = FilteredCVE(
                    cve_id=cve_id,
                    description=description[:500],  # Limit description length
                    cwes=cwes,
                    attack_techniques=attack_techniques,
                    cvss_score=cvss_score,
                    cvss_severity=cvss_severity,
                    vendor=None,  # NVD doesn't have vendor in same format
                    product=None,
                    is_exploited=False,  # Unknown from NVD alone
                    is_ransomware=False,
                    exploit_refs=[],
                    date_added=cve.get('published'),
                    source='nvd'
                )

                filtered.append(filtered_cve)

                if attack_techniques:
                    self.stats['nvd_with_attack'] += 1

        logger.info(f"NVD: {len(filtered)} critical CVEs (CVSS >= {min_cvss}), {self.stats['nvd_with_attack']} with ATT&CK mapping")
        return filtered

    def merge_and_deduplicate(self, kev_entries: List[FilteredCVE], nvd_entries: List[FilteredCVE]) -> List[FilteredCVE]:
        """Merge KEV and NVD entries, preferring KEV data for duplicates."""
        # Index KEV by CVE ID
        kev_by_id = {entry.cve_id: entry for entry in kev_entries}

        merged = list(kev_entries)  # Start with all KEV entries

        # Add NVD entries that aren't in KEV
        nvd_only = 0
        nvd_enriched = 0

        for nvd_entry in nvd_entries:
            if nvd_entry.cve_id in kev_by_id:
                # Enrich KEV entry with CVSS from NVD
                kev_entry = kev_by_id[nvd_entry.cve_id]
                if nvd_entry.cvss_score:
                    # Find and update in merged list
                    for i, entry in enumerate(merged):
                        if entry.cve_id == nvd_entry.cve_id:
                            merged[i] = FilteredCVE(
                                cve_id=entry.cve_id,
                                description=entry.description,
                                cwes=list(set(entry.cwes + nvd_entry.cwes)),
                                attack_techniques=list(set(entry.attack_techniques + nvd_entry.attack_techniques)),
                                cvss_score=nvd_entry.cvss_score,
                                cvss_severity=nvd_entry.cvss_severity,
                                vendor=entry.vendor,
                                product=entry.product,
                                is_exploited=entry.is_exploited,
                                is_ransomware=entry.is_ransomware,
                                exploit_refs=entry.exploit_refs,
                                date_added=entry.date_added,
                                source='kev+nvd'
                            )
                            nvd_enriched += 1
                            break
            else:
                merged.append(nvd_entry)
                nvd_only += 1

        logger.info(f"Merged: {len(merged)} total ({len(kev_entries)} KEV, {nvd_only} NVD-only, {nvd_enriched} enriched)")
        return merged

    def save_filtered_data(self, entries: List[FilteredCVE], filename: str):
        """Save filtered data to JSON."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.output_dir / f"{filename}_{timestamp}.json"

        # Convert to dicts
        data = [asdict(entry) for entry in entries]

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(entries)} entries to {output_file}")
        return output_file

    def generate_attack_mapping_summary(self, entries: List[FilteredCVE]) -> Dict:
        """Generate summary of ATT&CK technique coverage."""
        technique_counts = {}
        cwe_counts = {}

        for entry in entries:
            for technique in entry.attack_techniques:
                technique_counts[technique] = technique_counts.get(technique, 0) + 1
            for cwe in entry.cwes:
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

        return {
            'total_entries': len(entries),
            'entries_with_attack': sum(1 for e in entries if e.attack_techniques),
            'entries_exploited': sum(1 for e in entries if e.is_exploited),
            'entries_ransomware': sum(1 for e in entries if e.is_ransomware),
            'technique_distribution': dict(sorted(technique_counts.items(), key=lambda x: -x[1])),
            'cwe_distribution': dict(sorted(cwe_counts.items(), key=lambda x: -x[1])[:20]),
        }

    def run(self, include_nvd: bool = True, nvd_min_cvss: float = 9.0):
        """Run the full filtering pipeline."""
        logger.info("=" * 60)
        logger.info("Starting KEV/NVD filtering pipeline")
        logger.info("=" * 60)

        # Filter KEV
        kev_entries = self.filter_kev()

        # Filter NVD (optional)
        nvd_entries = []
        if include_nvd:
            nvd_entries = self.filter_nvd(min_cvss=nvd_min_cvss)

        # Merge and deduplicate
        merged_entries = self.merge_and_deduplicate(kev_entries, nvd_entries)

        # Save outputs
        self.save_filtered_data(kev_entries, "kev_filtered")
        if nvd_entries:
            self.save_filtered_data(nvd_entries, "nvd_critical_filtered")
        self.save_filtered_data(merged_entries, "cve_attack_mapping")

        # Generate and save summary
        summary = self.generate_attack_mapping_summary(merged_entries)
        summary['stats'] = self.stats

        summary_file = self.output_dir / f"cve_attack_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        logger.info("=" * 60)
        logger.info("FILTERING SUMMARY")
        logger.info("=" * 60)
        logger.info(f"KEV entries: {self.stats['kev_total']}")
        logger.info(f"  - With ATT&CK mapping: {self.stats['kev_with_attack']}")
        logger.info(f"  - Ransomware: {self.stats['kev_ransomware']}")
        logger.info(f"NVD entries processed: {self.stats['nvd_total']}")
        logger.info(f"  - Critical (CVSS >= {nvd_min_cvss}): {self.stats['nvd_critical']}")
        logger.info(f"  - With ATT&CK mapping: {self.stats['nvd_with_attack']}")
        logger.info(f"Total merged entries: {len(merged_entries)}")
        logger.info(f"Unique ATT&CK techniques: {len(summary['technique_distribution'])}")

        return merged_entries, summary


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Filter KEV and NVD data for causal graph")
    parser.add_argument("--raw-dir", default="raw_data", help="Raw data directory")
    parser.add_argument("--output-dir", default="filtered_data", help="Output directory")
    parser.add_argument("--no-nvd", action="store_true", help="Skip NVD processing")
    parser.add_argument("--nvd-min-cvss", type=float, default=9.0, help="Minimum CVSS for NVD (default: 9.0)")

    args = parser.parse_args()

    filter_pipeline = KEVNVDFilter(
        raw_data_dir=args.raw_dir,
        output_dir=args.output_dir
    )

    filter_pipeline.run(
        include_nvd=not args.no_nvd,
        nvd_min_cvss=args.nvd_min_cvss
    )


if __name__ == "__main__":
    main()
