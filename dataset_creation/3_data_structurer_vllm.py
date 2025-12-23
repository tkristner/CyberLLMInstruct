#!/usr/bin/env python3
"""
Data structurer using vLLM with parallel processing.
Converts filtered data into instruction-response pairs for training.

Enhanced version with:
- Extended MITRE/STIX type detection (malware, intrusion-set, campaign, tool, etc.)
- Diversified instruction templates per type
- STIX relationship exploitation
- Better quality validation
"""

import json
import logging
import yaml
import pandas as pd
import asyncio
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple
from datetime import datetime
import re
import random

from vllm_client import VLLMClient, VLLMConfig, check_vllm_health

# Import calibrated uncertainty module for response language calibration
try:
    from calibrated_uncertainty import get_uncertainty_prefix, get_uncertainty_qualifier
    HAS_CALIBRATED_UNCERTAINTY = True
except ImportError:
    HAS_CALIBRATED_UNCERTAINTY = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CyberDataStructurerVLLM:
    """Data structurer using vLLM for parallel LLM inference."""

    def __init__(
        self,
        input_dir: str = "filtered_data/sources",
        output_dir: str = "structured_data",
        vllm_url: str = "http://localhost:8000",
        vllm_model: str = "nemotron",
        max_concurrent: int = 8,
        max_instructions_per_entry: int = 3,
        enable_thinking: bool = True,
        reasoning_budget: int = 128,
    ):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_instructions_per_entry = max_instructions_per_entry

        self.vllm_config = VLLMConfig(
            base_url=vllm_url,
            model=vllm_model,
            max_tokens=3072,  # Sufficient for reasoning JSON + detailed answer
            temperature=0.2,  # Low for consistent JSON structure
            max_concurrent=max_concurrent,
            enable_thinking=enable_thinking,
            reasoning_budget=reasoning_budget,  # Default 256 recommended for quality
        )

        # Extended template patterns for all cybersecurity data types
        self.templates = self._build_templates()

    def _build_templates(self) -> Dict:
        """Build comprehensive templates for all data types."""
        return {
            # === VULNERABILITIES ===
            'vulnerability': {
                'system_prompt': """You are a senior cybersecurity analyst specializing in vulnerability assessment.
Provide detailed, technical responses with actionable information. Include CVSSv3 context when relevant.""",
                'instructions': [
                    # Technical analysis
                    "Explain the technical details of {cve_id} and how it can be exploited.",
                    "What is the root cause of the {cve_id} vulnerability?",
                    "Describe the attack vector and exploitation method for {cve_id}.",
                    # Impact assessment
                    "What systems and software are affected by {cve_id}?",
                    "Assess the potential business impact of {cve_id} exploitation.",
                    "What is the severity rating and risk level of {cve_id}?",
                    # Mitigation
                    "What are the recommended patches and mitigations for {cve_id}?",
                    "How can organizations detect if they've been compromised by {cve_id}?",
                    "What compensating controls can be applied if patching {cve_id} is not immediately possible?",
                    # Comparison
                    "How does {cve_id} compare to similar vulnerabilities in the same software?",
                ]
            },

            # === ATTACK PATTERNS (MITRE ATT&CK Techniques) ===
            'attack_pattern': {
                'system_prompt': """You are a threat intelligence analyst with expertise in MITRE ATT&CK framework.
Explain attack techniques with practical examples and detection strategies.""",
                'instructions': [
                    # Methodology
                    "Explain how the '{attack_name}' technique works step by step.",
                    "What tools and methods do attackers use to execute '{attack_name}'?",
                    "Describe the prerequisites and conditions needed for '{attack_name}' to succeed.",
                    # Detection
                    "What indicators of compromise (IOCs) are associated with '{attack_name}'?",
                    "How can security teams detect '{attack_name}' using SIEM or EDR?",
                    "What log sources should be monitored to identify '{attack_name}'?",
                    # Defense
                    "What defensive measures can prevent '{attack_name}'?",
                    "How should incident responders handle a '{attack_name}' attack?",
                    # Context
                    "Which threat actors are known to use '{attack_name}'?",
                    "What is the typical kill chain position of '{attack_name}'?",
                ]
            },

            # === MALWARE ===
            'malware': {
                'system_prompt': """You are a malware analyst with reverse engineering expertise.
Provide technical analysis of malware behavior, capabilities, and indicators.""",
                'instructions': [
                    # Behavior
                    "Describe the behavior and capabilities of the '{malware_name}' malware.",
                    "What persistence mechanisms does '{malware_name}' use?",
                    "How does '{malware_name}' communicate with its command and control infrastructure?",
                    # Technical
                    "What are the technical indicators of compromise (IOCs) for '{malware_name}'?",
                    "Explain the infection chain and delivery methods of '{malware_name}'.",
                    "What evasion techniques does '{malware_name}' employ?",
                    # Attribution
                    "Which threat actors are associated with '{malware_name}'?",
                    "What campaigns have used '{malware_name}'?",
                    # Defense
                    "How can organizations detect and remove '{malware_name}'?",
                    "What YARA rules or signatures can identify '{malware_name}'?",
                ]
            },

            # === INTRUSION SETS (Threat Actors/APT Groups) ===
            'intrusion_set': {
                'system_prompt': """You are a threat intelligence analyst specializing in APT group tracking.
Provide detailed profiles of threat actors including TTPs, targets, and attribution.""",
                'instructions': [
                    # Profile
                    "Provide a comprehensive profile of the '{group_name}' threat actor.",
                    "What are the known aliases and naming conventions for '{group_name}'?",
                    "What is the suspected origin and motivation of '{group_name}'?",
                    # TTPs
                    "What are the primary tactics, techniques, and procedures (TTPs) used by '{group_name}'?",
                    "What malware and tools are associated with '{group_name}'?",
                    "Describe the typical attack lifecycle of '{group_name}' operations.",
                    # Targeting
                    "What industries and regions does '{group_name}' typically target?",
                    "What are notable campaigns attributed to '{group_name}'?",
                    # Defense
                    "How can organizations defend against '{group_name}' attacks?",
                    "What threat intelligence indicators should be monitored for '{group_name}' activity?",
                ]
            },

            # === CAMPAIGNS ===
            'campaign': {
                'system_prompt': """You are a threat intelligence analyst tracking cyber campaigns.
Analyze campaign objectives, methods, and impact with timeline context.""",
                'instructions': [
                    # Overview
                    "Describe the '{campaign_name}' cyber campaign and its objectives.",
                    "What was the timeline and duration of the '{campaign_name}' campaign?",
                    "Who were the primary targets of '{campaign_name}'?",
                    # Methods
                    "What attack techniques were used in '{campaign_name}'?",
                    "What vulnerabilities were exploited during '{campaign_name}'?",
                    "Describe the initial access vectors used in '{campaign_name}'.",
                    # Impact
                    "What was the impact and damage caused by '{campaign_name}'?",
                    "What data or assets were compromised in '{campaign_name}'?",
                    # Attribution
                    "Which threat actors are attributed to '{campaign_name}'?",
                    "What lessons can be learned from '{campaign_name}' for future defense?",
                ]
            },

            # === TOOLS ===
            'tool': {
                'system_prompt': """You are a security tools expert with knowledge of both offensive and defensive tools.
Explain tool capabilities, use cases, and security implications.""",
                'instructions': [
                    # Functionality
                    "What is '{tool_name}' and what are its primary capabilities?",
                    "How is '{tool_name}' used in security operations or attacks?",
                    "What are the key features and functions of '{tool_name}'?",
                    # Usage
                    "Provide examples of '{tool_name}' usage in real-world scenarios.",
                    "What platforms and environments does '{tool_name}' support?",
                    # Security
                    "How can '{tool_name}' be detected when used maliciously?",
                    "What are the defensive countermeasures against '{tool_name}'?",
                    # Comparison
                    "How does '{tool_name}' compare to similar tools in its category?",
                ]
            },

            # === COURSE OF ACTION (Mitigations) ===
            'course_of_action': {
                'system_prompt': """You are a cybersecurity architect specializing in security controls and mitigations.
Provide practical, implementable security recommendations.""",
                'instructions': [
                    # Implementation
                    "Explain how to implement the '{mitigation_name}' security control.",
                    "What are the prerequisites for deploying '{mitigation_name}'?",
                    "Describe the step-by-step process to configure '{mitigation_name}'.",
                    # Effectiveness
                    "What threats and attack techniques does '{mitigation_name}' address?",
                    "How effective is '{mitigation_name}' against modern attacks?",
                    # Considerations
                    "What are the potential impacts and trade-offs of implementing '{mitigation_name}'?",
                    "How should '{mitigation_name}' be monitored and maintained?",
                ]
            },

            # === SECURITY ADVISORIES ===
            'security_advisory': {
                'system_prompt': """You are a security operations analyst responsible for advisory response.
Provide clear, actionable guidance for security advisories.""",
                'instructions': [
                    # Summary
                    "Summarize the security advisory {advisory_id} and its key findings.",
                    "What vulnerabilities or threats are addressed in {advisory_id}?",
                    # Actions
                    "What immediate actions should organizations take for {advisory_id}?",
                    "What is the recommended patching timeline for {advisory_id}?",
                    # Impact
                    "What systems and versions are affected by {advisory_id}?",
                    "What is the risk level if {advisory_id} recommendations are not followed?",
                ]
            },

            # === THREAT INTELLIGENCE (IOCs, Pulses) ===
            'threat_intel': {
                'system_prompt': """You are a threat intelligence analyst processing IOC feeds and threat data.
Contextualize threat intelligence with actionable analysis.""",
                'instructions': [
                    # Analysis
                    "Analyze this threat intelligence and explain its significance.",
                    "What type of threat activity does this intelligence indicate?",
                    "How should this threat intelligence be prioritized?",
                    # Action
                    "What defensive actions should be taken based on this intelligence?",
                    "How can this intelligence be operationalized in security tools?",
                    # Context
                    "What threat actors or campaigns might this intelligence relate to?",
                ]
            },

            # === CTF/CHALLENGES ===
            'ctf': {
                'system_prompt': """You are a CTF player and security educator.
Explain security concepts through practical challenge scenarios.""",
                'instructions': [
                    "Describe this CTF challenge and the skills it tests.",
                    "What security concepts are demonstrated in this challenge?",
                    "How would you approach solving this type of security challenge?",
                    "What learning objectives does this challenge address?",
                ]
            },

            # === RESEARCH PAPERS ===
            'research': {
                'system_prompt': """You are a security researcher analyzing academic publications.
Summarize research findings and their practical implications.""",
                'instructions': [
                    "Summarize the key findings of this cybersecurity research.",
                    "What novel attack or defense techniques are presented?",
                    "What are the practical implications of this research for security practitioners?",
                    "How does this research advance the field of cybersecurity?",
                ]
            },

            # === CAPEC ATTACK PATTERNS ===
            'capec_pattern': {
                'system_prompt': """You are a security architect with expertise in attack pattern analysis.
Explain attack patterns with focus on prevention and detection.""",
                'instructions': [
                    "Explain the '{pattern_name}' attack pattern (CAPEC-{pattern_id}).",
                    "What weaknesses (CWEs) are exploited by CAPEC-{pattern_id}?",
                    "How can developers prevent CAPEC-{pattern_id} in their applications?",
                    "What are the detection methods for CAPEC-{pattern_id}?",
                    "Describe the typical severity and likelihood of CAPEC-{pattern_id}.",
                ]
            },

            # === SECURITY CONTROLS (NIST 800-53, CIS Controls) ===
            'security_control': {
                'system_prompt': """You are a security compliance expert specializing in NIST and CIS frameworks.
Explain security controls with implementation guidance and audit considerations.""",
                'instructions': [
                    "Explain the security control '{identifier}' and its purpose.",
                    "How should organizations implement '{identifier}' in their environment?",
                    "What are the key requirements and assessment criteria for '{identifier}'?",
                    "What evidence should be collected to demonstrate compliance with '{identifier}'?",
                    "How does '{identifier}' map to common threats and attack techniques?",
                ]
            },

            # === SECURITY FRAMEWORKS (NIST CSF) ===
            'security_framework': {
                'system_prompt': """You are a cybersecurity framework expert specializing in NIST CSF.
Explain framework functions, categories, and implementation tiers.""",
                'instructions': [
                    "Explain the '{identifier}' function/category in the NIST Cybersecurity Framework.",
                    "What activities and outcomes are expected under '{identifier}'?",
                    "How should organizations assess their maturity level for '{identifier}'?",
                    "What implementation examples demonstrate '{identifier}' in practice?",
                ]
            },

            # === SECURE DEVELOPMENT (NIST SSDF) ===
            'secure_development': {
                'system_prompt': """You are a secure software development expert specializing in SDLC security.
Explain secure development practices with practical implementation guidance.""",
                'instructions': [
                    "Explain the secure development practice '{identifier}' and its importance.",
                    "What specific tasks are required to implement '{identifier}'?",
                    "How does '{identifier}' reduce security vulnerabilities in software?",
                    "What tools and processes support the implementation of '{identifier}'?",
                ]
            },

            # === ICS/OT SECURITY (MITRE ATT&CK for ICS) ===
            'ics_ot_security': {
                'system_prompt': """You are an ICS/OT security expert specializing in industrial control systems.
Explain threats to operational technology with detection and mitigation strategies.""",
                'instructions': [
                    "Explain the ICS attack technique '{identifier}' and how it targets industrial systems.",
                    "What industrial protocols or systems are vulnerable to '{identifier}'?",
                    "How can organizations detect '{identifier}' in OT environments?",
                    "What mitigations protect against '{identifier}' in industrial networks?",
                ]
            },

            # === CONTROL MAPPING (NIST to ATT&CK) ===
            'control_mapping': {
                'system_prompt': """You are a security architect specializing in control frameworks and threat mapping.
Explain how security controls map to attack techniques and provide coverage analysis.""",
                'instructions': [
                    "How does the security control map to the specified ATT&CK technique?",
                    "What coverage does this control provide against the attack technique?",
                    "What gaps exist in this control-to-attack mapping?",
                    "How should organizations prioritize this control for threat mitigation?",
                ]
            },

            # === BEST PRACTICES (OWASP Cheat Sheets) ===
            'best_practice': {
                'system_prompt': """You are a security best practices expert specializing in secure development and operations.
Explain security best practices with actionable implementation guidance.""",
                'instructions': [
                    "Explain the security best practice '{identifier}' and when to apply it.",
                    "What are the key implementation steps for '{identifier}'?",
                    "What common mistakes should be avoided when implementing '{identifier}'?",
                    "How can organizations verify correct implementation of '{identifier}'?",
                ]
            },

            # === LOLBAS (Living Off The Land Binaries And Scripts) ===
            'lolbas': {
                'system_prompt': """You are a red team operator and Windows security expert.
Explain LOLBin techniques for post-exploitation, detection methods, and defensive countermeasures.""",
                'instructions': [
                    # Offensive use
                    "How can '{binary_name}' be abused for post-exploitation on Windows?",
                    "What are the specific commands to use '{binary_name}' for {use_case}?",
                    "Describe the MITRE ATT&CK technique ({mitre_id}) associated with '{binary_name}'.",
                    # Detection
                    "How can defenders detect malicious use of '{binary_name}'?",
                    "What Sigma rules or detection signatures exist for '{binary_name}' abuse?",
                    "What event logs should be monitored for '{binary_name}' exploitation?",
                    # Defense
                    "What application whitelisting rules can prevent '{binary_name}' abuse?",
                    "How can AppLocker or WDAC policies block '{binary_name}' misuse?",
                ]
            },

            # === LOLDRIVERS (Vulnerable/Malicious Drivers) ===
            'loldriver': {
                'system_prompt': """You are a Windows kernel security expert specializing in driver vulnerabilities.
Explain driver exploitation, BYOVD attacks, and kernel-level defense strategies.""",
                'instructions': [
                    # Technical analysis
                    "Explain the security risks of the '{driver_name}' driver.",
                    "What vulnerabilities or capabilities make '{driver_name}' exploitable?",
                    "How can attackers use '{driver_name}' to escalate privileges or disable security?",
                    # BYOVD context
                    "Describe how '{driver_name}' can be used in a BYOVD (Bring Your Own Vulnerable Driver) attack.",
                    "What kernel capabilities does '{driver_name}' expose to attackers?",
                    # Detection
                    "How can security teams detect loading of '{driver_name}'?",
                    "What hash-based or certificate-based blocking can prevent '{driver_name}' loading?",
                    # Defense
                    "How can HVCI (Hypervisor-protected Code Integrity) protect against '{driver_name}'?",
                    "What driver blocklist policies should include '{driver_name}'?",
                ]
            },

            # === HIJACKLIBS (DLL Hijacking) ===
            'hijacklib': {
                'system_prompt': """You are a Windows security researcher specializing in DLL hijacking and binary planting.
Explain DLL hijacking techniques, vulnerable applications, and mitigation strategies.""",
                'instructions': [
                    # Attack mechanics
                    "How can the '{dll_name}' DLL be used for DLL hijacking attacks?",
                    "What applications are vulnerable to '{dll_name}' hijacking?",
                    "Describe the DLL search order exploitation for '{dll_name}'.",
                    # Technique types
                    "What type of DLL hijacking ({hijack_type}) applies to '{dll_name}'?",
                    "How does sideloading work with '{dll_name}' and the vulnerable executable?",
                    # Detection
                    "How can defenders detect '{dll_name}' DLL hijacking attempts?",
                    "What file integrity monitoring can identify '{dll_name}' planting?",
                    # Mitigation
                    "How can developers prevent DLL hijacking in applications loading '{dll_name}'?",
                    "What secure DLL loading practices should be implemented?",
                ]
            },

            # === OSINT TOOLS/RESOURCES ===
            'osint_tool': {
                'system_prompt': """You are an OSINT analyst and investigator with expertise in open-source intelligence gathering.
Explain OSINT tools, methodologies, and ethical considerations for intelligence collection.""",
                'instructions': [
                    # Tool usage
                    "What is '{tool_name}' and how is it used for OSINT investigations?",
                    "What type of intelligence can be gathered using '{tool_name}'?",
                    "Describe the methodology for using '{tool_name}' in an investigation.",
                    # Capabilities
                    "What data sources does '{tool_name}' access for intelligence gathering?",
                    "How does '{tool_name}' compare to similar OSINT tools in its category?",
                    # Ethics and OPSEC
                    "What are the legal and ethical considerations when using '{tool_name}'?",
                    "How can investigators maintain OPSEC while using '{tool_name}'?",
                    # Practical application
                    "Provide a practical example of using '{tool_name}' for threat intelligence.",
                ]
            },
        }

    def _build_reasoning_schemas(self) -> Dict:
        """Build reasoning schemas optimized for each data type.

        Design principles:
        - All multi-value fields are LISTS for consistency
        - mitigation_priority included where applicable (HIGH/MEDIUM/LOW)
        - Structured for dense, technical output (no filler)
        """
        return {
            'vulnerability': {
                "key_fields_analyzed": ["field1", "field2"],
                "vulnerability_details": {
                    "cve_id": "CVE-YYYY-NNNNN",
                    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
                    "cvss_score": 0.0,
                    "attack_vector": "NETWORK/LOCAL/PHYSICAL/ADJACENT",
                    "cwe_ids": ["CWE-XX"]
                },
                "affected_systems": ["product1 version", "product2 version"],
                "exploit_status": "active/poc_available/theoretical/none",
                "risk_assessment": "business impact summary",
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'threat_intel': {
                "key_fields_analyzed": ["field1", "field2"],
                "threat_classification": {
                    "threat_type": "malware/phishing/c2/apt/ransomware",
                    "malware_families": ["family1", "family2"],
                    "threat_actors": ["APT group or unknown"]
                },
                "extracted_indicators": {
                    "iocs": ["indicator1", "indicator2"],
                    "ioc_types": ["ip", "domain", "hash", "url"]
                },
                "kill_chain_phase": "reconnaissance/weaponization/delivery/exploitation/installation/c2/actions",
                "confidence_level": "HIGH/MEDIUM/LOW",
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'attack_pattern': {
                "key_fields_analyzed": ["field1", "field2"],
                "technique_details": {
                    "technique_id": "T1234 or CAPEC-XXX",
                    "technique_name": "name",
                    "tactics": ["tactic1", "tactic2"],
                    "platforms": ["Windows", "Linux", "macOS", "Cloud"]
                },
                "prerequisites": ["condition1", "condition2"],
                "detection_methods": ["method1", "method2"],
                "defensive_controls": ["control1", "control2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'malware': {
                "key_fields_analyzed": ["field1", "field2"],
                "malware_profile": {
                    "family": "malware family name",
                    "type": "ransomware/RAT/stealer/botnet/wiper/loader",
                    "file_hashes": ["sha256", "md5"]
                },
                "capabilities": ["capability1", "capability2"],
                "associated_actors": ["actor1", "actor2"],
                "detection_signatures": ["signature1", "signature2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'intrusion_set': {
                "key_fields_analyzed": ["field1", "field2"],
                "actor_profile": {
                    "name": "threat group name",
                    "aliases": ["alias1", "alias2"],
                    "origin": "attributed country/region",
                    "motivation": "financial/espionage/hacktivism/destruction"
                },
                "ttps": ["technique1", "technique2"],
                "target_sectors": ["sector1", "sector2"],
                "target_regions": ["region1", "region2"],
                "attribution_confidence": "HIGH/MEDIUM/LOW"
            },
            'campaign': {
                "key_fields_analyzed": ["field1", "field2"],
                "campaign_profile": {
                    "name": "campaign name",
                    "timeframe": "YYYY-MM to YYYY-MM",
                    "attributed_to": "threat actor or unknown"
                },
                "objectives": ["objective1", "objective2"],
                "target_sectors": ["sector1", "sector2"],
                "techniques_used": ["T1234", "T5678"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'security_advisory': {
                "key_fields_analyzed": ["field1", "field2"],
                "advisory_details": {
                    "advisory_id": "identifier",
                    "title": "advisory title",
                    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
                    "vendor": "affected vendor"
                },
                "affected_products": ["product1 version", "product2 version"],
                "patches_available": ["patch1", "patch2"],
                "workarounds": ["workaround1", "workaround2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'tool': {
                "key_fields_analyzed": ["field1", "field2"],
                "tool_profile": {
                    "name": "tool name",
                    "type": "legitimate/dual-use/malicious",
                    "purposes": ["purpose1", "purpose2"]
                },
                "malicious_uses": ["abuse1", "abuse2"],
                "detection_methods": ["method1", "method2"],
                "legitimate_alternatives": ["alt1", "alt2"]
            },
            'course_of_action': {
                "key_fields_analyzed": ["field1", "field2"],
                "mitigation_details": {
                    "name": "mitigation name",
                    "type": "preventive/detective/corrective",
                    "nist_functions": ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
                },
                "implementation_steps": ["step1", "step2"],
                "effectiveness": "HIGH/MEDIUM/LOW",
                "dependencies": ["dependency1", "dependency2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'capec_pattern': {
                "key_fields_analyzed": ["field1", "field2"],
                "pattern_details": {
                    "capec_id": "CAPEC-XXX",
                    "name": "attack pattern name",
                    "severity": "HIGH/MEDIUM/LOW",
                    "likelihood": "HIGH/MEDIUM/LOW"
                },
                "related_cwes": ["CWE-XX", "CWE-YY"],
                "prerequisites": ["condition1", "condition2"],
                "mitigations": ["mitigation1", "mitigation2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'security_control': {
                "key_fields_analyzed": ["field1", "field2"],
                "control_details": {
                    "control_id": "AC-1, SC-7, etc",
                    "title": "control title",
                    "family": "control family",
                    "baseline": ["LOW", "MODERATE", "HIGH"]
                },
                "implementation_guidance": ["step1", "step2"],
                "related_controls": ["control1", "control2"],
                "assessment_methods": ["method1", "method2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'security_framework': {
                "key_fields_analyzed": ["field1", "field2"],
                "framework_element": {
                    "element_id": "identifier",
                    "title": "element title",
                    "function": "GOVERN/IDENTIFY/PROTECT/DETECT/RESPOND/RECOVER",
                    "category": "category name"
                },
                "implementation_examples": ["example1", "example2"],
                "related_standards": ["standard1", "standard2"],
                "maturity_indicators": ["indicator1", "indicator2"]
            },
            'secure_development': {
                "key_fields_analyzed": ["field1", "field2"],
                "practice_details": {
                    "practice_id": "PO.1, PS.1, etc",
                    "title": "practice title",
                    "group": "Prepare/Protect/Produce/Respond"
                },
                "tasks": ["task1", "task2"],
                "implementation_guidance": ["step1", "step2"],
                "verification_methods": ["method1", "method2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'ics_ot_security': {
                "key_fields_analyzed": ["field1", "field2"],
                "ics_context": {
                    "technique_id": "T0XXX",
                    "technique_name": "name",
                    "asset_types": ["PLC", "HMI", "SCADA", "DCS", "RTU"],
                    "protocols_affected": ["Modbus", "DNP3", "OPC", "Profinet"]
                },
                "safety_impact": "impact on physical safety",
                "detection_methods": ["method1", "method2"],
                "ics_specific_mitigations": ["mitigation1", "mitigation2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'control_mapping': {
                "key_fields_analyzed": ["field1", "field2"],
                "mapping_details": {
                    "source_control": "NIST 800-53 control ID",
                    "target_technique": "ATT&CK technique ID",
                    "mapping_type": "mitigates/detects"
                },
                "coverage_analysis": "how well the control addresses the technique",
                "implementation_notes": ["note1", "note2"],
                "gaps_identified": ["gap1", "gap2"]
            },
            'research': {
                "key_fields_analyzed": ["field1", "field2"],
                "research_focus": {
                    "topic": "main subject",
                    "methodology": "approach used",
                    "key_findings": ["finding1", "finding2"]
                },
                "practical_applications": ["application1", "application2"],
                "skill_domains": ["domain1", "domain2"]
            },
            'ctf_challenge': {
                "key_fields_analyzed": ["field1", "field2"],
                "challenge_profile": {
                    "name": "CTF name",
                    "format": "jeopardy/attack-defense/king-of-the-hill",
                    "categories": ["pwn", "web", "crypto", "reverse", "forensics"]
                },
                "skills_tested": ["skill1", "skill2"],
                "learning_objectives": ["objective1", "objective2"]
            },
            'best_practice': {
                "key_fields_analyzed": ["field1", "field2"],
                "practice_details": {
                    "title": "practice title",
                    "category": "authentication/authorization/input_validation/etc",
                    "applicable_contexts": ["web", "api", "mobile", "infrastructure"]
                },
                "implementation_steps": ["step1", "step2"],
                "common_mistakes": ["mistake1", "mistake2"],
                "verification_methods": ["method1", "method2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'lolbas': {
                "key_fields_analyzed": ["field1", "field2"],
                "binary_details": {
                    "name": "binary name",
                    "path": "full path to binary",
                    "mitre_ids": ["T1218", "T1105"],
                    "categories": ["Execute", "Download", "AWL Bypass"]
                },
                "abuse_techniques": ["technique1", "technique2"],
                "detection_methods": ["Sigma rule", "event log", "EDR"],
                "defensive_controls": ["AppLocker", "WDAC", "audit"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'loldriver': {
                "key_fields_analyzed": ["field1", "field2"],
                "driver_details": {
                    "name": "driver name",
                    "category": "vulnerable driver/malicious",
                    "mitre_id": "T1068",
                    "hashes": ["SHA256", "MD5"]
                },
                "exploitation_capabilities": ["privilege escalation", "kill AV", "read/write memory"],
                "byovd_risk": "HIGH/MEDIUM/LOW",
                "detection_methods": ["driver load monitoring", "hash blocklist"],
                "defensive_controls": ["HVCI", "driver blocklist", "code integrity"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'hijacklib': {
                "key_fields_analyzed": ["field1", "field2"],
                "dll_details": {
                    "name": "DLL name",
                    "hijack_type": "Sideloading/Phantom/Search Order/Environment Variable",
                    "vendor": "affected vendor",
                    "cve": "CVE if applicable"
                },
                "vulnerable_executables": ["exe1", "exe2"],
                "attack_prerequisites": ["prerequisite1", "prerequisite2"],
                "detection_methods": ["file integrity", "Sysmon", "EDR"],
                "secure_coding_fixes": ["fix1", "fix2"],
                "mitigation_priority": "HIGH/MEDIUM/LOW"
            },
            'osint_tool': {
                "key_fields_analyzed": ["field1", "field2"],
                "tool_details": {
                    "name": "tool name",
                    "category": "Username/Email/Domain/IP/Social/etc",
                    "tool_type": "url/local_tool/google_dork"
                },
                "intelligence_types": ["PII", "infrastructure", "social", "financial"],
                "data_sources": ["source1", "source2"],
                "ethical_considerations": ["consideration1", "consideration2"],
                "opsec_notes": ["note1", "note2"]
            },
        }

    def get_reasoning_schema(self, entry_type: str) -> Dict:
        """Get the appropriate reasoning schema for an entry type."""
        schemas = self._build_reasoning_schemas()
        # Map entry types to schema types
        type_mapping = {
            'vulnerability': 'vulnerability',
            'threat_intel': 'threat_intel',
            'attack_pattern': 'attack_pattern',
            'malware': 'malware',
            'intrusion_set': 'intrusion_set',
            'campaign': 'campaign',
            'security_advisory': 'security_advisory',
            'tool': 'tool',
            'course_of_action': 'course_of_action',
            'capec_pattern': 'capec_pattern',
            'research': 'research',
            'ctf_challenge': 'ctf_challenge',
            'ctf': 'ctf_challenge',
            # New NIST/CIS/OWASP types
            'security_control': 'security_control',
            'security_framework': 'security_framework',
            'secure_development': 'secure_development',
            'ics_ot_security': 'ics_ot_security',
            'control_mapping': 'control_mapping',
            'best_practice': 'best_practice',
            # Aliases
            'ioc': 'threat_intel',
            'indicator': 'threat_intel',
            'nist_control': 'security_control',
            'cis_control': 'security_control',
            'csf_function': 'security_framework',
            'ssdf_practice': 'secure_development',
            'owasp_cheatsheet': 'best_practice',
            'ics_technique': 'ics_ot_security',
            'nist_attack_mapping': 'control_mapping',
            # Offensive/Pentest types
            'lolbas': 'lolbas',
            'loldriver': 'loldriver',
            'hijacklib': 'hijacklib',
            'osint_tool': 'osint_tool',
        }
        schema_key = type_mapping.get(entry_type, 'security_control')  # Default to security_control for frameworks
        return schemas.get(schema_key, schemas['threat_intel'])

    def detect_entry_type(self, entry: Dict, source_file: str = "") -> Optional[str]:
        """Detect the type of cybersecurity data entry with extended STIX support."""
        entry_str = str(entry).lower()
        source_lower = source_file.lower()

        # STIX type detection (MITRE ATT&CK format)
        if 'type' in entry:
            stix_type = entry.get('type', '').lower()
            type_mapping = {
                'attack-pattern': 'attack_pattern',
                'malware': 'malware',
                'intrusion-set': 'intrusion_set',
                'campaign': 'campaign',
                'tool': 'tool',
                'course-of-action': 'course_of_action',
                'indicator': 'threat_intel',
                'threat-actor': 'intrusion_set',
                # Extended STIX types for MITRE ATT&CK
                'x-mitre-tactic': 'attack_pattern',  # Tactics are part of ATT&CK framework
                'x-mitre-matrix': 'attack_pattern',  # Matrix definitions
                'x-mitre-data-source': 'attack_pattern',  # Data sources for detection
                'x-mitre-data-component': 'attack_pattern',  # Data components
                'x-mitre-analytic': 'attack_pattern',  # Detection analytics
                'x-mitre-detection-strategy': 'attack_pattern',  # Detection strategies
                'identity': None,  # Skip identity objects
                'marking-definition': None,  # Skip marking definitions
                'relationship': None,  # Skip relationship objects (processed separately)
            }
            if stix_type in type_mapping:
                result = type_mapping[stix_type]
                if result is None:
                    return None  # Skip this entry type
                return result

        # NIST/CIS/OWASP/Framework detection (check these first for new sources)
        # NIST SP 800-53 controls
        if 'nist_standards' in source_lower or 'nist_sp800_53' in source_lower:
            return 'security_control'
        if 'family_id' in entry and 'statement' in entry:
            return 'security_control'

        # NIST CSF 2.0
        if 'nist_csf' in source_lower:
            return 'security_framework'
        if 'categories' in entry and any(f in str(entry) for f in ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER']):
            return 'security_framework'

        # NIST SP 800-171
        if 'nist_sp800_171' in source_lower or 'sp800-171' in source_lower:
            return 'security_control'
        if 'requirement' in entry and 'family_title' in entry:
            return 'security_control'

        # NIST SSDF (Secure Software Development Framework)
        if 'nist_ssdf' in source_lower or 'ssdf' in source_lower:
            return 'secure_development'
        if 'practice_groups' in entry or ('tasks' in entry and 'practice' in str(entry).lower()):
            return 'secure_development'

        # CIS Controls
        if 'cis-controls' in source_lower or 'cis_controls' in source_lower:
            return 'security_control'
        if '_group_title' in entry or 'cisc-' in str(entry.get('id', '')).lower():
            return 'security_control'

        # MITRE ATT&CK for ICS
        if 'mitre_attack_ics' in source_lower or 'ics-attack' in source_lower:
            return 'ics_ot_security'
        if 'x_mitre_platforms' in entry and any(p in str(entry.get('x_mitre_platforms', [])) for p in ['Control Server', 'Field Controller', 'Safety Instrumented System']):
            return 'ics_ot_security'

        # NIST to ATT&CK mapping
        if 'nist_attack_mapping' in source_lower or 'mapping_objects' in source_lower:
            return 'control_mapping'
        if 'capability_id' in entry and 'attack_object_id' in entry:
            return 'control_mapping'

        # OWASP Cheat Sheets
        if 'security_testing' in source_lower or 'owasp' in source_lower or 'cheatsheet' in source_lower:
            return 'best_practice'
        if 'cheatsheets.owasp.org' in str(entry.get('url', '')):
            return 'best_practice'

        # === OFFENSIVE/PENTEST SOURCES ===
        # LOLBAS (Living Off The Land Binaries And Scripts)
        if 'lolbas' in source_lower:
            return 'lolbas'
        if 'Commands' in entry and 'Full_Path' in entry:
            return 'lolbas'

        # LOLDrivers (Vulnerable/Malicious Drivers)
        if 'loldriver' in source_lower:
            return 'loldriver'
        if 'KnownVulnerableSamples' in entry or ('Category' in entry and 'driver' in str(entry.get('Category', '')).lower()):
            return 'loldriver'

        # HijackLibs (DLL Hijacking)
        if 'hijacklib' in source_lower:
            return 'hijacklib'
        if 'VulnerableExecutables' in entry or 'ExpectedLocations' in entry:
            return 'hijacklib'

        # OSINT Framework
        if 'osint_framework' in source_lower or 'osint' in source_lower:
            return 'osint_tool'
        if entry.get('type') == 'url' and 'children' not in entry:
            # Leaf node in OSINT framework tree = actual tool
            return 'osint_tool'

        # CAPEC detection
        if 'capec' in source_lower or ('id' in entry and 'Attack_Pattern' in str(entry.get('id', ''))):
            return 'capec_pattern'
        if entry.get('related_cwe') or entry.get('likelihood'):
            return 'capec_pattern'

        # CVE/Vulnerability detection
        if 'cve-' in entry_str or any(key.lower().startswith('cve') for key in entry.keys()):
            return 'vulnerability'

        # Threat intelligence feeds
        if 'pulse' in source_lower or 'otx' in source_lower:
            return 'threat_intel'
        if 'ioc' in source_lower or 'threatfox' in source_lower:
            return 'threat_intel'

        # CTF detection
        if 'ctf' in source_lower or 'ctftime' in source_lower:
            return 'ctf'

        # Research papers
        if 'arxiv' in source_lower or 'paper' in source_lower:
            return 'research'

        # Security advisories
        if any(key in entry for key in {'advisory', 'bulletin', 'notice', 'alert', 'usn'}):
            return 'security_advisory'
        if 'advisory' in entry_str or 'bulletin' in entry_str or 'security notice' in entry_str:
            return 'security_advisory'
        # Microsoft Security Updates
        if 'microsoft' in source_lower or 'msrc' in source_lower:
            return 'security_advisory'
        if any(key in entry for key in {'DocumentTitle', 'CvrfUrl', 'CurrentReleaseDate'}):
            return 'security_advisory'

        # Malware samples
        if 'malware' in source_lower or 'bazaar' in source_lower:
            return 'malware'

        # Fallback attack pattern detection
        if any(key in entry for key in {'attack_pattern', 'technique', 'tactic', 'mitre'}):
            return 'attack_pattern'
        if 'attack' in entry_str and ('technique' in entry_str or 'method' in entry_str):
            return 'attack_pattern'

        return None

    def extract_fields(self, entry: Dict, entry_type: str) -> Dict:
        """Extract relevant fields based on entry type with enhanced STIX support."""
        fields = {}
        entry_str = json.dumps(entry, default=str)

        # Common field extraction
        name = entry.get('name', entry.get('title', entry.get('Name', '')))

        if entry_type == 'vulnerability':
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cve_matches = re.findall(cve_pattern, entry_str, re.IGNORECASE)
            fields['cve_id'] = cve_matches[0] if cve_matches else "Unknown CVE"
            fields['identifier'] = fields['cve_id']

        elif entry_type == 'attack_pattern':
            fields['attack_name'] = name or "Unknown Technique"
            # Extract MITRE ID if present
            mitre_id = entry.get('external_references', [{}])
            if isinstance(mitre_id, list):
                for ref in mitre_id:
                    if isinstance(ref, dict) and ref.get('source_name') == 'mitre-attack':
                        fields['mitre_id'] = ref.get('external_id', '')
                        break
            fields['identifier'] = fields.get('mitre_id', fields['attack_name'])

        elif entry_type == 'malware':
            # For MalwareBazaar data: signature contains malware family name
            malware_name = name
            if not malware_name:
                malware_name = entry.get('signature')  # MalwareBazaar field
            if not malware_name:
                # Try to extract from tags (e.g., "dropped-by-Amadey" -> "Amadey")
                tags = entry.get('tags', [])
                if isinstance(tags, list):
                    for tag in tags:
                        if isinstance(tag, str) and 'dropped-by-' in tag.lower():
                            malware_name = tag.split('-')[-1]
                            break
                        elif isinstance(tag, str) and tag not in {'exe', 'dll', 'msi', 'sh', 'elf', 'apk', 'jar', 'doc', 'xls', 'pdf'}:
                            # Use non-file-type tag as potential malware name
                            malware_name = tag
                            break
            if not malware_name:
                # Use file_type + sha256 prefix as identifier
                file_type = entry.get('file_type', 'unknown')
                sha256 = entry.get('sha256_hash', '')[:12]
                malware_name = f"{file_type.upper()} Sample ({sha256})" if sha256 else "Unknown Malware"

            fields['malware_name'] = malware_name
            # Extract malware type from file_type or malware_types
            malware_type = ', '.join(entry.get('malware_types', [])) if entry.get('malware_types') else ''
            if not malware_type:
                malware_type = entry.get('file_type', '')
            fields['malware_type'] = malware_type
            fields['identifier'] = fields['malware_name']

        elif entry_type == 'intrusion_set':
            fields['group_name'] = name or "Unknown Group"
            aliases = entry.get('aliases', [])
            fields['aliases'] = ', '.join(aliases) if aliases else ''
            fields['identifier'] = fields['group_name']

        elif entry_type == 'campaign':
            fields['campaign_name'] = name or "Unknown Campaign"
            fields['identifier'] = fields['campaign_name']

        elif entry_type == 'tool':
            fields['tool_name'] = name or "Unknown Tool"
            fields['identifier'] = fields['tool_name']

        elif entry_type == 'course_of_action':
            fields['mitigation_name'] = name or "Unknown Mitigation"
            fields['identifier'] = fields['mitigation_name']

        elif entry_type == 'security_advisory':
            # Support various advisory formats (Ubuntu USN, RedHat, Microsoft, etc.)
            advisory_id = entry.get('id', entry.get('ID', entry.get('advisory_id', entry.get('cve_id', ''))))
            advisory_title = entry.get('title', entry.get('DocumentTitle', entry.get('name', '')))
            fields['advisory_id'] = advisory_id or "Unknown Advisory"
            fields['advisory_title'] = advisory_title or fields['advisory_id']
            fields['identifier'] = fields['advisory_title'] if fields['advisory_title'] != fields['advisory_id'] else fields['advisory_id']

        elif entry_type == 'threat_intel':
            fields['intel_name'] = name or entry.get('pulse_info', {}).get('name', 'Threat Intelligence')
            fields['identifier'] = fields['intel_name']

        elif entry_type == 'ctf':
            fields['event_name'] = name or entry.get('title', 'CTF Event')
            fields['identifier'] = fields['event_name']

        elif entry_type == 'research':
            fields['paper_title'] = name or entry.get('title', 'Research Paper')
            fields['identifier'] = fields['paper_title']

        elif entry_type == 'capec_pattern':
            fields['pattern_name'] = name or entry.get('name', 'Unknown Pattern')
            fields['pattern_id'] = entry.get('id', 'Unknown')
            fields['severity'] = entry.get('severity', 'Unknown')
            fields['likelihood'] = entry.get('likelihood', 'Unknown')
            fields['identifier'] = f"CAPEC-{fields['pattern_id']}"

        # === SECURITY FRAMEWORKS (NIST, CIS, OWASP) ===
        elif entry_type == 'security_control':
            # NIST 800-53, CIS Controls, NIST 800-171
            ctrl_id = entry.get('id', entry.get('control_id', entry.get('family_id', '')))
            ctrl_title = entry.get('title', entry.get('name', name or ''))
            fields['identifier'] = ctrl_id or ctrl_title or 'Unknown Control'
            fields['control_title'] = ctrl_title
            fields['control_family'] = entry.get('family', entry.get('family_title', entry.get('_group_title', '')))
            fields['statement'] = entry.get('statement', entry.get('description', ''))

        elif entry_type == 'security_framework':
            # NIST CSF 2.0
            func_id = entry.get('id', entry.get('function_id', ''))
            func_name = entry.get('name', entry.get('title', name or ''))
            fields['identifier'] = func_id or func_name or 'Unknown Function'
            fields['function_name'] = func_name
            fields['function'] = entry.get('function', '')
            fields['category'] = entry.get('category', '')

        elif entry_type == 'secure_development':
            # NIST SSDF
            practice_id = entry.get('id', entry.get('practice_id', ''))
            practice_name = entry.get('name', entry.get('title', name or ''))
            fields['identifier'] = practice_id or practice_name or 'Unknown Practice'
            fields['practice_name'] = practice_name
            fields['group'] = entry.get('group', entry.get('practice_group', ''))
            fields['tasks'] = entry.get('tasks', [])

        elif entry_type == 'ics_ot_security':
            # MITRE ATT&CK for ICS
            tech_id = entry.get('id', '')
            # Extract T-number from external_references
            ext_refs = entry.get('external_references', [])
            for ref in ext_refs:
                if isinstance(ref, dict) and ref.get('source_name') == 'mitre-ics-attack':
                    tech_id = ref.get('external_id', tech_id)
                    break
            tech_name = entry.get('name', name or 'Unknown ICS Technique')
            fields['identifier'] = tech_id or tech_name
            fields['technique_name'] = tech_name
            fields['platforms'] = entry.get('x_mitre_platforms', [])

        elif entry_type == 'control_mapping':
            # NIST to ATT&CK mapping
            cap_id = entry.get('capability_id', entry.get('source_id', ''))
            attack_id = entry.get('attack_object_id', entry.get('target_id', ''))
            fields['identifier'] = f"{cap_id} -> {attack_id}" if cap_id and attack_id else 'Unknown Mapping'
            fields['source_control'] = cap_id
            fields['target_technique'] = attack_id
            fields['mapping_type'] = entry.get('mapping_type', entry.get('relationship_type', ''))

        elif entry_type == 'best_practice':
            # OWASP Cheat Sheets and other best practices
            practice_name = entry.get('name', entry.get('title', name or 'Unknown Practice'))
            fields['identifier'] = practice_name
            fields['practice_name'] = practice_name
            fields['category'] = entry.get('category', entry.get('type', ''))
            fields['url'] = entry.get('url', '')

        # === OFFENSIVE/PENTEST SOURCES ===
        elif entry_type == 'lolbas':
            fields['binary_name'] = entry.get('Name', name or 'Unknown Binary')
            # Get first command's info
            commands = entry.get('Commands', [])
            if commands and isinstance(commands, list) and len(commands) > 0:
                first_cmd = commands[0]
                fields['use_case'] = first_cmd.get('Category', 'Execution')
                fields['mitre_id'] = first_cmd.get('MitreID', 'T1218')
            else:
                fields['use_case'] = 'Execution'
                fields['mitre_id'] = 'T1218'
            fields['identifier'] = fields['binary_name']

        elif entry_type == 'loldriver':
            # Get driver name from Tags or Id
            tags = entry.get('Tags', [])
            driver_name = tags[0] if tags else entry.get('Id', 'Unknown Driver')
            fields['driver_name'] = driver_name
            fields['category'] = entry.get('Category', 'vulnerable driver')
            fields['mitre_id'] = entry.get('MitreID', 'T1068')
            fields['identifier'] = fields['driver_name']

        elif entry_type == 'hijacklib':
            fields['dll_name'] = entry.get('Name', name or 'Unknown DLL')
            # Get hijack type from first vulnerable executable
            vuln_exes = entry.get('VulnerableExecutables', [])
            if vuln_exes and isinstance(vuln_exes, list) and len(vuln_exes) > 0:
                fields['hijack_type'] = vuln_exes[0].get('Type', 'Sideloading')
            else:
                fields['hijack_type'] = 'Sideloading'
            fields['vendor'] = entry.get('Vendor', 'Unknown')
            fields['identifier'] = fields['dll_name']

        elif entry_type == 'osint_tool':
            fields['tool_name'] = entry.get('name', name or 'OSINT Tool')
            fields['tool_url'] = entry.get('url', '')
            fields['tool_type'] = entry.get('type', 'url')
            fields['identifier'] = fields['tool_name']

        # Extract kill chain phases if present
        kill_chain = entry.get('kill_chain_phases', [])
        if kill_chain:
            phases = [p.get('phase_name', '') for p in kill_chain if isinstance(p, dict)]
            fields['kill_chain_phases'] = ', '.join(phases)

        # Extract description
        description = entry.get('description', entry.get('Description', ''))
        if isinstance(description, str):
            fields['description'] = description[:500]  # Limit description length

        # Store raw data as native JSON object for context field
        # Truncate large string values to keep reasonable size (~6000 chars equivalent)
        def truncate_entry(obj, max_str_len=1000):
            """Recursively truncate long string values in nested structures."""
            if isinstance(obj, dict):
                return {k: truncate_entry(v, max_str_len) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [truncate_entry(item, max_str_len) for item in obj[:50]]  # Max 50 items
            elif isinstance(obj, str):
                return obj[:max_str_len] if len(obj) > max_str_len else obj
            else:
                return obj

        fields['raw_data'] = truncate_entry(entry)

        return fields

    def select_instructions(self, entry_type: str, fields: Dict) -> List[str]:
        """Select diverse instructions for an entry, avoiding redundancy."""
        if entry_type not in self.templates:
            return []

        all_instructions = self.templates[entry_type]['instructions']

        # Categorize instructions by type for diversity
        # Select a mix of different question types
        selected = random.sample(
            all_instructions,
            min(self.max_instructions_per_entry, len(all_instructions))
        )

        return selected

    def _parse_llm_json_response(self, response: str) -> Optional[Dict]:
        """Parse JSON response from LLM with robust handling of various formats.

        Handles cases where the model outputs:
        1. Clean JSON: {"reasoning": {...}, "answer": "..."}
        2. JSON in code block: ```json {...} ```
        3. Stream-of-consciousness with embedded JSON (schema example + actual response)
        4. Multiple JSON objects (picks the best one with substantive 'answer' field)
        """
        if not response:
            return None

        # Method 1: Try direct JSON parse (clean response)
        try:
            parsed = json.loads(response)
            if isinstance(parsed, dict) and 'answer' in parsed:
                # Verify answer is substantive (not just a template placeholder)
                answer = parsed.get('answer', '')
                if len(answer) > 100 and 'comprehensive technical response' not in answer.lower():
                    return parsed
        except json.JSONDecodeError:
            pass

        # Method 2: Extract from ```json ... ``` code blocks
        if '```json' in response:
            try:
                json_content = response.split('```json', 1)[1].split('```', 1)[0].strip()
                parsed = json.loads(json_content)
                if isinstance(parsed, dict) and 'answer' in parsed:
                    answer = parsed.get('answer', '')
                    if len(answer) > 100 and 'comprehensive technical response' not in answer.lower():
                        return parsed
            except (json.JSONDecodeError, IndexError):
                pass

        # Method 3: Find ALL balanced JSON objects containing "answer" field
        # Then pick the one with the most substantive answer
        candidates = []
        depth = 0
        start = -1

        for i, char in enumerate(response):
            if char == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        json_str = response[start:i+1]
                        parsed = json.loads(json_str)
                        if isinstance(parsed, dict) and 'answer' in parsed:
                            answer = parsed.get('answer', '')
                            # Skip template/placeholder answers
                            if 'comprehensive technical response' not in answer.lower():
                                candidates.append({
                                    'parsed': parsed,
                                    'answer_len': len(answer),
                                    'position': start
                                })
                    except json.JSONDecodeError:
                        pass
                    start = -1

        if candidates:
            # Sort by answer length (prefer longer, more substantive answers)
            # If tied, prefer later positions (actual response vs schema example)
            candidates.sort(key=lambda x: (x['answer_len'], x['position']), reverse=True)
            best = candidates[0]
            if best['answer_len'] > 100:
                return best['parsed']

        return None

    async def create_instruction_response(
        self,
        client: VLLMClient,
        entry: Dict,
        entry_type: str,
        instruction_template: str,
        fields: Dict,
    ) -> Optional[Dict]:
        """Create a single instruction-response pair with reasoning and quality validation."""
        try:
            instruction = instruction_template.format(**fields)
        except KeyError as e:
            logger.debug(f"Missing field for template: {e}")
            return None

        template = self.templates[entry_type]

        # Get reasoning schema for this entry type
        reasoning_schema = self.get_reasoning_schema(entry_type)
        reasoning_schema_str = json.dumps(reasoning_schema, indent=2)

        # Convert raw_data to string for LLM prompt
        raw_data_str = json.dumps(fields['raw_data'], indent=2, default=str)

        # Build uncertainty calibration directive if confidence data is available
        uncertainty_directive = ""
        if HAS_CALIBRATED_UNCERTAINTY:
            corroboration_score = fields.get('raw_data', {}).get('corroboration_score')
            if corroboration_score is not None:
                if corroboration_score >= 0.7:
                    uncertainty_directive = "\n- Use confident language (e.g., 'is confirmed to', 'definitively', 'based on strong evidence')"
                elif corroboration_score >= 0.4:
                    uncertainty_directive = "\n- Use moderate confidence language (e.g., 'likely', 'evidence suggests', 'probably')"
                elif corroboration_score >= 0.2:
                    uncertainty_directive = "\n- Use cautious language (e.g., 'may', 'possibly', 'limited evidence suggests')"
                else:
                    uncertainty_directive = "\n- Use speculative language (e.g., 'theoretically', 'hypothetically', 'unconfirmed')"

        # Build prompt requesting structured reasoning + answer as JSON
        prompt = f"""Analyze the following {entry_type.replace('_', ' ')} data and answer the question.

CONTEXT (JSON):
{raw_data_str}

QUESTION: {instruction}

Respond with a JSON object following this exact structure:
{{
  "reasoning": {reasoning_schema_str},
  "answer": "your comprehensive technical response"
}}

REQUIREMENTS:
- The "reasoning" field must analyze the JSON context and extract key information using the EXACT schema structure above
- The "answer" field must be technically dense and actionable - prioritize substance over length
- Include specific identifiers (CVE, CWE, MITRE IDs), concrete steps, and measurable recommendations
- Avoid filler phrases, repetition, and generic statements - every sentence must add value
- Use bullet points or numbered lists for actionable items when appropriate{uncertainty_directive}
- Return ONLY valid JSON, no markdown formatting"""

        response = await client.simple_query(
            prompt,
            system_prompt=template['system_prompt'] + " Always respond with valid JSON only.",
            max_tokens=2048,  # Increased for reasoning + answer
            temperature=0.2,  # Low for consistent JSON structure
        )

        # Parse JSON response
        if response:
            response = response.strip()

            # Try to extract and parse JSON with improved parsing
            parsed = self._parse_llm_json_response(response)

            if parsed:
                reasoning = parsed.get('reasoning', {})
                answer = parsed.get('answer', '')

                # Validate answer quality (minimum ~80 words / 400 chars for dense technical content)
                if not answer or len(answer) < 400:
                    logger.debug(f"Answer too short ({len(answer) if answer else 0} chars, need 400+)")
                    return None

                # Check for refusal patterns
                refusal_patterns = ['i cannot', "i can't", 'i am unable', 'as an ai']
                if any(pattern in answer.lower()[:100] for pattern in refusal_patterns):
                    logger.debug("Answer appears to be a refusal")
                    return None

                # Extract enrichment metadata if available
                raw_data = fields.get('raw_data', {})
                enrichment_metadata = {}
                if raw_data.get('corroboration_score') is not None:
                    enrichment_metadata['corroboration_score'] = raw_data.get('corroboration_score')
                    enrichment_metadata['sources_count'] = raw_data.get('sources_count', 0)
                if raw_data.get('remediation_complexity'):
                    rc = raw_data['remediation_complexity']
                    enrichment_metadata['remediation_complexity'] = rc.get('level') if isinstance(rc, dict) else None
                    enrichment_metadata['implementation_group'] = rc.get('min_implementation_group') if isinstance(rc, dict) else None

                result = {
                    'instruction': instruction,
                    'context': raw_data,  # Full source data as native JSON
                    'reasoning': reasoning,  # Structured reasoning
                    'response': answer,  # The actual answer
                    'type': entry_type,
                    'source_data': {
                        'id': fields.get('identifier', 'Unknown'),
                        'type': entry_type,
                        'kill_chain': fields.get('kill_chain_phases', ''),
                    }
                }

                # Add enrichment metadata if present
                if enrichment_metadata:
                    result['enrichment'] = enrichment_metadata

                return result
            else:
                logger.debug("Failed to parse JSON response")
        return None

    async def process_entry(
        self,
        client: VLLMClient,
        entry: Dict,
        idx: int,
        total: int,
        source_file: str = "",
    ) -> List[Dict]:
        """Process a single entry and generate instruction-response pairs."""
        if idx % 10 == 0:
            logger.info(f"Processing entry {idx + 1}/{total}")

        entry_type = self.detect_entry_type(entry, source_file)
        if not entry_type:
            logger.debug(f"Could not determine type for entry {idx + 1}")
            return []

        if entry_type not in self.templates:
            logger.debug(f"No template for type: {entry_type}")
            return []

        fields = self.extract_fields(entry, entry_type)
        selected_instructions = self.select_instructions(entry_type, fields)

        if not selected_instructions:
            return []

        pairs = []

        # Create tasks for selected instruction templates
        tasks = [
            self.create_instruction_response(client, entry, entry_type, instr_template, fields)
            for instr_template in selected_instructions
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Error creating pair: {result}")
            elif result:
                pairs.append(result)

        return pairs

    async def structure_file(self, file_path: Path, checkpoint_interval: int = 10) -> Tuple[List[Dict], Dict]:
        """Structure a single file into instruction-response pairs with checkpointing."""
        data = self.load_data(file_path)
        if not data:
            return [], {}

        # Handle different data formats - extract nested lists
        if isinstance(data, dict):
            nested_keys = [
                'vulnerabilities', 'entries', 'pulses', 'iocs', 'data',
                'objects', 'samples', 'advisories', 'results', 'items',
                'cves', 'summary', 'Attack_Patterns', 'ctftime_events',
                'phishing_urls', 'papers', 'value',
            ]

            extracted = False
            for key in nested_keys:
                if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                    logger.info(f"Extracting {len(data[key])} items from '{key}' key")
                    data = data[key]
                    extracted = True
                    break

            if not extracted:
                data = [data]

        total = len(data)
        logger.info(f"Processing {total} entries from {file_path.name}")

        # Check for existing checkpoint
        base_name = file_path.stem.split('_filtered_')[0]
        checkpoint_file = self.output_dir / f"{base_name}_checkpoint.json"

        all_pairs = []
        type_counts = {}
        start_idx = 0

        # Resume from checkpoint if exists
        if checkpoint_file.exists():
            try:
                with open(checkpoint_file, 'r') as f:
                    checkpoint = json.load(f)
                all_pairs = checkpoint.get('pairs', [])
                type_counts = checkpoint.get('type_counts', {})
                start_idx = checkpoint.get('processed_entries', 0)
                logger.info(f"Resuming from checkpoint: {start_idx}/{total} entries, {len(all_pairs)} pairs")
            except Exception as e:
                logger.warning(f"Could not load checkpoint: {e}")

        async with VLLMClient(self.vllm_config) as client:
            batch_size = self.vllm_config.max_concurrent
            entries_since_checkpoint = 0

            for batch_start in range(start_idx, total, batch_size):
                batch_end = min(batch_start + batch_size, total)
                batch = data[batch_start:batch_end]

                tasks = [
                    self.process_entry(client, entry, batch_start + i, total, file_path.name)
                    for i, entry in enumerate(batch)
                ]

                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error processing entry: {result}")
                    elif result:
                        for pair in result:
                            pair_type = pair.get('type', 'unknown')
                            type_counts[pair_type] = type_counts.get(pair_type, 0) + 1
                        all_pairs.extend(result)

                entries_since_checkpoint += len(batch)

                # Save checkpoint every N entries
                if entries_since_checkpoint >= checkpoint_interval:
                    with open(checkpoint_file, 'w') as f:
                        json.dump({
                            'processed_entries': batch_end,
                            'pairs': all_pairs,
                            'type_counts': type_counts,
                        }, f)
                    logger.info(f"Checkpoint saved: {batch_end}/{total} entries, {len(all_pairs)} pairs")
                    entries_since_checkpoint = 0

        # Remove checkpoint after successful completion
        if checkpoint_file.exists():
            checkpoint_file.unlink()

        logger.info(f"Generated {len(all_pairs)} instruction-response pairs from {file_path.name}")
        if type_counts:
            logger.info(f"Type distribution: {type_counts}")

        return all_pairs, type_counts

    def load_data(self, file_path: Path) -> Union[Dict, List, None]:
        """Load data from various file formats."""
        try:
            suffix = file_path.suffix.lower()
            if suffix == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            elif suffix in {'.yaml', '.yml'}:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            elif suffix == '.csv':
                return pd.read_csv(file_path).to_dict('records')
            else:
                logger.warning(f"Unsupported file format: {suffix}")
                return None
        except Exception as e:
            logger.error(f"Error loading file {file_path}: {str(e)}")
            return None

    def _get_output_path(self, input_file: Path) -> Path:
        """Get output path for a structured file."""
        # Remove _filtered_ timestamp and add _structured_
        stem = input_file.stem
        # e.g., "cve_data_20251221_164810_filtered_20251221_205414" -> "cve_data_20251221_164810"
        base_name = stem.split('_filtered_')[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return self.output_dir / f"{base_name}_structured_{timestamp}.json"

    def _is_already_processed(self, input_file: Path) -> bool:
        """Check if input file was already processed."""
        stem = input_file.stem
        base_name = stem.split('_filtered_')[0]
        existing = list(self.output_dir.glob(f"{base_name}_structured_*.json"))
        return len(existing) > 0

    async def process_directory(self):
        """Process all files in the input directory."""
        # Check vLLM health first
        if not await check_vllm_health(self.vllm_config.base_url):
            logger.error(f"vLLM server not available at {self.vllm_config.base_url}")
            return

        logger.info(f"vLLM server healthy at {self.vllm_config.base_url}")

        all_type_counts = {}
        processed_files = 0
        total_pairs = 0

        # Get filtered JSON files
        input_files = list(self.input_dir.glob('*_filtered_*.json'))
        total_files = len(input_files)

        logger.info(f"Found {total_files} filtered files to process")

        for i, file_path in enumerate(input_files, 1):
            # Skip if already processed
            if self._is_already_processed(file_path):
                logger.info(f"\nSkipping {file_path.name} (already processed)")
                continue

            logger.info(f"\nProcessing file {i}/{total_files}: {file_path.name}")

            pairs, type_counts = await self.structure_file(file_path)

            if pairs:
                processed_files += 1
                total_pairs += len(pairs)
                for t, c in type_counts.items():
                    all_type_counts[t] = all_type_counts.get(t, 0) + c

                # Save immediately after each file
                output_file = self._get_output_path(file_path)
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        'metadata': {
                            'source_file': file_path.name,
                            'total_entries': len(pairs),
                            'generation_timestamp': datetime.now().isoformat(),
                            'model_used': self.vllm_config.model,
                            'type_distribution': type_counts,
                        },
                        'data': pairs
                    }, f, indent=2)

                logger.info(f"Saved {len(pairs)} pairs to {output_file.name}")

        logger.info("\n" + "=" * 50)
        logger.info("Structuring Statistics:")
        logger.info(f"Processed Files: {processed_files}")
        logger.info(f"Total Instruction-Response Pairs: {total_pairs}")
        logger.info("Type Distribution:")
        for t, c in sorted(all_type_counts.items(), key=lambda x: -x[1]):
            logger.info(f"  {t}: {c}")


    async def _process_single_source_sample(
        self,
        file_path: Path,
        sample_size: int,
        client: VLLMClient,
        sample_output_dir: Path,
        timestamp: str,
    ) -> Dict:
        """Process samples from a single source file.

        Args:
            file_path: Path to the filtered source file
            sample_size: Number of entries to sample
            client: Shared VLLMClient instance (handles concurrency internally)
            sample_output_dir: Directory to save individual sample files
            timestamp: Timestamp string for output file naming

        Returns:
            Summary dict for this source
        """
        logger.info(f"Starting: {file_path.name}")

        data = self.load_data(file_path)
        if not data:
            return None

        # Handle different data formats - extract nested lists
        if isinstance(data, dict):
            nested_keys = [
                'vulnerabilities', 'entries', 'pulses', 'iocs', 'data',
                'objects', 'samples', 'advisories', 'results', 'items',
                'cves', 'summary', 'Attack_Patterns', 'ctftime_events',
                'phishing_urls', 'papers', 'value',
            ]

            extracted = False
            for key in nested_keys:
                if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                    data = data[key]
                    extracted = True
                    break

            if not extracted:
                data = [data]

        total_entries = len(data)

        # Pre-filter entries that have valid types (skip relationship, identity, etc.)
        valid_entries = []
        for entry in data:
            entry_type = self.detect_entry_type(entry, file_path.name)
            if entry_type is not None and entry_type in self.templates:
                valid_entries.append(entry)

        if not valid_entries:
            logger.warning(f"  No valid entries in {file_path.name} (all {total_entries} entries filtered out)")
            return {
                'source_file': file_path.name,
                'total_entries_in_source': total_entries,
                'entries_sampled': 0,
                'pairs_generated': 0,
                'type_distribution': {},
                'detected_types': [],
                'pairs': [],
            }

        # Log if many entries were filtered
        if len(valid_entries) < total_entries * 0.5:
            logger.info(f"  {file_path.name}: {len(valid_entries)}/{total_entries} valid entries ({100*len(valid_entries)/total_entries:.0f}%)")

        # Sample from valid entries only
        actual_sample_size = min(sample_size, len(valid_entries))
        sampled_entries = random.sample(valid_entries, actual_sample_size)

        # Process sampled entries concurrently (client's semaphore handles rate limiting)
        # With retry logic for transient failures
        file_pairs = []
        type_counts = {}
        max_retries = 2

        for attempt in range(max_retries + 1):
            tasks = [
                self.process_entry(client, entry, idx, actual_sample_size, file_path.name)
                for idx, entry in enumerate(sampled_entries)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"  Error in {file_path.name}: {result}")
                elif result:
                    for pair in result:
                        pair_type = pair.get('type', 'unknown')
                        type_counts[pair_type] = type_counts.get(pair_type, 0) + 1
                        pair['source_file'] = file_path.name
                        file_pairs.append(pair)

            # If we got some pairs, we're done
            if file_pairs:
                break
            elif attempt < max_retries:
                logger.warning(f"  {file_path.name}: 0 pairs, retrying ({attempt + 1}/{max_retries})...")
                await asyncio.sleep(1)  # Brief pause before retry

        # Save individual source sample file immediately
        base_name = file_path.stem.split('_filtered_')[0]
        source_sample_file = sample_output_dir / f"{base_name}_sample_{timestamp}.json"

        with open(source_sample_file, 'w', encoding='utf-8') as f:
            json.dump({
                'source_file': file_path.name,
                'total_entries_in_source': total_entries,
                'entries_sampled': actual_sample_size,
                'pairs_generated': len(file_pairs),
                'type_distribution': type_counts,
                'samples': file_pairs
            }, f, indent=2)

        logger.info(f"✓ {base_name}: {len(file_pairs)} pairs -> {source_sample_file.name}")

        return {
            'source_file': file_path.name,
            'total_entries_in_source': total_entries,
            'entries_sampled': actual_sample_size,
            'pairs_generated': len(file_pairs),
            'type_distribution': type_counts,
            'detected_types': list(type_counts.keys()),
            'pairs': file_pairs,
        }

    async def process_sample(self, sample_size: int = 5):
        """Process a sample of entries from each source file for quality verification.

        Processes all sources in parallel while respecting max_concurrent limit.

        Args:
            sample_size: Number of entries to sample from each source file (default: 5)
        """
        # Check vLLM health first
        if not await check_vllm_health(self.vllm_config.base_url):
            logger.error(f"vLLM server not available at {self.vllm_config.base_url}")
            return

        logger.info(f"vLLM server healthy at {self.vllm_config.base_url}")
        logger.info(f"=== SAMPLE MODE: Processing {sample_size} entries per source (PARALLEL) ===")

        # Create sample output directory
        sample_output_dir = self.output_dir / "samples"
        sample_output_dir.mkdir(parents=True, exist_ok=True)

        # Get filtered JSON files
        input_files = list(self.input_dir.glob('*_filtered_*.json'))
        total_files = len(input_files)

        # Generate timestamp once for all files in this run
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        logger.info(f"Found {total_files} filtered files to sample")
        logger.info(f"Max concurrent requests: {self.vllm_config.max_concurrent}")

        # Use a single shared client - its internal semaphore handles concurrency
        async with VLLMClient(self.vllm_config) as client:
            # Process all sources in parallel - client's semaphore limits actual requests
            tasks = [
                self._process_single_source_sample(file_path, sample_size, client, sample_output_dir, timestamp)
                for file_path in input_files
            ]

            logger.info(f"\nStarting parallel processing of {len(tasks)} sources...")
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        source_summaries = []
        all_samples = []

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Source processing error: {result}")
            elif result:
                pairs = result.pop('pairs', [])
                source_summaries.append(result)
                all_samples.extend(pairs)

        # Save combined summary file (use same timestamp)
        sample_file = sample_output_dir / f"sample_output_{timestamp}.json"

        with open(sample_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'mode': 'sample',
                    'sample_size_per_source': sample_size,
                    'total_sources': len(source_summaries),
                    'total_pairs_generated': len(all_samples),
                    'generation_timestamp': datetime.now().isoformat(),
                    'model_used': self.vllm_config.model,
                    'max_concurrent': self.vllm_config.max_concurrent,
                },
                'source_summaries': source_summaries,
                'samples': all_samples
            }, f, indent=2)

        # Print final summary
        logger.info("\n" + "=" * 60)
        logger.info("SAMPLE MODE SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Sources processed: {len(source_summaries)}")
        logger.info(f"Total sample pairs: {len(all_samples)}")
        logger.info(f"Output saved to: {sample_file}")
        logger.info("\nPer-source breakdown:")

        for summary in source_summaries:
            source_name = summary['source_file'].split('_filtered_')[0]
            logger.info(f"  {source_name}: {summary['pairs_generated']} pairs, types: {summary['detected_types']}")

        logger.info("\n" + "=" * 60)
        logger.info(f"Review samples at: {sample_file}")
        logger.info(f"Individual samples in: {sample_output_dir}/")
        logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Structure cybersecurity data using vLLM")
    parser.add_argument("--input-dir", default="filtered_data/sources", help="Input directory with source data")
    parser.add_argument("--output-dir", default="structured_data", help="Output directory")
    parser.add_argument("--vllm-url", default="http://localhost:8000", help="vLLM server URL")
    parser.add_argument("--vllm-model", default="nemotron", help="vLLM model name")
    parser.add_argument("--max-concurrent", type=int, default=8, help="Max concurrent requests")
    parser.add_argument("--max-instructions", type=int, default=3, help="Max instructions per entry")
    parser.add_argument("--reasoning-budget", type=int, default=256, help="Limit reasoning tokens (default: 256, recommended for quality)")
    parser.add_argument("--no-thinking", action="store_true", help="Disable reasoning completely")
    parser.add_argument("--sample", type=int, nargs='?', const=5, default=None,
                        metavar="N", help="Sample mode: process N entries per source (default: 5)")

    args = parser.parse_args()

    structurer = CyberDataStructurerVLLM(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        vllm_url=args.vllm_url,
        vllm_model=args.vllm_model,
        max_concurrent=args.max_concurrent,
        max_instructions_per_entry=args.max_instructions,
        enable_thinking=not args.no_thinking,
        reasoning_budget=args.reasoning_budget,
    )

    if args.sample is not None:
        asyncio.run(structurer.process_sample(sample_size=args.sample))
    else:
        asyncio.run(structurer.process_directory())


if __name__ == "__main__":
    main()
