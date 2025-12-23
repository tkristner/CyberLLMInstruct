#!/usr/bin/env python3
"""
Extract ATT&CK techniques and attack chains from CTI reports using LLM.

Uses vLLM Nemotron (262K context) to process full reports without chunking.
Outputs structured JSON for causal graph integration.
"""

import json
import logging
import re
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# vLLM configuration
VLLM_BASE_URL = "http://127.0.0.1:5000"
VLLM_MODEL = "nemotron"


@dataclass
class AttackChain:
    """Represents an observed attack chain from CTI report."""
    from_technique: str
    to_technique: str
    relation: str  # "enables", "followed_by", "leads_to"
    evidence: str
    actor: Optional[str] = None
    campaign: Optional[str] = None
    confidence: float = 0.7


@dataclass
class ExtractedCTI:
    """Extracted CTI data from a report."""
    report_name: str
    report_year: int
    source_file: str
    extraction_timestamp: str
    techniques_mentioned: List[str] = field(default_factory=list)
    techniques_with_context: List[Dict] = field(default_factory=list)  # For traceability
    attack_chains: List[AttackChain] = field(default_factory=list)
    actors_mentioned: List[str] = field(default_factory=list)
    campaigns_mentioned: List[str] = field(default_factory=list)
    malware_mentioned: List[str] = field(default_factory=list)
    cves_mentioned: List[str] = field(default_factory=list)
    extraction_confidence: float = 0.0
    raw_llm_response: str = ""


EXTRACTION_PROMPT = '''You are a cybersecurity threat intelligence analyst. Your task is to extract specific information from the CTI report below.

READ THE ENTIRE REPORT CAREFULLY, then extract:
1. MITRE ATT&CK technique IDs (T1XXX format) that are mentioned or described
2. Threat actor names (APT groups, FIN groups, named adversaries like "Lazarus", "Fancy Bear")
3. Malware family names mentioned
4. CVE IDs mentioned (CVE-XXXX-XXXXX format)
5. Attack sequences where one action leads to another

IMPORTANT: Only extract information that is ACTUALLY IN the report. Do not copy the example.

=== REPORT TO ANALYZE ===
{report_content}
=== END OF REPORT ===

Based on the report above, output a JSON object with your findings. If nothing relevant is found for a category, use an empty list [].

JSON output:'''



# Valid MITRE ATT&CK technique patterns (main techniques only for validation)
VALID_TECHNIQUE_PATTERN = re.compile(r'^T1\d{3}(?:\.\d{3})?$')

# Known valid parent techniques (T1001-T1659 range approximately)
VALID_TECHNIQUE_RANGE = range(1001, 1700)


class CTIReportExtractor:
    """Extract structured CTI data from markdown reports using LLM."""

    def __init__(
        self,
        reports_dir: str = "raw_data/MD_CTI_reports",
        output_dir: str = "filtered_data/sources/threat_intel",
        vllm_url: str = VLLM_BASE_URL,
        model: str = VLLM_MODEL,
        max_workers: int = 4
    ):
        self.reports_dir = Path(reports_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.vllm_url = vllm_url
        self.model = model
        self.max_workers = max_workers

        # Thread-safe stats
        self._stats_lock = threading.Lock()
        self.stats = {
            'total_reports': 0,
            'processed': 0,
            'failed': 0,
            'total_techniques': set(),
            'total_chains': 0,
            'total_actors': set()
        }

    def validate_technique(self, tech_id: str) -> bool:
        """Validate that a technique ID is plausibly real."""
        if not VALID_TECHNIQUE_PATTERN.match(tech_id):
            return False

        # Extract parent technique number
        parent_num = int(tech_id.split('.')[0][1:])

        # Check if in valid range
        if parent_num not in VALID_TECHNIQUE_RANGE:
            return False

        # Filter out obviously hallucinated subtechniques (most have < 20 subtechniques)
        if '.' in tech_id:
            sub_num = int(tech_id.split('.')[1])
            if sub_num > 50:  # No technique has > 50 subtechniques
                return False

        return True

    def filter_valid_techniques(self, techniques: List[str]) -> List[str]:
        """Filter list to only valid technique IDs."""
        return [t for t in techniques if self.validate_technique(t)]

    def check_vllm_health(self) -> bool:
        """Check if vLLM server is available."""
        try:
            response = requests.get(f"{self.vllm_url}/v1/models", timeout=5)
            if response.status_code == 200:
                models = response.json()
                logger.info(f"vLLM available with models: {[m['id'] for m in models['data']]}")
                return True
        except Exception as e:
            logger.error(f"vLLM not available: {e}")
        return False

    def call_llm(self, content: str, max_tokens: int = 2000, disable_reasoning: bool = False) -> Optional[str]:
        """Call vLLM Chat API for extraction.

        Args:
            content: The content to send to the LLM
            max_tokens: Maximum tokens in response
            disable_reasoning: If True, disable Nemotron's reasoning mode for direct output
        """
        try:
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a CTI analyst. Extract cybersecurity indicators from reports. Output ONLY the data found, no explanations."
                    },
                    {
                        "role": "user",
                        "content": f"""Extract from this CTI report:
1. MITRE ATT&CK technique IDs (T1XXX or T1XXX.XXX format)
2. Threat actor names (APT groups, FIN groups, named adversaries)
3. Malware family names
4. CVE IDs (CVE-XXXX-XXXXX format)

Report:
{content}

Output format (comma-separated, one category per line):
TECHNIQUES: T1566, T1059.001, ...
ACTORS: APT29, FIN7, ...
MALWARE: Cobalt Strike, SUNBURST, ...
CVES: CVE-2023-34362, ..."""
                    }
                ],
                "max_tokens": max_tokens,
                "temperature": 0.1
            }

            # Disable reasoning mode for direct structured output
            if disable_reasoning:
                payload["chat_template_kwargs"] = {"enable_thinking": False}

            response = requests.post(
                f"{self.vllm_url}/v1/chat/completions",
                json=payload,
                timeout=180
            )

            if response.status_code == 200:
                result = response.json()
                msg = result['choices'][0]['message']

                # Handle Nemotron's reasoning mode where content is null
                if msg.get('content'):
                    return msg['content'].strip()
                elif msg.get('reasoning'):
                    # Extract useful data from reasoning field
                    reasoning = msg['reasoning']
                    logger.debug(f"Using reasoning field (content was null)")
                    return reasoning.strip()
                else:
                    logger.warning(f"No content or reasoning in response: {msg}")
                    return None
            else:
                logger.error(f"vLLM error: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return None

    def extract_attack_chains_llm(self, content: str) -> List[Dict]:
        """Extract attack chains from report using LLM with reasoning disabled."""
        try:
            prompt = f"""Analyze this CTI report and extract attack chains.

RULES:
1. An attack chain is when technique A enables or leads to technique B
2. Only extract chains EXPLICITLY described in the report text
3. Use the actor name mentioned in the report (e.g., BlackCat, LockBit, APT29)
4. If no actor is specified for a chain, use "Unknown"
5. Do NOT duplicate chains - each unique chain should appear only once

OUTPUT FORMAT (one chain per line):
TECHNIQUE_A -> TECHNIQUE_B | ACTOR_NAME | CONFIDENCE

Example:
T1190 -> T1078 | BlackCat | 0.85
T1566 -> T1059 | LockBit | 0.80

Extract chains from this report:
{content[:30000]}"""

            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a CTI analyst. Extract attack chains exactly as described in reports. Be precise with actor names. Output ONLY the chains, one per line."
                    },
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 2000,
                "temperature": 0.1,
                "chat_template_kwargs": {"enable_thinking": False}
            }

            response = requests.post(
                f"{self.vllm_url}/v1/chat/completions",
                json=payload,
                timeout=180
            )

            if response.status_code != 200:
                logger.warning(f"Attack chain extraction failed: {response.status_code}")
                return []

            result = response.json()
            msg = result['choices'][0]['message']
            output = msg.get('content') or msg.get('reasoning') or ""

            # Parse the chains
            chains = []
            seen_chains = set()  # Deduplicate
            consecutive_low_confidence = 0  # Detect model repetition loops

            for line in output.strip().split('\n'):
                line = line.strip()
                if '->' not in line or '|' not in line:
                    continue

                try:
                    # Parse: T1XXX -> T1XXX | ACTOR | CONFIDENCE
                    parts = line.split('|')
                    if len(parts) < 2:
                        continue

                    technique_part = parts[0].strip()
                    actor = parts[1].strip() if len(parts) > 1 else "Unknown"
                    confidence_str = parts[2].strip() if len(parts) > 2 else "0.7"

                    # Parse techniques
                    if '->' not in technique_part:
                        continue

                    techniques = [t.strip() for t in technique_part.split('->')]
                    if len(techniques) != 2:
                        continue

                    from_tech = techniques[0]
                    to_tech = techniques[1]

                    # Validate technique format
                    if not (from_tech.startswith('T1') and to_tech.startswith('T1')):
                        continue

                    # Parse confidence
                    try:
                        confidence = float(confidence_str)
                        confidence = max(0.0, min(1.0, confidence))
                    except ValueError:
                        confidence = 0.7

                    # Filter out very low confidence chains (likely hallucinations)
                    if confidence < 0.3:
                        consecutive_low_confidence += 1
                        # Stop if we see too many low confidence chains (model in repetition loop)
                        if consecutive_low_confidence > 5:
                            logger.debug("Stopping chain extraction - detected repetition loop")
                            break
                        continue
                    else:
                        consecutive_low_confidence = 0

                    # Deduplicate (ignore actor for dedup to avoid same chain with different actors)
                    chain_key = f"{from_tech}->{to_tech}"
                    if chain_key in seen_chains:
                        continue
                    seen_chains.add(chain_key)

                    # Clean actor name (remove quotes and common artifacts)
                    actor = actor.strip('"\'')
                    if len(actor) > 50 or 'Also' in actor or '?' in actor:
                        actor = "Unknown"

                    chains.append({
                        "from_technique": from_tech,
                        "to_technique": to_tech,
                        "relation": "enables",
                        "actor": actor if actor != "Unknown" else None,
                        "confidence": confidence,
                        "evidence": f"Extracted from CTI report"
                    })

                except Exception as e:
                    logger.debug(f"Failed to parse chain line: {line} - {e}")
                    continue

            logger.info(f"Extracted {len(chains)} attack chains")
            return chains

        except Exception as e:
            logger.error(f"Attack chain extraction failed: {e}")
            return []

    def parse_llm_response(self, response: str) -> Optional[Dict]:
        """Parse line-based LLM response (TECHNIQUES: ..., ACTORS: ..., etc.)."""
        if not response:
            return None

        result = {
            'techniques_mentioned': [],
            'attack_chains': [],
            'actors_mentioned': [],
            'campaigns_mentioned': [],
            'malware_mentioned': [],
            'cves_mentioned': [],
            'extraction_confidence': 0.7
        }

        try:
            lines = response.strip().split('\n')
            found_structured = False

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Parse each category
                if line.upper().startswith('TECHNIQUES:'):
                    found_structured = True
                    items = line.split(':', 1)[1].strip()
                    if items and items not in ['...', 'None', 'N/A', '']:
                        techniques = [t.strip() for t in items.split(',')]
                        result['techniques_mentioned'] = [
                            t for t in techniques
                            if t.startswith('T1') and 'XXX' not in t and len(t) >= 5
                        ]

                elif line.upper().startswith('ACTORS:'):
                    found_structured = True
                    items = line.split(':', 1)[1].strip()
                    if items and items not in ['...', 'None', 'N/A', '']:
                        actors = [a.strip() for a in items.split(',')]
                        result['actors_mentioned'] = [
                            a for a in actors
                            if a and len(a) > 2 and 'NAME' not in a and '...' not in a
                        ]

                elif line.upper().startswith('MALWARE:'):
                    found_structured = True
                    items = line.split(':', 1)[1].strip()
                    if items and items not in ['...', 'None', 'N/A', '']:
                        malware = [m.strip() for m in items.split(',')]
                        result['malware_mentioned'] = [
                            m for m in malware
                            if m and len(m) > 2 and '...' not in m
                        ]

                elif line.upper().startswith('CVES:') or line.upper().startswith('CVE:'):
                    found_structured = True
                    items = line.split(':', 1)[1].strip()
                    if items and items not in ['...', 'None', 'N/A', '']:
                        cves = [c.strip() for c in items.split(',')]
                        result['cves_mentioned'] = [
                            c for c in cves
                            if c.startswith('CVE-') and 'XXXX' not in c
                        ]

            # If no structured output found, try regex extraction from reasoning text
            if not found_structured:
                logger.info("No structured output, extracting from reasoning text")
                # Extract techniques mentioned anywhere in the text
                techniques = set(re.findall(r'T1\d{3}(?:\.\d{3})?', response))
                result['techniques_mentioned'] = [t for t in techniques if 'XXX' not in t]

                # Extract CVEs
                cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', response))
                result['cves_mentioned'] = list(cves)

                # Extract actors
                actors = set(re.findall(r'APT\d{1,2}|FIN\d{1,2}|UNC\d{4}|Lazarus|Fancy Bear|Cozy Bear|Kimsuky|Turla|Sandworm', response, re.IGNORECASE))
                result['actors_mentioned'] = list(actors)

                # Extract malware
                malware = set(re.findall(r'Cobalt Strike|Emotet|TrickBot|Ryuk|Conti|LockBit|BlackCat|ALPHV|Mimikatz|QakBot|IcedID', response, re.IGNORECASE))
                result['malware_mentioned'] = list(malware)

                # Lower confidence for unstructured extraction
                result['extraction_confidence'] = 0.5

            # Set confidence based on what was found
            found_count = sum([
                len(result['techniques_mentioned']) > 0,
                len(result['actors_mentioned']) > 0,
                len(result['malware_mentioned']) > 0,
                len(result['cves_mentioned']) > 0
            ])
            result['extraction_confidence'] = max(result['extraction_confidence'], 0.5 + (found_count * 0.1))

            return result

        except Exception as e:
            logger.warning(f"Failed to parse response: {e}")
            return None

    def _normalize_extraction(self, data: Dict) -> Dict:
        """Normalize field names from various LLM output formats."""
        normalized = {
            'techniques_mentioned': [],
            'attack_chains': [],
            'actors_mentioned': [],
            'campaigns_mentioned': [],
            'malware_mentioned': [],
            'cves_mentioned': [],
            'extraction_confidence': 0.5
        }

        # Map various field names to our standard format
        technique_keys = ['techniques_mentioned', 'mitre_attack_techniques', 'mitre_techniques', 'techniques', 'attack_techniques']
        actor_keys = ['actors_mentioned', 'threat_actors', 'actors', 'apt_groups']
        malware_keys = ['malware_mentioned', 'malware_families', 'malware']
        cve_keys = ['cves_mentioned', 'cve_ids', 'cves', 'vulnerabilities']
        chain_keys = ['attack_chains', 'attack_sequences', 'chains', 'sequences']

        for key in technique_keys:
            if key in data and isinstance(data[key], list):
                # Filter out placeholder values
                normalized['techniques_mentioned'] = [
                    t for t in data[key]
                    if isinstance(t, str) and t.startswith('T1') and 'XXXX' not in t
                ]
                break

        for key in actor_keys:
            if key in data and isinstance(data[key], list):
                normalized['actors_mentioned'] = [
                    a for a in data[key]
                    if isinstance(a, str) and 'NAME_' not in a and len(a) > 2
                ]
                break

        for key in malware_keys:
            if key in data and isinstance(data[key], list):
                normalized['malware_mentioned'] = [
                    m for m in data[key]
                    if isinstance(m, str) and 'NAME_' not in m and len(m) > 2
                ]
                break

        for key in cve_keys:
            if key in data and isinstance(data[key], list):
                normalized['cves_mentioned'] = [
                    c for c in data[key]
                    if isinstance(c, str) and c.startswith('CVE-') and 'XXXX' not in c
                ]
                break

        for key in chain_keys:
            if key in data and isinstance(data[key], list):
                chains = []
                for chain in data[key]:
                    if isinstance(chain, dict):
                        # Check if it has valid technique IDs
                        from_t = chain.get('from_technique', chain.get('source', ''))
                        to_t = chain.get('to_technique', chain.get('target', ''))
                        if from_t and to_t and 'XXXX' not in from_t and 'XXXX' not in to_t:
                            chains.append(chain)
                normalized['attack_chains'] = chains
                break

        if 'extraction_confidence' in data:
            normalized['extraction_confidence'] = data['extraction_confidence']

        return normalized

    def extract_with_regex(self, content: str) -> Dict:
        """Fallback regex extraction for techniques and CVEs with context."""
        techniques = set(re.findall(r'T1\d{3}(?:\.\d{3})?', content))
        cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', content))

        # Common APT/actor patterns
        actors = set(re.findall(r'APT\d{1,2}|FIN\d{1,2}|UNC\d{4}|Lazarus|Fancy Bear|Cozy Bear|Kimsuky|Turla|Sandworm', content, re.IGNORECASE))

        # Common malware patterns
        malware = set(re.findall(r'Cobalt Strike|Emotet|TrickBot|Ryuk|Conti|LockBit|BlackCat|ALPHV|Mimikatz|QakBot|IcedID', content, re.IGNORECASE))

        return {
            'techniques_mentioned': sorted(list(techniques)),
            'cves_mentioned': sorted(list(cves)),
            'actors_mentioned': sorted(list(actors)),
            'malware_mentioned': sorted(list(malware)),
            'attack_chains': [],
            'campaigns_mentioned': [],
            'extraction_confidence': 0.4  # Lower confidence for regex-only
        }

    def extract_with_context(self, content: str) -> List[Dict]:
        """Extract techniques with surrounding context for traceability."""
        extractions = []

        # Find techniques with context
        for match in re.finditer(r'(T1\d{3}(?:\.\d{3})?)', content):
            technique_id = match.group(1)
            start = max(0, match.start() - 150)
            end = min(len(content), match.end() + 150)
            context = content[start:end].replace('\n', ' ').strip()

            extractions.append({
                'technique_id': technique_id,
                'context': f"...{context}...",
                'position': match.start()
            })

        return extractions

    def process_report(self, report_path: Path) -> Optional[ExtractedCTI]:
        """Process a single CTI report."""
        try:
            # Read report content
            content = report_path.read_text(encoding='utf-8', errors='ignore')

            # Skip very short reports
            if len(content) < 500:
                logger.warning(f"Skipping short report: {report_path.name}")
                return None

            # Extract year from path
            year = int(report_path.parent.name) if report_path.parent.name.isdigit() else 2024

            # Call LLM with content directly (Chat API handles prompt internally)
            logger.info(f"Processing: {report_path.name} ({len(content)} chars)")
            llm_response = self.call_llm(content)

            # Parse response
            extracted = self.parse_llm_response(llm_response)

            if not extracted:
                # Fallback to regex
                logger.warning(f"LLM extraction failed, using regex fallback for {report_path.name}")
                extracted = self.extract_with_regex(content)
                extracted['extraction_confidence'] = 0.3

            # Filter and validate techniques
            raw_techniques = extracted.get('techniques_mentioned', [])
            valid_techniques = self.filter_valid_techniques(raw_techniques)

            if len(raw_techniques) != len(valid_techniques):
                logger.info(f"Filtered {len(raw_techniques) - len(valid_techniques)} invalid techniques")

            # Extract attack chains using LLM with reasoning disabled
            llm_chains = self.extract_attack_chains_llm(content)

            # Filter attack chains to only include valid techniques
            valid_chains = []
            for chain in llm_chains:
                if isinstance(chain, dict):
                    from_t = chain.get('from_technique', '')
                    to_t = chain.get('to_technique', '')
                    if self.validate_technique(from_t) and self.validate_technique(to_t):
                        valid_chains.append(chain)

            # Extract techniques with context for traceability
            techniques_with_context = self.extract_with_context(content)

            # Merge LLM + regex techniques
            regex_extraction = self.extract_with_regex(content)
            all_techniques = set(valid_techniques) | set(regex_extraction['techniques_mentioned'])
            all_actors = set(extracted.get('actors_mentioned', [])) | set(regex_extraction['actors_mentioned'])
            all_malware = set(extracted.get('malware_mentioned', [])) | set(regex_extraction['malware_mentioned'])
            all_cves = set(extracted.get('cves_mentioned', [])) | set(regex_extraction['cves_mentioned'])

            # Build result
            result = ExtractedCTI(
                report_name=report_path.stem,
                report_year=year,
                source_file=str(report_path),
                extraction_timestamp=datetime.now().isoformat(),
                techniques_mentioned=sorted(list(all_techniques)),
                techniques_with_context=techniques_with_context,  # Traceability!
                attack_chains=[
                    AttackChain(**chain) if isinstance(chain, dict) else chain
                    for chain in valid_chains
                ],
                actors_mentioned=sorted(list(all_actors)),
                campaigns_mentioned=extracted.get('campaigns_mentioned', []),
                malware_mentioned=sorted(list(all_malware)),
                cves_mentioned=sorted(list(all_cves)),
                extraction_confidence=extracted.get('extraction_confidence', 0.5),
                raw_llm_response=llm_response or ""
            )

            # Update stats (thread-safe)
            with self._stats_lock:
                self.stats['processed'] += 1
                self.stats['total_techniques'].update(result.techniques_mentioned)
                self.stats['total_chains'] += len(result.attack_chains)
                self.stats['total_actors'].update(result.actors_mentioned)

            return result

        except Exception as e:
            logger.error(f"Error processing {report_path}: {e}")
            with self._stats_lock:
                self.stats['failed'] += 1
            return None

    def _process_report_wrapper(self, args: Tuple[int, int, Path]) -> Optional[ExtractedCTI]:
        """Wrapper for parallel processing with progress tracking."""
        idx, total, report_path = args
        logger.info(f"[{idx}/{total}] Processing {report_path.name}")
        return self.process_report(report_path)

    def process_all_reports(
        self,
        years: Optional[List[int]] = None,
        limit: Optional[int] = None,
        parallel: bool = True
    ) -> List[ExtractedCTI]:
        """Process all CTI reports (optionally in parallel)."""

        # Check vLLM
        if not self.check_vllm_health():
            logger.error("vLLM not available, cannot proceed")
            return []

        # Collect report files
        report_files = []
        for year_dir in sorted(self.reports_dir.iterdir()):
            if year_dir.is_dir() and year_dir.name.isdigit():
                year = int(year_dir.name)
                if years and year not in years:
                    continue

                for report_file in year_dir.glob("*.md"):
                    report_files.append(report_file)

        self.stats['total_reports'] = len(report_files)
        logger.info(f"Found {len(report_files)} reports to process")

        if limit:
            report_files = report_files[:limit]
            logger.info(f"Limited to {limit} reports")

        total = len(report_files)

        if parallel and self.max_workers > 1:
            # Parallel processing
            logger.info(f"Processing with {self.max_workers} parallel workers")
            results = []

            # Prepare args with index for progress tracking
            task_args = [(i + 1, total, path) for i, path in enumerate(report_files)]

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all tasks
                future_to_path = {
                    executor.submit(self._process_report_wrapper, args): args[2]
                    for args in task_args
                }

                # Collect results as they complete
                for future in as_completed(future_to_path):
                    report_path = future_to_path[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        logger.error(f"Exception processing {report_path}: {e}")
                        with self._stats_lock:
                            self.stats['failed'] += 1

            return results
        else:
            # Sequential processing (original behavior)
            logger.info("Processing sequentially")
            results = []
            for i, report_path in enumerate(report_files):
                logger.info(f"[{i+1}/{total}] Processing {report_path.name}")

                result = self.process_report(report_path)
                if result:
                    results.append(result)

                # Rate limiting for sequential mode
                time.sleep(0.5)

            return results

    def save_results(self, results: List[ExtractedCTI], filename: str = "cti_extracted"):
        """Save extraction results."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Convert to serializable format
        data = []
        for r in results:
            r_dict = asdict(r)
            # Convert AttackChain objects
            r_dict['attack_chains'] = [
                asdict(c) if hasattr(c, '__dataclass_fields__') else c
                for c in r.attack_chains
            ]
            data.append(r_dict)

        # Save full results
        output_file = self.output_dir / f"{filename}_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(results)} extractions to {output_file}")

        # Save summary
        summary = {
            'extraction_timestamp': timestamp,
            'total_reports': self.stats['total_reports'],
            'processed': self.stats['processed'],
            'failed': self.stats['failed'],
            'unique_techniques': sorted(list(self.stats['total_techniques'])),
            'unique_techniques_count': len(self.stats['total_techniques']),
            'total_attack_chains': self.stats['total_chains'],
            'unique_actors': sorted(list(self.stats['total_actors'])),
            'unique_actors_count': len(self.stats['total_actors'])
        }

        summary_file = self.output_dir / f"{filename}_summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"Saved summary to {summary_file}")

        return output_file, summary_file

    def generate_causal_relations(self, results: List[ExtractedCTI]) -> List[Dict]:
        """Generate causal relations for graph integration."""
        relations = []

        for extraction in results:
            for chain in extraction.attack_chains:
                if isinstance(chain, dict):
                    chain_data = chain
                else:
                    chain_data = asdict(chain)

                relation = {
                    'source_id': chain_data['from_technique'],
                    'source_name': chain_data['from_technique'],
                    'target_id': chain_data['to_technique'],
                    'target_name': chain_data['to_technique'],
                    'relation_type': 'enables',  # Map to causal graph type
                    'confidence': chain_data.get('confidence', 0.7),
                    'evidence': [
                        chain_data.get('evidence', ''),
                        f"Source: {extraction.report_name}"
                    ],
                    'actors': [chain_data.get('actor')] if chain_data.get('actor') else [],
                    'source_report': extraction.report_name,
                    'source_year': extraction.report_year
                }
                relations.append(relation)

        return relations


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Extract CTI data from reports using LLM")
    parser.add_argument("--reports-dir", default="raw_data/MD_CTI_reports", help="Reports directory")
    parser.add_argument("--output-dir", default="filtered_data/sources/threat_intel", help="Output directory")
    parser.add_argument("--years", type=int, nargs="+", help="Specific years to process")
    parser.add_argument("--limit", type=int, help="Limit number of reports")
    parser.add_argument("--vllm-url", default=VLLM_BASE_URL, help="vLLM server URL")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers (default: 4)")
    parser.add_argument("--sequential", action="store_true", help="Disable parallel processing")

    args = parser.parse_args()

    extractor = CTIReportExtractor(
        reports_dir=args.reports_dir,
        output_dir=args.output_dir,
        vllm_url=args.vllm_url,
        max_workers=args.workers
    )

    # Process reports
    start_time = time.time()
    results = extractor.process_all_reports(
        years=args.years,
        limit=args.limit,
        parallel=not args.sequential
    )
    elapsed = time.time() - start_time

    if results:
        # Save results
        extractor.save_results(results)

        # Generate causal relations
        relations = extractor.generate_causal_relations(results)

        # Save relations for graph integration
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        relations_file = Path(args.output_dir) / f"cti_causal_relations_{timestamp}.json"
        with open(relations_file, 'w') as f:
            json.dump(relations, f, indent=2)
        logger.info(f"Saved {len(relations)} causal relations to {relations_file}")

        # Print summary
        print("\n" + "="*60)
        print("EXTRACTION SUMMARY")
        print("="*60)
        print(f"Reports processed: {extractor.stats['processed']}/{extractor.stats['total_reports']}")
        print(f"Failed: {extractor.stats['failed']}")
        print(f"Unique techniques: {len(extractor.stats['total_techniques'])}")
        print(f"Attack chains: {extractor.stats['total_chains']}")
        print(f"Unique actors: {len(extractor.stats['total_actors'])}")
        print(f"Time elapsed: {elapsed:.1f}s ({elapsed/60:.1f} min)")
        print(f"Avg time/report: {elapsed/len(results):.1f}s")
        print(f"Workers used: {args.workers if not args.sequential else 1}")
    else:
        logger.warning("No results extracted")


if __name__ == "__main__":
    main()
