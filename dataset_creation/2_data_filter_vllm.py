#!/usr/bin/env python3
"""
Data filter using vLLM with parallel processing.
Filters cybersecurity data using LLM-based relevance assessment.
"""

import json
import logging
import yaml
import pandas as pd
import asyncio
import argparse
from pathlib import Path
from typing import Dict, List, Union, Tuple
from datetime import datetime
from dataclasses import dataclass

from vllm_client import VLLMClient, VLLMConfig, check_vllm_health

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class FilterConfig:
    """Configuration for data filtering."""
    input_dir: str = "raw_data"
    output_dir: str = "filtered_data"
    vllm_url: str = "http://localhost:8000"
    vllm_model: str = "nemotron"
    max_concurrent: int = 8
    min_content_length: int = 50
    enable_thinking: bool = True
    reasoning_budget: int = 128


class CyberDataFilterVLLM:
    """Data filter using vLLM for parallel LLM inference."""

    def __init__(self, config: FilterConfig):
        self.config = config
        self.input_dir = Path(config.input_dir)
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.vllm_config = VLLMConfig(
            base_url=config.vllm_url,
            model=config.vllm_model,
            max_tokens=1024 + config.reasoning_budget,  # Response + reasoning budget
            temperature=0.2,
            max_concurrent=config.max_concurrent,
            enable_thinking=config.enable_thinking,
            reasoning_budget=config.reasoning_budget,
        )

        # Keywords for rule-based fallback
        self.cybersecurity_keywords = {
            'high_relevance': {
                'vulnerability', 'exploit', 'malware', 'ransomware', 'cyber', 'security',
                'attack', 'threat', 'breach', 'CVE-', 'patch', 'authentication', 'authorization',
                'encryption', 'cryptography', 'backdoor', 'botnet', 'phishing', 'injection',
                'zero-day', '0day', 'penetration', 'pentest', 'firewall', 'malicious'
            },
            'medium_relevance': {
                'network', 'system', 'software', 'hardware', 'protocol', 'server',
                'client', 'database', 'web', 'application', 'code', 'programming',
                'access', 'control', 'monitoring', 'detection', 'response', 'incident'
            }
        }

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

    def is_relevant_rule_based(self, text: str) -> bool:
        """Rule-based relevance check as fallback."""
        if len(text) < self.config.min_content_length:
            return False

        text_lower = text.lower()
        high_matches = sum(1 for kw in self.cybersecurity_keywords['high_relevance']
                          if kw.lower() in text_lower)
        medium_matches = sum(1 for kw in self.cybersecurity_keywords['medium_relevance']
                            if kw.lower() in text_lower)

        return (high_matches * 2 + medium_matches) >= 2

    def get_entry_text(self, entry: Union[Dict, str]) -> str:
        """Extract text content from an entry."""
        # Handle string entries (e.g., phishing URLs)
        if isinstance(entry, str):
            return entry

        text_parts = []
        for key, value in entry.items():
            if isinstance(value, str):
                text_parts.append(value)
            elif isinstance(value, (dict, list)):
                text_parts.append(str(value))
        return ' '.join(text_parts)

    async def assess_relevance(self, client: VLLMClient, entry: Dict) -> Tuple[bool, str]:
        """Assess if an entry is relevant to cybersecurity."""
        text = self.get_entry_text(entry)

        if len(text) < self.config.min_content_length:
            return False, "Content too short"

        # Limit content length for LLM
        text_limited = text[:1000]

        prompt = f"""Is this text related to cybersecurity? Answer with only YES or NO.

Text: {text_limited}

Answer:"""

        response = await client.simple_query(
            prompt,
            system_prompt="You are a cybersecurity expert. Determine if text is related to cybersecurity.",
            max_tokens=10,
            temperature=0.1,
        )

        if response:
            response_upper = response.upper().strip()
            if "YES" in response_upper:
                return True, "LLM: relevant"
            elif "NO" in response_upper:
                return False, "LLM: not relevant"

        # Fallback to rule-based
        if self.is_relevant_rule_based(text):
            return True, "Rule-based: relevant"
        return False, "Rule-based: not relevant"

    async def enhance_entry(self, client: VLLMClient, entry: Dict) -> Dict:
        """Enhance an entry with additional cybersecurity context."""
        text = self.get_entry_text(entry)

        if len(text) > 1500 or len(text) < 50:
            return entry

        text_limited = text[:1000]

        prompt = f"""Analyze this cybersecurity information and create a JSON with these fields:
- description: Brief technical description (1-2 sentences)
- risk_level: Critical, High, Medium, or Low
- affected_systems: Array of affected system types
- mitigations: Main recommendation (1 sentence)

Content: {text_limited}

Return only valid JSON:"""

        result = await client.simple_query_json(
            prompt,
            system_prompt="You are a cybersecurity analyst. Analyze content and return structured JSON.",
            max_tokens=256,
            temperature=0.3,
        )

        if result and isinstance(result, dict):
            entry["enhanced"] = result
        return entry

    async def process_entry(self, client: VLLMClient, entry: Union[Dict, str], idx: int, total: int) -> Tuple[Union[Dict, str], bool, str]:
        """Process a single entry: assess relevance and enhance if relevant."""
        logger.info(f"Processing entry {idx + 1}/{total}")

        is_relevant, reason = await self.assess_relevance(client, entry)

        # Only enhance dict entries
        if is_relevant and isinstance(entry, dict):
            entry = await self.enhance_entry(client, entry)

        return entry, is_relevant, reason

    async def filter_file(self, file_path: Path) -> Tuple[List[Dict], List[Dict]]:
        """Filter a single file."""
        data = self.load_data(file_path)
        if not data:
            return [], []

        # Handle different data formats - extract nested lists
        if isinstance(data, dict):
            # Known keys that contain the actual data lists
            nested_keys = [
                'vulnerabilities',  # NVD CVE
                'entries',          # RSS feeds (Ubuntu, RedHat, etc.) + LOLBAS/LOLDrivers/HijackLibs
                'pulses',           # AlienVault OTX
                'iocs',             # ThreatFox
                'data',             # Generic
                'objects',          # MITRE ATT&CK STIX
                'samples',          # MalwareBazaar
                'advisories',       # GitHub Security
                'results',          # Generic API responses
                'items',            # Generic
                'cves',             # OpenCVE (alternative)
                'summary',          # OpenCVE
                'Attack_Patterns',  # CAPEC
                'ctftime_events',   # CTFTime events
                'phishing_urls',    # PhishTank/OpenPhish
                'papers',           # ArXiv papers
                'value',            # Microsoft Security Updates
                'controls',         # NIST SP 800-53
                'requirements',     # NIST SP 800-171
                'functions',        # NIST CSF 2.0
                'practice_groups',  # NIST SSDF
                'techniques',       # MITRE ATT&CK ICS
                'cheatsheets',      # OWASP Cheat Sheets
                'mapping_objects',  # NIST to ATT&CK mapping
                'framework_data',   # OSINT Framework (tree structure)
            ]

            extracted = False

            # Special handling for OSCAL catalog format (CIS Controls, some NIST)
            if 'catalog' in data:
                catalog = data['catalog']
                groups = catalog.get('groups', [])
                if groups:
                    # Flatten controls from all groups
                    all_controls = []
                    for group in groups:
                        controls = group.get('controls', [])
                        for control in controls:
                            # Add group context to each control
                            control['_group_id'] = group.get('id', '')
                            control['_group_title'] = group.get('title', '')
                            all_controls.append(control)
                            # Also extract nested controls (safeguards)
                            for subcontrol in control.get('controls', []):
                                subcontrol['_group_id'] = group.get('id', '')
                                subcontrol['_group_title'] = group.get('title', '')
                                subcontrol['_parent_id'] = control.get('id', '')
                                subcontrol['_parent_title'] = control.get('title', '')
                                all_controls.append(subcontrol)
                    if all_controls:
                        logger.info(f"Extracting {len(all_controls)} controls from OSCAL catalog")
                        data = all_controls
                        extracted = True

            # Special handling for OSINT Framework (tree structure with children[])
            if not extracted and 'framework_data' in data:
                def extract_osint_tools(node, category_path=None):
                    """Recursively extract tools from OSINT Framework tree."""
                    tools = []
                    if category_path is None:
                        category_path = []

                    if isinstance(node, dict):
                        name = node.get('name', '')
                        current_path = category_path + [name] if name else category_path

                        # If it's a leaf node with URL, it's a tool
                        if node.get('type') == 'url' or (node.get('url') and not node.get('children')):
                            tool_entry = {
                                'name': name,
                                'url': node.get('url', ''),
                                'type': node.get('type', 'url'),
                                '_category_path': ' > '.join(current_path[:-1]) if len(current_path) > 1 else 'Root',
                                '_category': current_path[-2] if len(current_path) > 1 else 'Root',
                            }
                            tools.append(tool_entry)

                        # Recurse into children
                        for child in node.get('children', []):
                            tools.extend(extract_osint_tools(child, current_path))

                    elif isinstance(node, list):
                        for item in node:
                            tools.extend(extract_osint_tools(item, category_path))

                    return tools

                framework_tree = data['framework_data']
                all_tools = extract_osint_tools(framework_tree)
                if all_tools:
                    logger.info(f"Extracting {len(all_tools)} tools from OSINT Framework tree")
                    data = all_tools
                    extracted = True

            if not extracted:
                for key in nested_keys:
                    if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                        logger.info(f"Extracting {len(data[key])} items from '{key}' key")
                        data = data[key]
                        extracted = True
                        break

            if not extracted:
                # If no known key found, wrap in list
                data = [data]

        logger.info(f"Processing {len(data)} entries from {file_path.name}")

        relevant_entries = []
        filtered_entries = []

        async with VLLMClient(self.vllm_config) as client:
            # Process entries in batches for better progress tracking
            batch_size = self.vllm_config.max_concurrent
            total = len(data)

            for batch_start in range(0, total, batch_size):
                batch_end = min(batch_start + batch_size, total)
                batch = data[batch_start:batch_end]

                # Create tasks for batch
                tasks = [
                    self.process_entry(client, entry, batch_start + i, total)
                    for i, entry in enumerate(batch)
                ]

                # Process batch concurrently
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Error processing entry: {result}")
                        # Keep entry with error flag
                        entry = batch[i]
                        if isinstance(entry, dict):
                            entry['filter_error'] = str(result)
                            filtered_entries.append(entry)
                        else:
                            # String entries (e.g., URLs) - wrap in dict
                            filtered_entries.append({'value': entry, 'filter_error': str(result)})
                    else:
                        entry, is_relevant, reason = result
                        if is_relevant:
                            relevant_entries.append(entry)
                        else:
                            if isinstance(entry, dict):
                                entry['filtered_reason'] = reason
                                filtered_entries.append(entry)
                            else:
                                filtered_entries.append({'value': entry, 'filtered_reason': reason})

        logger.info(f"Filtered {file_path.name}: {len(relevant_entries)} relevant, {len(filtered_entries)} filtered")
        return relevant_entries, filtered_entries

    def save_filtered_data(self, data: List[Dict], original_file: Path, suffix: str = '') -> bool:
        """Save filtered data. Removed entries go to 'removed/' subdirectory."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            # Save removed entries to subdirectory for cleaner organization
            if '_removed' in suffix:
                removed_dir = self.output_dir / "removed"
                removed_dir.mkdir(parents=True, exist_ok=True)
                output_file = removed_dir / f"{original_file.stem}{suffix}_{timestamp}.json"
            else:
                output_file = self.output_dir / f"{original_file.stem}{suffix}_{timestamp}.json"

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return False

    async def process_directory(self, limit: int = None):
        """Process all files in the input directory."""
        # Check vLLM health first
        if not await check_vllm_health(self.config.vllm_url):
            logger.error(f"vLLM server not available at {self.config.vllm_url}")
            return

        logger.info(f"vLLM server healthy at {self.config.vllm_url}")

        total_stats = {
            'processed_files': 0,
            'total_entries': 0,
            'retained_entries': 0,
            'filtered_entries': 0
        }

        files_to_process = list(self.input_dir.glob('*.*'))
        files_to_process = [f for f in files_to_process
                          if f.suffix.lower() in {'.json', '.yaml', '.yml', '.csv'}]

        if limit and limit > 0:
            files_to_process = files_to_process[:limit]

        logger.info(f"Processing {len(files_to_process)} files")

        for file_path in files_to_process:
            # Skip if already processed (check for existing output)
            existing_outputs = list(self.output_dir.glob(f"{file_path.stem}_filtered_*.json"))
            if existing_outputs:
                logger.info(f"\nSkipping {file_path.name} (already processed)")
                continue

            logger.info(f"\nProcessing {file_path.name}")

            relevant_entries, filtered_entries = await self.filter_file(file_path)

            if relevant_entries or filtered_entries:
                total_stats['processed_files'] += 1
                total_stats['total_entries'] += len(relevant_entries) + len(filtered_entries)
                total_stats['retained_entries'] += len(relevant_entries)
                total_stats['filtered_entries'] += len(filtered_entries)

                if relevant_entries:
                    self.save_filtered_data(relevant_entries, file_path, '_filtered')
                if filtered_entries:
                    self.save_filtered_data(filtered_entries, file_path, '_removed')

        # Log statistics
        logger.info("\n" + "=" * 50)
        logger.info("Filtering Statistics:")
        logger.info(f"Processed Files: {total_stats['processed_files']}")
        logger.info(f"Total Entries: {total_stats['total_entries']}")
        logger.info(f"Retained Entries: {total_stats['retained_entries']}")
        logger.info(f"Filtered Entries: {total_stats['filtered_entries']}")

        if total_stats['total_entries'] > 0:
            retention_rate = (total_stats['retained_entries'] / total_stats['total_entries'] * 100)
            logger.info(f"Retention Rate: {retention_rate:.2f}%")


def main():
    parser = argparse.ArgumentParser(description="Filter cybersecurity data using vLLM")
    parser.add_argument("--input-dir", default="raw_data", help="Input directory")
    parser.add_argument("--output-dir", default="filtered_data", help="Output directory")
    parser.add_argument("--vllm-url", default="http://localhost:8000", help="vLLM server URL")
    parser.add_argument("--vllm-model", default="nemotron", help="vLLM model name")
    parser.add_argument("--max-concurrent", type=int, default=8, help="Max concurrent requests")
    parser.add_argument("--limit", type=int, default=0, help="Limit files to process (0 = no limit)")
    parser.add_argument("--reasoning-budget", type=int, default=128, help="Limit reasoning tokens (default: 128)")
    parser.add_argument("--no-thinking", action="store_true", help="Disable reasoning completely")

    args = parser.parse_args()

    config = FilterConfig(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        vllm_url=args.vllm_url,
        vllm_model=args.vllm_model,
        max_concurrent=args.max_concurrent,
        enable_thinking=not args.no_thinking,
        reasoning_budget=args.reasoning_budget,
    )

    filter_instance = CyberDataFilterVLLM(config)
    limit = args.limit if args.limit > 0 else None
    asyncio.run(filter_instance.process_directory(limit))


if __name__ == "__main__":
    main()
