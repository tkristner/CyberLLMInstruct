#!/usr/bin/env python3
"""
Domain classifier using vLLM with parallel processing.
Classifies cybersecurity data into specific domains.
"""

import json
import logging
import asyncio
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from vllm_client import VLLMClient, VLLMConfig, check_vllm_health

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CyberDomainClassifierVLLM:
    """Domain classifier using vLLM for parallel LLM inference."""

    def __init__(
        self,
        input_dir: str = "structured_data",
        output_dir: str = "domain_classified",
        vllm_url: str = "http://localhost:8000",
        vllm_model: str = "nemotron",
        max_concurrent: int = 8,
    ):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.vllm_config = VLLMConfig(
            base_url=vllm_url,
            model=vllm_model,
            max_tokens=256,
            temperature=0.3,
            max_concurrent=max_concurrent,
        )

        # Define cybersecurity domains
        self.domains = [
            'malware',
            'phishing',
            'zero_day',
            'iot_security',
            'web_security',
            'network_security',
            'vulnerability_management',
            'cloud_security',
            'cryptography',
            'identity_access_management'
        ]

    async def classify_entry(
        self,
        client: VLLMClient,
        entry: Dict,
        idx: int,
        total: int,
    ) -> Dict:
        """Classify a single entry using vLLM."""
        logger.info(f"Classifying entry {idx + 1}/{total}")

        instruction = entry.get('instruction', '')
        response = entry.get('response', '')

        # Limit content length
        content = f"Instruction: {instruction[:500]}\nResponse: {response[:500]}"

        prompt = f"""Classify this cybersecurity content into one or more of these domains:
{', '.join(self.domains)}

Content:
{content}

Return a JSON array with domain and confidence (0.0-1.0), sorted by confidence descending.
Only include domains with confidence > 0.2.

Example format:
[
    {{"domain": "web_security", "confidence": 0.95}},
    {{"domain": "vulnerability_management", "confidence": 0.75}}
]

JSON response:"""

        result = await client.simple_query_json(
            prompt,
            system_prompt="You are a cybersecurity domain classification expert. Return only valid JSON array.",
            max_tokens=256,
            temperature=0.2,
        )

        if result and isinstance(result, list):
            # Filter valid domains
            valid_classifications = [
                c for c in result
                if isinstance(c, dict)
                and c.get('domain') in self.domains
                and isinstance(c.get('confidence'), (int, float))
                and c.get('confidence', 0) > 0.2
            ]

            # Sort by confidence
            valid_classifications.sort(key=lambda x: x.get('confidence', 0), reverse=True)

            entry['domains'] = valid_classifications
            entry['primary_domain'] = valid_classifications[0]['domain'] if valid_classifications else 'uncategorized'
        else:
            entry['domains'] = []
            entry['primary_domain'] = 'uncategorized'

        return entry

    async def process_file(self, file_path: Path) -> List[Dict]:
        """Process a single file and classify all entries."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return []

        if not isinstance(data, dict) or 'data' not in data:
            logger.warning(f"Invalid data format in {file_path}")
            return []

        entries = data['data']
        total = len(entries)
        logger.info(f"Processing {total} entries from {file_path.name}")

        classified_entries = []

        async with VLLMClient(self.vllm_config) as client:
            # Process entries in batches
            batch_size = self.vllm_config.max_concurrent

            for batch_start in range(0, total, batch_size):
                batch_end = min(batch_start + batch_size, total)
                batch = entries[batch_start:batch_end]

                # Create tasks for batch
                tasks = [
                    self.classify_entry(client, entry, batch_start + i, total)
                    for i, entry in enumerate(batch)
                ]

                # Process batch concurrently
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Error classifying entry: {result}")
                        # Keep entry with uncategorized
                        entry = batch[i]
                        entry['domains'] = []
                        entry['primary_domain'] = 'uncategorized'
                        classified_entries.append(entry)
                    else:
                        classified_entries.append(result)

        return classified_entries

    async def process_directory(self):
        """Process all files in the input directory."""
        # Check vLLM health first
        if not await check_vllm_health(self.vllm_config.base_url):
            logger.error(f"vLLM server not available at {self.vllm_config.base_url}")
            return

        logger.info(f"vLLM server healthy at {self.vllm_config.base_url}")

        all_classified_data = []
        processed_files = 0

        for file_path in self.input_dir.glob('*.json'):
            logger.info(f"\nProcessing {file_path.name}")

            classified_entries = await self.process_file(file_path)

            if classified_entries:
                processed_files += 1
                all_classified_data.extend(classified_entries)

                # Save classified data
                output_data = {
                    'metadata': {
                        'total_entries': len(classified_entries),
                        'classification_timestamp': datetime.now().strftime('%Y%m%d_%H%M%S'),
                        'model_used': self.vllm_config.model
                    },
                    'data': classified_entries
                }

                output_file = self.output_dir / f"{file_path.stem}_classified.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2)

                logger.info(f"Saved to {output_file}")

        # Log statistics
        domain_counts = {}
        for entry in all_classified_data:
            domain = entry.get('primary_domain', 'uncategorized')
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

        logger.info("\n" + "=" * 50)
        logger.info("Classification Statistics:")
        logger.info(f"Processed Files: {processed_files}")
        logger.info(f"Total Entries: {len(all_classified_data)}")
        logger.info("\nDomain Distribution:")

        for domain, count in sorted(domain_counts.items(), key=lambda x: -x[1]):
            if all_classified_data:
                percentage = (count / len(all_classified_data)) * 100
                logger.info(f"  {domain}: {count} entries ({percentage:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Classify cybersecurity data using vLLM")
    parser.add_argument("--input-dir", default="structured_data", help="Input directory")
    parser.add_argument("--output-dir", default="domain_classified", help="Output directory")
    parser.add_argument("--vllm-url", default="http://localhost:8000", help="vLLM server URL")
    parser.add_argument("--vllm-model", default="nemotron", help="vLLM model name")
    parser.add_argument("--max-concurrent", type=int, default=8, help="Max concurrent requests")

    args = parser.parse_args()

    classifier = CyberDomainClassifierVLLM(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        vllm_url=args.vllm_url,
        vllm_model=args.vllm_model,
        max_concurrent=args.max_concurrent,
    )

    asyncio.run(classifier.process_directory())


if __name__ == "__main__":
    main()
