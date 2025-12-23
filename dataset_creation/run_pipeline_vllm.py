#!/usr/bin/env python3
"""
Complete CyberLLMInstruct pipeline using vLLM.
Runs all stages in sequence with parallel LLM processing.
"""

import asyncio
import argparse
import logging
import subprocess
import sys
from pathlib import Path
from datetime import datetime

from vllm_client import check_vllm_health, get_vllm_models

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def run_pipeline(
    vllm_url: str = "http://localhost:8000",
    vllm_model: str = "nemotron",
    max_concurrent: int = 8,
    skip_collection: bool = False,
    skip_review: bool = True,
):
    """Run the complete pipeline."""

    start_time = datetime.now()
    logger.info("=" * 60)
    logger.info("CyberLLMInstruct Pipeline (vLLM Edition)")
    logger.info("=" * 60)

    # Check vLLM server
    logger.info("\n[0/7] Checking vLLM server...")
    if not await check_vllm_health(vllm_url):
        logger.error(f"vLLM server not available at {vllm_url}")
        logger.error("Start vLLM with: vllm serve <model> --host 0.0.0.0 --port 8000")
        return False

    models = await get_vllm_models(vllm_url)
    logger.info(f"Available models: {models}")

    if vllm_model not in models:
        logger.warning(f"Model '{vllm_model}' not in available models. Using first available.")
        if models:
            vllm_model = models[0]
        else:
            logger.error("No models available on vLLM server")
            return False

    logger.info(f"Using model: {vllm_model}")

    base_dir = Path(__file__).parent

    # Stage 1: Data Collection
    if not skip_collection:
        logger.info("\n[1/7] Data Collection...")
        result = subprocess.run(
            [sys.executable, str(base_dir / "1_data_collector.py")],
            cwd=str(base_dir)
        )
        if result.returncode != 0:
            logger.error("Data collection failed")
            return False
    else:
        logger.info("\n[1/7] Skipping data collection (--skip-collection)")

    # Stage 2: Data Filtering
    logger.info("\n[2/7] Data Filtering...")
    result = subprocess.run(
        [
            sys.executable, str(base_dir / "2_data_filter_vllm.py"),
            "--vllm-url", vllm_url,
            "--vllm-model", vllm_model,
            "--max-concurrent", str(max_concurrent),
        ],
        cwd=str(base_dir)
    )
    if result.returncode != 0:
        logger.error("Data filtering failed")
        return False

    # Stage 3: Data Structuring
    logger.info("\n[3/7] Data Structuring...")
    result = subprocess.run(
        [
            sys.executable, str(base_dir / "3_data_structurer_vllm.py"),
            "--vllm-url", vllm_url,
            "--vllm-model", vllm_model,
            "--max-concurrent", str(max_concurrent),
        ],
        cwd=str(base_dir)
    )
    if result.returncode != 0:
        logger.error("Data structuring failed")
        return False

    # Stage 4: Domain Classification
    logger.info("\n[4/7] Domain Classification...")
    result = subprocess.run(
        [
            sys.executable, str(base_dir / "4_domain_classifier_vllm.py"),
            "--vllm-url", vllm_url,
            "--vllm-model", vllm_model,
            "--max-concurrent", str(max_concurrent),
        ],
        cwd=str(base_dir)
    )
    if result.returncode != 0:
        logger.error("Domain classification failed")
        return False

    # Stage 5: Manual Review (optional)
    if not skip_review:
        logger.info("\n[5/7] Manual Review...")
        logger.info("Run manually: python 5_manual_reviewer.py")
        logger.info("Skipping automatic execution (requires interactive input)")
    else:
        logger.info("\n[5/7] Skipping manual review (--skip-review)")
        # Copy classified data to reviewed_data for next stage
        import shutil
        classified_dir = base_dir / "domain_classified"
        reviewed_dir = base_dir / "reviewed_data"
        reviewed_dir.mkdir(exist_ok=True)

        for f in classified_dir.glob("*.json"):
            shutil.copy(f, reviewed_dir / f.name)
            logger.info(f"Copied {f.name} to reviewed_data/")

    # Stage 6: Security Alignment
    logger.info("\n[6/7] Security Alignment...")
    result = subprocess.run(
        [
            sys.executable, str(base_dir / "6_security_aligner_vllm.py"),
            "--vllm-url", vllm_url,
            "--vllm-model", vllm_model,
            "--max-concurrent", str(max_concurrent),
        ],
        cwd=str(base_dir)
    )
    if result.returncode != 0:
        logger.error("Security alignment failed")
        return False

    # Stage 7: Final Assembly
    logger.info("\n[7/7] Final Assembly...")
    result = subprocess.run(
        [sys.executable, str(base_dir / "8_final_assembler.py")],
        cwd=str(base_dir)
    )
    if result.returncode != 0:
        logger.error("Final assembly failed")
        return False

    end_time = datetime.now()
    duration = end_time - start_time

    logger.info("\n" + "=" * 60)
    logger.info("Pipeline Complete!")
    logger.info(f"Total duration: {duration}")
    logger.info("=" * 60)

    # Show output files
    final_dir = base_dir / "final_dataset"
    if final_dir.exists():
        logger.info("\nOutput files:")
        for f in final_dir.glob("*"):
            size_mb = f.stat().st_size / (1024 * 1024)
            logger.info(f"  {f.name} ({size_mb:.2f} MB)")

    return True


def main():
    parser = argparse.ArgumentParser(description="Run CyberLLMInstruct pipeline with vLLM")
    parser.add_argument("--vllm-url", default="http://localhost:8000", help="vLLM server URL")
    parser.add_argument("--vllm-model", default="nemotron", help="vLLM model name")
    parser.add_argument("--max-concurrent", type=int, default=8, help="Max concurrent requests")
    parser.add_argument("--skip-collection", action="store_true", help="Skip data collection stage")
    parser.add_argument("--skip-review", action="store_true", default=True, help="Skip manual review stage")

    args = parser.parse_args()

    success = asyncio.run(run_pipeline(
        vllm_url=args.vllm_url,
        vllm_model=args.vllm_model,
        max_concurrent=args.max_concurrent,
        skip_collection=args.skip_collection,
        skip_review=args.skip_review,
    ))

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
