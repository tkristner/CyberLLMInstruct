#!/usr/bin/env python3
"""
Benchmark vLLM to find optimal concurrency level.
"""

import asyncio
import aiohttp
import time
import argparse
from statistics import mean, stdev

async def single_request(session, url, model, prompt, semaphore):
    """Make a single request and return latency."""
    async with semaphore:
        start = time.perf_counter()
        try:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 50,
                "temperature": 0.1,
            }
            async with session.post(f"{url}/v1/chat/completions", json=payload) as resp:
                if resp.status == 200:
                    await resp.json()
                    latency = time.perf_counter() - start
                    return latency, None
                else:
                    return None, f"HTTP {resp.status}"
        except Exception as e:
            return None, str(e)

async def benchmark_concurrency(url, model, concurrency, num_requests=50):
    """Benchmark a specific concurrency level."""
    prompt = "Is this related to cybersecurity? Answer YES or NO: CVE-2024-1234 buffer overflow vulnerability"

    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency + 10)

    async with aiohttp.ClientSession(connector=connector) as session:
        start_time = time.perf_counter()

        tasks = [
            single_request(session, url, model, prompt, semaphore)
            for _ in range(num_requests)
        ]

        results = await asyncio.gather(*tasks)

        total_time = time.perf_counter() - start_time

    latencies = [r[0] for r in results if r[0] is not None]
    errors = [r[1] for r in results if r[1] is not None]

    if latencies:
        return {
            'concurrency': concurrency,
            'num_requests': num_requests,
            'successful': len(latencies),
            'errors': len(errors),
            'total_time': total_time,
            'throughput': len(latencies) / total_time,
            'avg_latency': mean(latencies),
            'min_latency': min(latencies),
            'max_latency': max(latencies),
            'std_latency': stdev(latencies) if len(latencies) > 1 else 0,
        }
    else:
        return {
            'concurrency': concurrency,
            'errors': len(errors),
            'error_sample': errors[:3] if errors else None
        }

async def run_benchmark(url, model, concurrency_levels, num_requests):
    """Run benchmark across different concurrency levels."""
    print(f"\n{'='*70}")
    print(f"vLLM Benchmark - {url} - Model: {model}")
    print(f"Requests per test: {num_requests}")
    print(f"{'='*70}\n")

    results = []

    for conc in concurrency_levels:
        print(f"Testing concurrency={conc}...", end=" ", flush=True)
        result = await benchmark_concurrency(url, model, conc, num_requests)
        results.append(result)

        if 'throughput' in result:
            print(f"✓ {result['throughput']:.1f} req/s, "
                  f"latency: {result['avg_latency']*1000:.0f}ms avg, "
                  f"errors: {result['errors']}")
        else:
            print(f"✗ Failed - {result.get('error_sample', 'Unknown error')}")

        # Small delay between tests
        await asyncio.sleep(2)

    # Summary
    print(f"\n{'='*70}")
    print("RESULTS SUMMARY")
    print(f"{'='*70}")
    print(f"{'Conc':>6} | {'Throughput':>12} | {'Avg Lat':>10} | {'Min Lat':>10} | {'Max Lat':>10} | {'Errors':>6}")
    print(f"{'-'*6}-+-{'-'*12}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}-+-{'-'*6}")

    best_throughput = 0
    best_conc = 0

    for r in results:
        if 'throughput' in r:
            print(f"{r['concurrency']:>6} | {r['throughput']:>10.2f}/s | "
                  f"{r['avg_latency']*1000:>8.0f}ms | {r['min_latency']*1000:>8.0f}ms | "
                  f"{r['max_latency']*1000:>8.0f}ms | {r['errors']:>6}")
            if r['throughput'] > best_throughput and r['errors'] == 0:
                best_throughput = r['throughput']
                best_conc = r['concurrency']
        else:
            print(f"{r['concurrency']:>6} | {'FAILED':>12} | {'-':>10} | {'-':>10} | {'-':>10} | {r['errors']:>6}")

    print(f"\n{'='*70}")
    print(f"RECOMMENDATION: Use --max-concurrent {best_conc}")
    print(f"  → Throughput: {best_throughput:.1f} requests/second")
    print(f"{'='*70}\n")

    return results

def main():
    parser = argparse.ArgumentParser(description="Benchmark vLLM concurrency")
    parser.add_argument("--url", default="http://localhost:5000", help="vLLM server URL")
    parser.add_argument("--model", default="nemotron", help="Model name")
    parser.add_argument("--requests", type=int, default=50, help="Requests per test")
    parser.add_argument("--levels", type=str, default="1,2,4,8,16,32,48,64",
                        help="Concurrency levels to test (comma-separated)")

    args = parser.parse_args()

    concurrency_levels = [int(x) for x in args.levels.split(",")]

    asyncio.run(run_benchmark(args.url, args.model, concurrency_levels, args.requests))

if __name__ == "__main__":
    main()
