#!/usr/bin/env python3
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic_replay import (
    Recorder, RecordingMode,
    Player, PlaybackMode,
    RequestStorage,
    MaskingEngine,
    ContextManager,
)


async def quick_start():
    print("=" * 50)
    print("Traffic Replay - Quick Start")
    print("=" * 50)

    storage = RequestStorage(base_dir="./quick_start_data")

    print("\n1. Initialize components...")
    masking_engine = MaskingEngine(preserve_structure=True)
    context_manager = ContextManager(enable_auto_extract=True)

    print("\n2. Start recorder (pointing to your API)...")
    recorder = Recorder(
        target_url="http://your-production-api.com",
        storage=storage,
        masking_engine=masking_engine,
        mode=RecordingMode.TAP,
        listen_port=8080,
    )
    await recorder.start()
    print("   Recorder running on http://localhost:8080")
    print("   Send traffic to this address to record")

    await asyncio.sleep(2)

    print("\n3. Stop recorder...")
    session_id = storage._session_id
    await recorder.stop()

    print(f"\n4. Start playback (to test environment)...")
    player = Player(
        target_url="http://your-test-api.com",
        storage=storage,
        context_manager=context_manager,
        mode=PlaybackMode.PRECISE_TIMING,
    )

    print(f"   Playing back session: {session_id}")
    report = await player.play(session_id=session_id)

    print(f"\n5. Results:")
    print(f"   Success: {report.successful_requests}/{report.total_requests}")
    print(f"   Avg latency: {report.avg_latency_ms:.2f}ms")
    print(f"   P95 latency: {report.p95_latency_ms:.2f}ms")

    print("\nDone!")


if __name__ == "__main__":
    asyncio.run(quick_start())
