import asyncio
import json
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


PACKET_DIR = os.environ.get("PACKET_DIR", "/data/packets")
MAX_QUEUE_SIZE = 10000

write_queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
counter = {"seq": 0}


async def file_writer():
    """Background worker that drains the queue and writes packets to disk in order."""
    while True:
        batch = []
        # Wait for at least one item
        item = await write_queue.get()
        batch.append(item)

        # Drain up to 100 more without waiting (batch writes)
        for _ in range(100):
            try:
                item = write_queue.get_nowait()
                batch.append(item)
            except asyncio.QueueEmpty:
                break

        # Write batch to disk
        for seq, data in batch:
            filename = "{:08d}_{}.json".format(seq, int(time.time() * 1000))
            filepath = os.path.join(PACKET_DIR, filename)
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            except Exception as e:
                print("[!] Write failed {}: {}".format(filepath, e))

        # Mark all as done
        for _ in batch:
            write_queue.task_done()


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(PACKET_DIR, exist_ok=True)

    # Restore counter from existing files
    existing = [f for f in os.listdir(PACKET_DIR) if f.endswith(".json")]
    if existing:
        max_seq = max(int(f.split("_")[0]) for f in existing)
        counter["seq"] = max_seq
        print("[*] Restored sequence counter to {}".format(max_seq))

    writer_task = asyncio.create_task(file_writer())
    print("[*] CollectServer started — saving to {}".format(PACKET_DIR))
    yield
    writer_task.cancel()


app = FastAPI(lifespan=lifespan)


@app.post("/forward")
async def forward(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid json"})

    counter["seq"] += 1
    seq = counter["seq"]

    try:
        write_queue.put_nowait((seq, data))
    except asyncio.QueueFull:
        return JSONResponse(status_code=503, content={"error": "queue full"})

    return JSONResponse(
        status_code=200,
        content={"status": "queued", "seq": seq}
    )


@app.get("/stats")
async def stats():
    files = [f for f in os.listdir(PACKET_DIR) if f.endswith(".json")]
    return {
        "total_saved": len(files),
        "queue_pending": write_queue.qsize(),
        "current_seq": counter["seq"]
    }
