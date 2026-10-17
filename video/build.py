"""Build the demo video: ElevenLabs narration per scene -> scene timings -> headless Chromium frames -> ffmpeg mux.
Usage: .venv/bin/python video/build.py [--tts eleven|say] [--fps 24] [--voice <id>]"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V = ROOT / "video"
OUT = V / "out"
sys.path.insert(0, str(ROOT))
from piiguard.env import load_dotenv  # noqa: E402

load_dotenv()


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def ffprobe_duration(path: Path) -> float:
    out = run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", str(path)]).stdout
    return float(out.strip())


def tts_eleven(text: str, dest: Path, voice: str, model: str) -> None:
    import httpx
    key = os.environ["ELEVENLABS_API_KEY"]
    import time
    last = None
    for attempt in range(4):
        r = httpx.post(f"https://api.elevenlabs.io/v1/text-to-speech/{voice}", headers={"xi-api-key": key, "accept": "audio/mpeg"},
                       json={"text": text, "model_id": model,
                             "voice_settings": {"stability": 0.55, "similarity_boost": 0.8, "style": 0.25, "use_speaker_boost": True, "speed": 1.12}},
                       timeout=120)
        if r.status_code == 200:
            dest.write_bytes(r.content)
            return
        last = r
        print(f"  tts {r.status_code} on attempt {attempt+1}: {r.text[:160]}", file=sys.stderr)
        time.sleep(2 * (attempt + 1))
    last.raise_for_status()


def tts_say(text: str, dest: Path) -> None:
    aiff = dest.with_suffix(".aiff")
    run(["say", "-v", "Daniel", "-r", "178", "-o", str(aiff), text])
    run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(aiff), str(dest)])
    aiff.unlink()


def pick_voice(preferred: list[str]) -> str:
    import httpx
    r = httpx.get("https://api.elevenlabs.io/v1/voices", headers={"xi-api-key": os.environ["ELEVENLABS_API_KEY"]}, timeout=30)
    r.raise_for_status()
    voices = r.json()["voices"]
    by_name = {v["name"].lower(): v["voice_id"] for v in voices}
    for name in preferred:
        if name.lower() in by_name:
            print(f"voice: {name}", file=sys.stderr)
            return by_name[name.lower()]
    v = voices[0]
    print(f"voice: {v['name']} (fallback)", file=sys.stderr)
    return v["voice_id"]


def captions_for(scenes, timings) -> list[dict]:
    caps, t0 = [], 0.0
    for s, dur in zip(scenes, timings):
        sents = [x.strip() for x in re.split(r"(?<=[.!?:])\s+", s["text"]) if x.strip()]
        # merge very short fragments with the previous sentence so captions do not flicker
        merged = []
        for x in sents:
            if merged and len(x) < 18:
                merged[-1] += " " + x
            else:
                merged.append(x)
        total = sum(len(x) for x in merged)
        speech = dur - 0.35
        t = t0
        for x in merged:
            d = speech * len(x) / total
            caps.append({"start": t, "end": t + d, "text": x})
            t += d
        t0 += dur
    return caps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tts", default="eleven", choices=["eleven", "say"])
    ap.add_argument("--fps", type=int, default=24)
    ap.add_argument("--voice", default=None)
    ap.add_argument("--model", default="eleven_multilingual_v2")
    ap.add_argument("--skip-tts", action="store_true", help="reuse existing out/narr_*.mp3")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    scenes = json.loads((V / "narration.json").read_text())
    data = json.loads((V / "data.json").read_text())

    # 1. narration
    voice = None
    if a.tts == "eleven" and not a.skip_tts:
        voice = a.voice or pick_voice(["Brian", "Daniel", "George", "Adam", "Bill", "Callum"])
    audio_files = []
    for s in scenes:
        f = OUT / f"narr_{s['id']}.mp3"
        if not (a.skip_tts and f.exists()):
            if a.tts == "eleven":
                tts_eleven(s["text"], f, voice, a.model)
            else:
                tts_say(s["text"], f)
        audio_files.append(f)
    timings = []
    for i, f in enumerate(audio_files):
        timings.append(round(ffprobe_duration(f) + (1.6 if i == len(audio_files) - 1 else 0.35), 2))
    total = sum(timings)
    print(f"scene durations: {timings}  total {total:.1f}s", file=sys.stderr)

    # 2. padded audio track
    padded = []
    for f, dur in zip(audio_files, timings):
        w = f.with_suffix(".wav")
        run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(f), "-af", f"apad=whole_dur={dur}", "-t", str(dur), "-ar", "48000", "-ac", "2", str(w)])
        padded.append(w)
    lst = OUT / "audio.txt"
    lst.write_text("".join(f"file '{p.name}'\n" for p in padded))
    run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(lst), "-c", "copy", str(OUT / "audio.wav")], cwd=OUT)

    # 3. frames
    caps = captions_for(scenes, timings)
    frames = OUT / "frames"
    shutil.rmtree(frames, ignore_errors=True)
    frames.mkdir()
    from playwright.sync_api import sync_playwright
    n = int(total * a.fps)
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1920, "height": 1080}, device_scale_factor=1)
        pg.goto((V / "scenes.html").as_uri(), wait_until="networkidle")
        pg.evaluate("([d,t,c]) => setData(d,t,c)", [data, timings, caps])
        pg.wait_for_timeout(300)
        for i in range(n):
            pg.evaluate("t => seek(t)", i / a.fps)
            pg.screenshot(path=str(frames / f"{i:05d}.png"))
            if i % 240 == 0:
                print(f"  frame {i}/{n}", file=sys.stderr)
        b.close()

    # 4. mux
    out = OUT / "piiguard-demo.mp4"
    run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(a.fps), "-i", str(frames / "%05d.png"), "-i", str(OUT / "audio.wav"),
         "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-pix_fmt", "yuv420p", "-r", str(a.fps), "-af", "loudnorm=I=-16:TP=-1.5:LRA=11", "-c:a", "aac", "-b:a", "192k", "-shortest", "-movflags", "+faststart", str(out)])
    print(f"wrote {out} ({out.stat().st_size/1e6:.1f} MB, {total:.1f}s)")


if __name__ == "__main__":
    main()
