#!/usr/bin/env python3
"""
ai_bridge.py — host-side half of the AlphaOS "ai" shell command.

AlphaOS has no network/TLS stack (it's a bare-metal freestanding
kernel), so it cannot call the Claude API itself. This script runs on
the host, holds the real API key, and speaks a small text protocol to
the guest over a second serial port (COM2) that `make run-ai` exposes
as a Unix socket.

SAFETY MODEL — read this before running against a real API key.

The guest kernel (kernel/ai.c) only ever *sends* one of five fixed
tool names: list_files, read_pe_info, mem_stats, pci_list, run_exe.
There is no "write file", "delete", "format", "shutdown", or "run
arbitrary code" opcode in the guest's protocol handler at all — not
disabled, structurally absent. This script mirrors that allowlist and
adds independent layers on top of it:

  - run_exe is refused locally (never even sent to the guest) unless
    you pass --allow-run.
  - even with --allow-run, every run_exe call requires an interactive
    y/N confirmation typed into *this* terminal before it is forwarded
    — a human is in the loop for the one tool with a real side effect.
  - a hard cap on tool-call round trips per question (--max-turns),
    independent of the guest's own backstop.
  - every tool call and its result is logged to stdout.
  - the ramdisk AlphaOS runs against is read-only at runtime, so even
    an approved run_exe can only launch a binary that was already
    baked into the OS image at build time.

usage:
  export ANTHROPIC_API_KEY=sk-ant-...
  python3 tools/ai_bridge.py --socket build/aichan.sock
  python3 tools/ai_bridge.py --socket build/aichan.sock --allow-run
  python3 tools/ai_bridge.py --socket build/aichan.sock --mock   # no
      network call at all; exercises the guest<->host protocol with a
      canned responder, for testing the transport without credentials
"""
import argparse
import json
import os
import socket
import sys
import time
import urllib.request
import urllib.error

DEFAULT_MODEL = "claude-sonnet-5"
API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"

SYSTEM_PROMPT = """\
You are a read-only diagnostic assistant embedded in AlphaOS, a small \
hobby operating system. You can inspect the machine through a handful \
of tools, all backed by real kernel calls on the running VM.

Ground rules:
- Prefer inspecting over acting. list_files, read_pe_info, mem_stats, \
and pci_list are always safe and side-effect free — use them freely.
- run_exe actually executes a program on the VM. Only call it when the \
user clearly asked you to run something, and say what you're about to \
run and why before calling it.
- You cannot write, delete, or modify anything — there is no tool for \
that, by design. Don't imply you can.
- Be concise. This is a serial console, not a chat window.
"""

TOOLS = [
    {
        "name": "list_files",
        "description": "List every file on AlphaOS's read-only ramdisk, with sizes.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_pe_info",
        "description": "Dump the PE headers (machine, sections, imports) of one file on the ramdisk.",
        "input_schema": {
            "type": "object",
            "properties": {"filename": {"type": "string"}},
            "required": ["filename"],
        },
    },
    {
        "name": "mem_stats",
        "description": "Physical memory, kernel heap, and uptime statistics.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "pci_list",
        "description": "List devices AlphaOS found on the PCI bus.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_exe",
        "description": "Execute a .exe already present on the ramdisk. Has a real "
                       "effect on the VM; only call this when asked to run something.",
        "input_schema": {
            "type": "object",
            "properties": {"filename": {"type": "string"}},
            "required": ["filename"],
        },
    },
]

ALLOWLIST = {t["name"] for t in TOOLS}


class GuestLink:
    """Line-oriented protocol over the COM2 Unix socket."""

    def __init__(self, path, connect_timeout=30):
        deadline = time.time() + connect_timeout
        last_err = None
        while time.time() < deadline:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(path)
                self.buf = b""
                return
            except OSError as e:
                last_err = e
                time.sleep(0.5)
        raise SystemExit(f"could not connect to {path}: {last_err}\n"
                          f"(is `make run-ai` running?)")

    def send(self, line: str):
        self.sock.sendall((line + "\n").encode())

    def readline(self, timeout=90) -> str:
        self.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise SystemExit("guest closed the connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode(errors="replace").rstrip("\r")

    def read_result_block(self, timeout=90) -> str:
        lines = []
        while True:
            line = self.readline(timeout)
            if line == "RESULT_END":
                return "\n".join(lines)
            if line.startswith("RESULT: "):
                lines.append(line[8:])


def log(msg):
    print(f"[bridge] {msg}", flush=True)


def call_claude(api_key, model, messages):
    body = json.dumps({
        "model": model,
        "max_tokens": 1024,
        "system": SYSTEM_PROMPT,
        "tools": TOOLS,
        "messages": messages,
    }).encode()
    req = urllib.request.Request(API_URL, data=body, method="POST", headers={
        "content-type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": API_VERSION,
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise SystemExit(f"Claude API error {e.code}: {detail}")


class MockModel:
    """Deterministic stand-in for the real API: exercises the full
    guest<->host protocol without network access or credentials, so the
    transport (and the safety gates) can be verified without a live key."""

    def __init__(self, scenario="list_files"):
        self.step = 0
        self.scenario = scenario

    def respond(self, messages):
        self.step += 1
        if self.step == 1:
            if self.scenario == "run_exe":
                return {"stop_reason": "tool_use", "content": [
                    {"type": "text", "text": "I'll run crash.exe to see what happens."},
                    {"type": "tool_use", "id": "mock1", "name": "run_exe",
                     "input": {"filename": "crash.exe"}},
                ]}
            return {"stop_reason": "tool_use", "content": [
                {"type": "text", "text": "Let me check what's on the ramdisk."},
                {"type": "tool_use", "id": "mock1", "name": "list_files", "input": {}},
            ]}
        return {"stop_reason": "end_turn", "content": [
            {"type": "text",
             "text": "(mock) done — see the tool result above; the real "
                     "bridge would summarize it via the Claude API here."},
        ]}


def run_turn(link: GuestLink, api_key, model, question, max_turns, allow_run,
            mock):
    messages = [{"role": "user", "content": question}]
    mock_model = MockModel(scenario=mock) if mock else None

    for turn in range(max_turns):
        log(f"calling model (turn {turn + 1}/{max_turns})...")
        resp = mock_model.respond(messages) if mock else \
            call_claude(api_key, model, messages)

        content = resp.get("content", [])
        text_parts = [b["text"] for b in content if b["type"] == "text"]
        tool_uses = [b for b in content if b["type"] == "tool_use"]

        for t in text_parts:
            log(f"model says: {t}")
            link.send(f"SAY: {t}")
        if text_parts:
            link.send("SAY_END")

        if not tool_uses:
            link.send("DONE")
            return

        messages.append({"role": "assistant", "content": content})
        tool_results = []
        for call in tool_uses:
            name = call["name"]
            arg = call.get("input", {}).get("filename", "")

            if name not in ALLOWLIST:
                # Should be structurally impossible (TOOLS defines the
                # only names the model can emit) but never trust that
                # alone — refuse locally, never contact the guest.
                result = f"error: {name} is not allowlisted"
                log(f"REFUSED (not allowlisted): {name}")
            elif name == "run_exe" and not allow_run:
                result = ("run_exe is disabled on this bridge; the operator "
                          "did not pass --allow-run")
                log(f"REFUSED (--allow-run not set): run_exe {arg}")
            elif name == "run_exe":
                log(f"model wants to run: {arg}")
                reply = input(f"  >>> allow running '{arg}' on the VM? "
                             f"[y/N] ").strip().lower()
                if reply != "y":
                    result = "operator declined to run this file"
                    log("REFUSED (operator declined)")
                else:
                    link.send(f"TOOL: {name} {arg}")
                    result = link.read_result_block()
                    log(f"run_exe {arg} ->\n{result}")
            else:
                link.send(f"TOOL: {name} {arg}".rstrip())
                result = link.read_result_block()
                log(f"{name} {arg} ->\n{result}")

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": call["id"],
                "content": result,
            })
        messages.append({"role": "user", "content": tool_results})

    link.send("SAY: (turn limit reached without a final answer)")
    link.send("SAY_END")
    link.send("DONE")
    log("max turns reached")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--socket", default="build/aichan.sock")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--max-turns", type=int, default=8)
    ap.add_argument("--allow-run", action="store_true",
                    help="permit the run_exe tool (still asks for confirmation)")
    ap.add_argument("--mock", nargs="?", const="list_files", default=None,
                    metavar="SCENARIO",
                    help="use a canned local responder instead of the real "
                        "API (no network call at all); SCENARIO is "
                        "'list_files' (default) or 'run_exe', to test the "
                        "run_exe safety gates")
    args = ap.parse_args()

    api_key = None
    if not args.mock:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise SystemExit(
                "ANTHROPIC_API_KEY is not set. Export it, or pass --mock to "
                "test the guest<->host transport without a real API key.")

    log(f"connecting to {args.socket} ...")
    link = GuestLink(args.socket)
    log("connected. waiting for `ai <question>` from the guest shell.")
    log(f"run_exe is {'ENABLED (with confirmation)' if args.allow_run else 'DISABLED'}")
    if args.mock:
        log("MOCK MODE: no network calls, canned responses only")

    while True:
        line = link.readline(timeout=3600)
        if not line.startswith("ASK: "):
            continue
        question = line[5:]
        log(f"guest asked: {question}")
        run_turn(link, api_key, args.model, question, args.max_turns,
                 args.allow_run, args.mock)


if __name__ == "__main__":
    main()
