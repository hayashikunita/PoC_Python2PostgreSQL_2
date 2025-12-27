from __future__ import annotations

import windows_collect


def main() -> None:
    payload = windows_collect.collect_eventlog(log_name="System", since_hours=24, max_events=50, timeout_s=30)
    err = payload.get("summary", {}).get("error") if isinstance(payload.get("summary"), dict) else None
    print("error:", err)
    print("count:", len(payload.get("events") or []))
    if payload.get("events"):
        print("first keys:", list(payload["events"][0].keys()))


if __name__ == "__main__":
    main()
