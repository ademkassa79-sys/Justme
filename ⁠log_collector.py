""" 
Log Collector

Layer 1 of the Cyber Defense Arsenal.

Job: watch a log source and yield new lines as they appear, without 
ever blocking the rest of the system. Works on Linux, Termux, macOS, 
and Windows since it relies only on the standard library.
"""

import os 
import time 
from datetime import datetime


class FileLogSource: 
    """Watches a single text log file and yields new lines as they're appended."""

    def __init__(self, path, poll_interval=1.0, read_existing=False):
        self.path = path
        self.poll_interval = poll_interval
        self.read_existing = read_existing
        self._stop = False

    def stop(self):
        self._stop = True

    def watch(self):
        """Generator that yields (timestamp, line) tuples forever until stop() is called."""
        position = 0

        while not self._stop:
            if not os.path.exists(self.path):
                time.sleep(self.poll_interval)
                continue

            try:
                with open(self.path, "r", errors="ignore") as f:
                    if position == 0 and not self.read_existing:
                        # Jump to end of file so we only see new activity, not history
                        f.seek(0, os.SEEK_END)
                        position = f.tell()
                    else:
                        f.seek(position)

                    for line in f:
                        line = line.rstrip("\n")
                        if line:
                            yield (datetime.utcnow().isoformat() + "Z", line)

                    position = f.tell()

            except (IOError, OSError):
                # File rotated mid-read or briefly unavailable, retry next loop
                pass

            time.sleep(self.poll_interval)


class MultiFileLogSource: 
    """Watches several log files at once (e.g. auth.log + nginx access.log)."""

    def __init__(self, paths, poll_interval=1.0):
        self.sources = [FileLogSource(p, poll_interval) for p in paths]

    def watch(self):
        import threading
        import queue

        q = queue.Queue()

        def pump(source):
            for ts, line in source.watch():
                q.put((ts, line))

        threads = [threading.Thread(target=pump, args=(s,), daemon=True) for s in self.sources]
        for t in threads:
            t.start()

        while True:
            yield q.get()

    def stop(self):
        for s in self.sources:
            s.stop()
