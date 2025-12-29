"""
In-memory scan queue with a background worker thread.
"""

import threading
import uuid
import time
from queue import Queue, Empty
from typing import Dict, Optional

from main import WebsiteScanner
from storage_utils import save_report_and_history


class ScanQueue:
    def __init__(self, scanner_cls=WebsiteScanner):
        self.scanner_cls = scanner_cls
        self.queue: "Queue[Dict]" = Queue()
        self.results: Dict[str, Dict] = {}
        self.status: Dict[str, Dict] = {}
        self._stop = threading.Event()
        self.worker = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker.start()

    def enqueue(self, url: str, save: bool = True) -> str:
        job_id = str(uuid.uuid4())
        self.status[job_id] = {
            'id': job_id,
            'url': url,
            'state': 'queued',
            'created_at': time.time(),
        }
        self.queue.put({'id': job_id, 'url': url, 'save': save})
        return job_id

    def get_status(self, job_id: Optional[str] = None) -> Dict:
        if job_id:
            return self.status.get(job_id, {})
        return self.status

    def stop(self):
        self._stop.set()
        self.worker.join(timeout=2)

    def _worker_loop(self):
        while not self._stop.is_set():
            try:
                item = self.queue.get(timeout=0.5)
            except Empty:
                continue
            job_id = item['id']
            url = item['url']
            save = item['save']
            self.status[job_id]['state'] = 'running'
            try:
                scanner = self.scanner_cls()
                result = scanner.scan(url)
                self.results[job_id] = result
                self.status[job_id]['state'] = 'completed'
                self.status[job_id]['completed_at'] = time.time()
                if save:
                    try:
                        path = save_report_and_history(result)
                        self.status[job_id]['report_path'] = path
                    except Exception as e:
                        self.status[job_id]['state'] = 'completed_with_error'
                        self.status[job_id]['error'] = f"Save failed: {e}"
            except Exception as e:
                self.status[job_id]['state'] = 'failed'
                self.status[job_id]['error'] = str(e)
            finally:
                self.queue.task_done()
