import time

from scan_queue import ScanQueue


class DummyScanner:
    def __init__(self):
        pass

    def scan(self, url):
        return {'url_info': {'original_url': url}, 'ok': True}


def test_queue_completes_job():
    q = ScanQueue(scanner_cls=DummyScanner)
    job_id = q.enqueue('https://example.com', save=False)
    deadline = time.time() + 5
    while time.time() < deadline:
        st = q.get_status(job_id)
        if st.get('state') == 'completed':
            break
        time.sleep(0.1)
    assert q.get_status(job_id).get('state') == 'completed'
    assert q.results[job_id]['url_info']['original_url'] == 'https://example.com'
    q.stop()
