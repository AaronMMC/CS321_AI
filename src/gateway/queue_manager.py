"""
Queue manager for handling email processing asynchronously.
Prevents bottlenecks during high email volume.
"""

import asyncio
from collections import deque
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
from pathlib import Path
from loguru import logger
import threading
import queue


class EmailQueue:
    """
    Thread-safe queue for processing emails asynchronously.
    """

    def __init__(self, maxsize: int = 1000):
        self.queue = queue.Queue(maxsize=maxsize)
        self.results = {}
        self.stats = {
            'enqueued': 0,
            'processed': 0,
            'failed': 0,
            'avg_wait_time': 0.0
        }
        self._lock = threading.Lock()

    def enqueue(self, email_data: Dict) -> str:
        """
        Add email to processing queue.

        Returns:
            job_id: Unique identifier for this email
        """
        job_id = f"job_{datetime.now().timestamp()}_{hash(email_data.get('subject', ''))}"

        job = {
            'job_id': job_id,
            'email_data': email_data,
            'enqueued_at': datetime.now().isoformat(),
            'status': 'queued'
        }

        self.queue.put(job)

        with self._lock:
            self.stats['enqueued'] += 1
            self.results[job_id] = job

        logger.debug(f"Enqueued email {job_id}")
        return job_id

    def dequeue(self) -> Optional[Dict]:
        """Get next email from queue for processing"""
        try:
            job = self.queue.get_nowait()
            job['status'] = 'processing'
            job['processing_started'] = datetime.now().isoformat()

            with self._lock:
                self.results[job['job_id']] = job

            return job
        except queue.Empty:
            return None

    def mark_complete(self, job_id: str, result: Dict):
        """Mark job as complete and store result"""
        with self._lock:
            if job_id in self.results:
                self.results[job_id]['status'] = 'completed'
                self.results[job_id]['completed_at'] = datetime.now().isoformat()
                self.results[job_id]['result'] = result

                # Update stats
                self.stats['processed'] += 1
                enqueued = datetime.fromisoformat(self.results[job_id]['enqueued_at'])
                completed = datetime.now()
                wait_time = (completed - enqueued).total_seconds()

                # Update average
                total = self.stats['avg_wait_time'] * (self.stats['processed'] - 1) + wait_time
                self.stats['avg_wait_time'] = total / self.stats['processed']

    def mark_failed(self, job_id: str, error: str):
        """Mark job as failed"""
        with self._lock:
            if job_id in self.results:
                self.results[job_id]['status'] = 'failed'
                self.results[job_id]['error'] = error
                self.stats['failed'] += 1

    def get_status(self, job_id: str) -> Optional[Dict]:
        """Get status of a specific job"""
        return self.results.get(job_id)

    def get_stats(self) -> Dict:
        """Get queue statistics"""
        with self._lock:
            return {
                **self.stats,
                'queue_size': self.queue.qsize(),
                'pending': self.stats['enqueued'] - self.stats['processed'] - self.stats['failed']
            }


class AsyncProcessor:
    """
    Asynchronous processor that consumes from queue and processes emails.
    """

    def __init__(self, queue: EmailQueue, model, threat_hub, num_workers: int = 3):
        self.queue = queue
        self.model = model
        self.threat_hub = threat_hub
        self.num_workers = num_workers
        self.workers = []
        self.running = False

    async def start(self):
        """Start worker processes"""
        self.running = True
        self.workers = [asyncio.create_task(self._worker(i)) for i in range(self.num_workers)]
        logger.info(f"Started {self.num_workers} async workers")

    async def stop(self):
        """Stop all workers"""
        self.running = False
        for worker in self.workers:
            worker.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        logger.info("All workers stopped")

    async def _worker(self, worker_id: int):
        """Worker process that processes emails from queue"""
        logger.info(f"Worker {worker_id} started")

        while self.running:
            # Get job from queue (non-blocking)
            job = self.queue.dequeue()

            if job is None:
                # No jobs, wait a bit
                await asyncio.sleep(0.1)
                continue

            try:
                logger.info(f"Worker {worker_id} processing job {job['job_id']}")

                # Process the email
                email_data = job['email_data']

                # Analyze with model
                text_to_analyze = f"{email_data.get('subject', '')} {email_data.get('body_plain', '')}"
                prediction = self.model.predict(text_to_analyze)

                # Get threat score
                if isinstance(prediction, dict):
                    threat_score = prediction.get('threat_score', 0)
                else:
                    threat_score = prediction

                # Get URLs for threat intelligence
                urls = email_data.get('urls', [])
                external_score = 0
                if urls:
                    features = self.threat_hub.get_features_for_model(text_to_analyze, urls)
                    external_score = float(features[0]) if len(features) > 0 else 0

                # Combine scores
                combined_score = (threat_score * 0.6) + (external_score * 0.4)

                result = {
                    'threat_score': combined_score,
                    'model_score': threat_score,
                    'external_score': external_score,
                    'risk_level': self._get_risk_level(combined_score),
                    'urls_found': urls,
                    'has_attachments': email_data.get('has_attachments', False)
                }

                self.queue.mark_complete(job['job_id'], result)
                logger.debug(f"Worker {worker_id} completed job {job['job_id']} with score {combined_score:.2f}")

            except Exception as e:
                logger.error(f"Worker {worker_id} failed processing job {job['job_id']}: {e}")
                self.queue.mark_failed(job['job_id'], str(e))

    def _get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "SAFE"


# Simple test
async def test_queue():
    """Test the queue system"""
    from src.models.tinybert_model import TinyBERTForEmailSecurity
    from src.features.external_intelligence import ThreatIntelligenceHub

    # Initialize
    email_queue = EmailQueue()
    model = TinyBERTForEmailSecurity()
    threat_hub = ThreatIntelligenceHub()
    processor = AsyncProcessor(email_queue, model, threat_hub, num_workers=2)

    # Start processor
    await processor.start()

    # Add some test emails
    test_emails = [
        {"subject": "Meeting reminder", "body_plain": "Meeting at 10am tomorrow"},
        {"subject": "URGENT: Account verification", "body_plain": "Click here: http://bit.ly/verify"},
    ]

    for email in test_emails:
        job_id = email_queue.enqueue(email)
        print(f"Enqueued: {job_id}")

    # Wait for processing
    await asyncio.sleep(5)

    # Check results
    print("\nQueue Stats:", email_queue.get_stats())
    for email in test_emails:
        for job_id, job in email_queue.results.items():
            if job.get('status') == 'completed':
                print(f"Result for {job_id}: {job.get('result')}")

    # Stop processor
    await processor.stop()


if __name__ == "__main__":
    asyncio.run(test_queue())