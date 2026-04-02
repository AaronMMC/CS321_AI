"""
Performance Metrics Framework.
Collects and exposes metrics for monitoring the Email Security Gateway.
"""
import time
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from loguru import logger


class PerformanceMetrics:
    """
    Collects and manages performance metrics for the email security gateway.
    Thread-safe implementation for use in multi-threaded environments.
    """
    
    def __init__(self, max_history_size: int = 1000):
        """
        Initialize performance metrics collector.
        
        Args:
            max_history_size: Maximum number of historical entries to keep
        """
        self.max_history_size = max_history_size
        self._lock = threading.RLock()
        
        # Basic counters
        self.emails_processed = 0
        self.threats_detected = 0
        self.warnings_added = 0
        self.urls_rewritten = 0
        self.emails_quarantined = 0
        self.authentication_failures = 0
        
        # Timing metrics
        self.processing_times = deque(maxlen=max_history_size)
        self.analysis_times = deque(maxlen=max_history_size)
        self.warning_injection_times = deque(maxlen=max_history_size)
        self.url_rewriting_times = deque(maxlen=max_history_size)
        
        # Threat level distribution
        self.threat_level_counts = defaultdict(int)
        
        # Hourly/daily aggregates
        self.hourly_counts = defaultdict(int)  # hour -> count
        self.daily_counts = defaultdict(int)   # date -> count
        
        # Recent activity for dashboard
        self.recent_emails = deque(maxlen=100)  # Keep last 100 emails for dashboard
        
        # Start time
        self.start_time = time.time()
        
        logger.info("Performance metrics framework initialized")

    def record_email_processed(self, processing_time: float = 0.0):
        """Record that an email was processed."""
        with self._lock:
            self.emails_processed += 1
            if processing_time > 0:
                self.processing_times.append(processing_time)
            
            # Update time-based aggregates
            now = datetime.now()
            hour_key = now.strftime("%Y-%m-%d %H:00")
            date_key = now.strftime("%Y-%m-%d")
            self.hourly_counts[hour_key] += 1
            self.daily_counts[date_key] += 1

    def record_threat_detected(self, threat_score: float, processing_time: float = 0.0):
        """Record that a threat was detected."""
        with self._lock:
            self.threats_detected += 1
            if processing_time > 0:
                self.analysis_times.append(processing_time)
            
            # Categorize threat level
            if threat_score >= 0.8:
                level = "CRITICAL"
            elif threat_score >= 0.6:
                level = "HIGH"
            elif threat_score >= 0.4:
                level = "MEDIUM"
            elif threat_score >= 0.2:
                level = "LOW"
            else:
                level = "SAFE"
                
            self.threat_level_counts[level] += 1

    def record_warning_added(self, processing_time: float = 0.0):
        """Record that a warning was added to an email."""
        with self._lock:
            self.warnings_added += 1
            if processing_time > 0:
                self.warning_injection_times.append(processing_time)

    def record_url_rewritten(self, count: int, processing_time: float = 0.0):
        """Record that URLs were rewritten for click-time protection."""
        with self._lock:
            self.urls_rewritten += count
            if processing_time > 0:
                self.url_rewriting_times.append(processing_time)

    def record_email_quarantined(self):
        """Record that an email was quarantined."""
        with self._lock:
            self.emails_quarantined += 1

    def record_authentication_failure(self):
        """Record an authentication verification failure."""
        with self._lock:
            self.authentication_failures += 1

    def record_email_activity(self, email_data: Dict):
        """Record recent email activity for dashboard display."""
        with self._lock:
            activity = {
                'timestamp': datetime.now().isoformat(),
                'from': email_data.get('from', 'unknown'),
                'subject': email_data.get('subject', 'No Subject')[:50],  # Truncate long subjects
                'threat_score': email_data.get('threat_score', 0.0),
                'risk_level': email_data.get('risk_level', 'UNKNOWN'),
                'actions': []
            }
            
            # Add actions taken
            if email_data.get('modified', False):
                activity['actions'].append('WARNING_ADDED')
            if email_data.get('url_mappings'):
                activity['actions'].append('URLS_REWRITTEN')
            if email_data.get('quarantined', False):
                activity['actions'].append('QUARANTINED')
                
            self.recent_emails.append(activity)

    def get_current_stats(self) -> Dict[str, Any]:
        """Get current performance statistics."""
        with self._lock:
            uptime = time.time() - self.start_time
            
            # Calculate averages
            avg_processing_time = (
                sum(self.processing_times) / len(self.processing_times)
                if self.processing_times else 0.0
            )
            avg_analysis_time = (
                sum(self.analysis_times) / len(self.analysis_times)
                if self.analysis_times else 0.0
            )
            avg_warning_time = (
                sum(self.warning_injection_times) / len(self.warning_injection_times)
                if self.warning_injection_times else 0.0
            )
            avg_url_time = (
                sum(self.url_rewriting_times) / len(self.url_rewriting_times)
                if self.url_rewriting_times else 0.0
            )
            
            return {
                'uptime_seconds': uptime,
                'emails_processed': self.emails_processed,
                'threats_detected': self.threats_detected,
                'warnings_added': self.warnings_added,
                'urls_rewritten': self.urls_rewritten,
                'emails_quarantined': self.emails_quarantined,
                'authentication_failures': self.authentication_failures,
                'threat_level_distribution': dict(self.threat_level_counts),
                'average_processing_time': avg_processing_time,
                'average_analysis_time': avg_analysis_time,
                'average_warning_injection_time': avg_warning_time,
                'average_url_rewriting_time': avg_url_time,
                'emails_per_minute': (
                    (self.emails_processed / uptime * 60) if uptime > 0 else 0
                ),
                'threat_detection_rate': (
                    (self.threats_detected / self.emails_processed * 100) 
                    if self.emails_processed > 0 else 0
                ),
                'warning_rate': (
                    (self.warnings_added / self.emails_processed * 100) 
                    if self.emails_processed > 0 else 0
                )
            }

    def get_recent_activity(self, limit: int = 10) -> List[Dict]:
        """Get recent email activity for dashboard."""
        with self._lock:
            # Return most recent first
            return list(self.recent_emails)[-limit:][::-1]

    def get_hourly_trends(self, hours: int = 24) -> Dict[str, int]:
        """Get email processing trends for the last N hours."""
        with self._lock:
            now = datetime.now()
            trends = {}
            
            for i in range(hours):
                hour = now - timedelta(hours=i)
                hour_key = hour.strftime("%Y-%m-%d %H:00")
                trends[hour_key] = self.hourly_counts.get(hour_key, 0)
                
            return trends

    def get_daily_trends(self, days: int = 7) -> Dict[str, int]:
        """Get email processing trends for the last N days."""
        with self._lock:
            now = datetime.now()
            trends = {}
            
            for i in range(days):
                day = now - timedelta(days=i)
                day_key = day.strftime("%Y-%m-%d")
                trends[day_key] = self.daily_counts.get(day_key, 0)
                
            return trends

    def reset_metrics(self):
        """Reset all metrics to zero."""
        with self._lock:
            self.__init__(self.max_history_size)
            logger.info("Performance metrics reset")

    def get_summary(self) -> str:
        """Get a formatted summary of current metrics."""
        stats = self.get_current_stats()
        
        summary = f"""
Email Security Gateway Performance Metrics
{'='*50}
Uptime: {stats['uptime_seconds']:.0f} seconds
Emails Processed: {stats['emails_processed']:,}
Threats Detected: {stats['threats_detected']:,}
Warnings Added: {stats['warnings_added']:,}
URLs Rewritten: {stats['urls_rewritten']:,}
Emails Quarantined: {stats['emails_quarantined']:,}
Auth Failures: {stats['authentication_failures']:,}

Processing Rates:
- Emails/minute: {stats['emails_per_minute']:.1f}
- Threat Detection Rate: {stats['threat_detection_rate']:.1f}%
- Warning Rate: {stats['warning_rate']:.1f}%

Average Times:
- Processing: {stats['average_processing_time']:.3f}s
- Analysis: {stats['average_analysis_time']:.3f}s
- Warning Injection: {stats['average_warning_injection_time']:.3f}s
- URL Rewriting: {stats['average_url_rewriting_time']:.3f}s

Threat Distribution:
{chr(10).join([f'  {level}: {count}' for level, count in stats['threat_level_distribution'].items()])}
"""
        return summary.strip()


# Global metrics instance
_metrics_instance = None


def get_performance_metrics() -> PerformanceMetrics:
    """Get or create the global performance metrics instance."""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = PerformanceMetrics()
    return _metrics_instance


def record_email_processed(processing_time: float = 0.0):
    """Convenience function to record email processed."""
    get_performance_metrics().record_email_processed(processing_time)


def record_threat_detected(threat_score: float, processing_time: float = 0.0):
    """Convenience function to record threat detected."""
    get_performance_metrics().record_threat_detected(threat_score, processing_time)


def record_warning_added(processing_time: float = 0.0):
    """Convenience function to record warning added."""
    get_performance_metrics().record_warning_added(processing_time)


def record_url_rewritten(count: int, processing_time: float = 0.0):
    """Convenience function to record URLs rewritten."""
    get_performance_metrics().record_url_rewritten(count, processing_time)


def record_email_quarantined():
    """Convenience function to record email quarantined."""
    get_performance_metrics().record_email_quarantined()


def record_authentication_failure():
    """Convenience function to record authentication failure."""
    get_performance_metrics().record_authentication_failure()


def record_email_activity(email_data: Dict):
    """Convenience function to record email activity."""
    get_performance_metrics().record_email_activity(email_data)


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_performance_metrics():
        """Test performance metrics functionality."""
        print("=" * 60)
        print("PERFORMANCE METRICS FRAMEWORK TEST")
        print("=" * 60)
        
        # Create metrics instance
        metrics = PerformanceMetrics(max_history_size=100)
        
        # Test recording emails
        metrics.record_email_processed(0.5)
        metrics.record_email_processed(0.3)
        print(f"✓ Recorded 2 emails processed")
        
        # Test threat detection
        metrics.record_threat_detected(0.9, 0.2)  # Critical threat
        metrics.record_threat_detected(0.5, 0.1)  # Medium threat
        metrics.record_threat_detected(0.1, 0.05) # Low threat
        print(f"✓ Recorded 3 threats detected")
        
        # Test warnings
        metrics.record_warning_added(0.05)
        metrics.record_warning_added(0.03)
        print(f"✓ Recorded 2 warnings added")
        
        # Test URL rewriting
        metrics.record_url_rewritten(3, 0.1)
        print(f"✓ Recorded 3 URLs rewritten")
        
        # Test quarantine
        metrics.record_email_quarantined()
        print(f"✓ Recorded 1 email quarantined")
        
        # Test authentication failure
        metrics.record_authentication_failure()
        print(f"✓ Recorded 1 authentication failure")
        
        # Test activity recording
        test_email = {
            'from': 'test@example.com',
            'subject': 'Test Email Subject',
            'threat_score': 0.7,
            'risk_level': 'HIGH',
            'modified': True,
            'url_mappings': [{'original': 'http://example.com', 'rewritten': 'http://proxy/check?url=...'}]
        }
        metrics.record_email_activity(test_email)
        print(f"✓ Recorded email activity")
        
        # Get stats
        stats = metrics.get_current_stats()
        print(f"✓ Current stats retrieved:")
        print(f"  - Emails processed: {stats['emails_processed']}")
        print(f"  - Threats detected: {stats['threats_detected']}")
        print(f"  - Warnings added: {stats['warnings_added']}")
        print(f"  - Average processing time: {stats['average_processing_time']:.3f}s")
        
        # Get summary
        summary = metrics.get_summary()
        print(f"✓ Summary generated ({len(summary)} characters)")
        
        # Test trends
        hourly = metrics.get_hourly_trends(hours=3)
        daily = metrics.get_daily_trends(days=2)
        print(f"✓ Trends retrieved: {len(hourly)} hours, {len(daily)} days")
        
        print("=" * 60)
        print("PERFORMANCE METRICS TEST COMPLETE")
        print("=" * 60)
    
    # Run the test
    asyncio.run(test_performance_metrics())