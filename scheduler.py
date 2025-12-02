"""
Email scheduling system
"""

import json
import schedule
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

@dataclass
class ScheduledJob:
    """Scheduled email job"""
    id: str
    payload: Dict[str, Any]
    schedule: str  # cron format or "once:YYYY-MM-DD HH:MM:SS"
    enabled: bool = True
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class EmailScheduler:
    """Schedule and manage email jobs"""
    
    def __init__(self, jobs_file: str = "scheduled_jobs.json"):
        self.jobs_file = Path(jobs_file)
        self.scheduled_jobs: Dict[str, ScheduledJob] = {}
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        
        self.load_jobs()
    
    def load_jobs(self) -> None:
        """Load scheduled jobs from file"""
        try:
            if self.jobs_file.exists():
                with open(self.jobs_file, 'r') as f:
                    data = json.load(f)
                    self.scheduled_jobs = {
                        job_id: ScheduledJob(**job_data) 
                        for job_id, job_data in data.items()
                    }
                    logger.info(f"Loaded {len(self.scheduled_jobs)} scheduled jobs")
        except Exception as e:
            logger.error(f"Failed to load scheduled jobs: {e}")
    
    def save_jobs(self) -> None:
        """Save scheduled jobs to file"""
        try:
            data = {job_id: asdict(job) for job_id, job in self.scheduled_jobs.items()}
            with open(self.jobs_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save scheduled jobs: {e}")
    
    def add_job(self, job: ScheduledJob, callback) -> bool:
        """Add a new scheduled job"""
        if job.id in self.scheduled_jobs:
            logger.warning(f"Job {job.id} already exists")
            return False
        
        # Schedule the job
        if job.schedule.startswith("once:"):
            # One-time job
            try:
                run_time = job.schedule[5:]  # Remove "once:" prefix
                dt = datetime.fromisoformat(run_time)
                schedule.every().day.at(dt.strftime("%H:%M")).do(
                    self._run_job, job.id, callback
                ).tag(job.id)
                
                job.next_run = run_time
            except Exception as e:
                logger.error(f"Invalid schedule format for one-time job: {e}")
                return False
        else:
            # Cron-like schedule
            try:
                # Parse schedule string (e.g., "every 10 minutes", "daily at 10:30")
                if job.schedule.startswith("every "):
                    # Handle simple schedules
                    parts = job.schedule.split()
                    if len(parts) >= 3:
                        interval = int(parts[1])
                        unit = parts[2]
                        
                        if unit.startswith("minute"):
                            schedule.every(interval).minutes.do(
                                self._run_job, job.id, callback
                            ).tag(job.id)
                        elif unit.startswith("hour"):
                            schedule.every(interval).hours.do(
                                self._run_job, job.id, callback
                            ).tag(job.id)
                        elif unit.startswith("day"):
                            schedule.every(interval).days.do(
                                self._run_job, job.id, callback
                            ).tag(job.id)
                elif job.schedule.startswith("daily at "):
                    time_str = job.schedule[9:]  # Remove "daily at " prefix
                    schedule.every().day.at(time_str).do(
                        self._run_job, job.id, callback
                    ).tag(job.id)
            except Exception as e:
                logger.error(f"Failed to schedule job: {e}")
                return False
        
        self.scheduled_jobs[job.id] = job
        self.save_jobs()
        logger.info(f"Added scheduled job: {job.id}")
        return True
    
    def _run_job(self, job_id: str, callback) -> None:
        """Execute a scheduled job"""
        if job_id not in self.scheduled_jobs:
            return
        
        job = self.scheduled_jobs[job_id]
        if not job.enabled:
            return
        
        try:
            logger.info(f"Running scheduled job: {job_id}")
            callback(job.payload)
            
            # Update job status
            job.last_run = datetime.now().isoformat()
            
            # Remove one-time jobs
            if job.schedule.startswith("once:"):
                self.remove_job(job_id)
            else:
                self.save_jobs()
                
        except Exception as e:
            logger.error(f"Failed to run scheduled job {job_id}: {e}")
    
    def remove_job(self, job_id: str) -> bool:
        """Remove a scheduled job"""
        if job_id in self.scheduled_jobs:
            schedule.clear(job_id)
            del self.scheduled_jobs[job_id]
            self.save_jobs()
            logger.info(f"Removed scheduled job: {job_id}")
            return True
        return False
    
    def start(self) -> None:
        """Start the scheduler"""
        if self.running:
            return
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        logger.info("Email scheduler started")
    
    def stop(self) -> None:
        """Stop the scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Email scheduler stopped")
    
    def _scheduler_loop(self) -> None:
        """Main scheduler loop"""
        while self.running:
            schedule.run_pending()
            time.sleep(1)