use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use cadence_macros::statsd_count;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::ApiError;
use crate::project::ProjectId;

const LIMITER_PRUNE_THRESHOLD: usize = 10_000;

/// Caps how many of something each project holds at once, such as its
/// requests in flight, where a Bootstrap can hold one for the full request
/// timeout.
pub struct InFlightLimiter {
    max_per_project: u32,
    /// Counted each time a project is refused.
    rejected_metric: &'static str,
    by_project: Mutex<HashMap<ProjectId, Arc<Semaphore>>>,
}

impl InFlightLimiter {
    pub fn new(max_per_project: u32, rejected_metric: &'static str) -> Self {
        Self {
            max_per_project,
            rejected_metric,
            by_project: Mutex::new(HashMap::new()),
        }
    }

    pub fn try_acquire(&self, project: &ProjectId) -> Result<OwnedSemaphorePermit, ApiError> {
        let semaphore = self.semaphore(project);
        semaphore.try_acquire_owned().map_err(|_| {
            statsd_count!(self.rejected_metric, 1);
            ApiError::TooManyInFlight
        })
    }

    fn semaphore(&self, project: &ProjectId) -> Arc<Semaphore> {
        let mut by_project = self
            .by_project
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if by_project.len() > LIMITER_PRUNE_THRESHOLD {
            let idle = self.max_per_project as usize;
            by_project.retain(|_, semaphore| semaphore.available_permits() < idle);
        }
        let semaphore = by_project
            .entry(project.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_project as usize)));
        Arc::clone(semaphore)
    }
}

#[cfg(test)]
#[path = "../tests/unit/concurrency_limits.rs"]
mod tests;
