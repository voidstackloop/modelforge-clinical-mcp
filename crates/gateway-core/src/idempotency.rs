use std::collections::BTreeMap;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::{
    GatewayError, IdempotencyAdmission, IdempotencyScope, IdempotencyStore, IdempotentCompletion,
};

enum State {
    InProgress,
    Completed {
        arguments_digest: String,
        completion: IdempotentCompletion,
    },
}

/// An in-process `IdempotencyStore`. A genuine, usable default for a single-instance
/// deployment — not durable across a process restart, and not shared across replicas, but
/// otherwise fully real: `begin` atomically reserves the scope so two concurrent callers can
/// never both proceed as `Fresh`, and it actually deduplicates and replays rather than only
/// checking key presence. A deployment that needs cross-instance or restart-durable
/// idempotency can implement `IdempotencyStore` against a shared store instead, since every
/// caller depends on the trait, not this type.
#[derive(Default)]
pub struct InMemoryIdempotencyStore {
    scopes: Mutex<BTreeMap<IdempotencyScope, State>>,
}

#[async_trait]
impl IdempotencyStore for InMemoryIdempotencyStore {
    async fn begin(
        &self,
        scope: &IdempotencyScope,
        arguments_digest: &str,
    ) -> Result<IdempotencyAdmission, GatewayError> {
        let mut scopes = self.scopes.lock().await;
        match scopes.get(scope) {
            Some(State::Completed {
                arguments_digest: stored_digest,
                completion,
            }) => {
                if stored_digest == arguments_digest {
                    Ok(IdempotencyAdmission::Replay(completion.clone()))
                } else {
                    Err(GatewayError::IdempotencyKeyReused)
                }
            }
            Some(State::InProgress) => Err(GatewayError::IdempotencyOperationInProgress),
            None => {
                scopes.insert(scope.clone(), State::InProgress);
                Ok(IdempotencyAdmission::Fresh)
            }
        }
    }

    async fn complete(
        &self,
        scope: &IdempotencyScope,
        arguments_digest: &str,
        completion: IdempotentCompletion,
    ) -> Result<(), GatewayError> {
        self.scopes.lock().await.insert(
            scope.clone(),
            State::Completed {
                arguments_digest: arguments_digest.to_owned(),
                completion,
            },
        );
        Ok(())
    }

    async fn abort(&self, scope: &IdempotencyScope) -> Result<(), GatewayError> {
        self.scopes.lock().await.remove(scope);
        Ok(())
    }
}
