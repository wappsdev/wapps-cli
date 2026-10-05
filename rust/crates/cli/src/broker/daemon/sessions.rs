//! Cloud capabilities live only in memory and stay scoped to their mission.
use super::super::{config::Config, forward};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::{atomic::AtomicBool, Arc, Mutex},
};

#[derive(Default)]
struct State {
    connected: HashMap<String, usize>,
    leases: HashMap<String, Lease>,
}
struct Lease {
    authority: Value,
    owners: HashSet<String>,
}
#[derive(Default)]
pub(super) struct Sessions {
    state: Mutex<State>,
    // Claim/release ordering matters, unlike long polls and ordinary forwarding.
    ownership: Mutex<()>,
}
pub(in crate::broker) struct Session {
    id: String,
    sessions: Arc<Sessions>,
}
impl Sessions {
    pub fn connections(&self) -> usize {
        self.state.lock().unwrap().connected.values().sum()
    }
    pub fn connect(self: &Arc<Self>, id: String) -> Session {
        *self
            .state
            .lock()
            .unwrap()
            .connected
            .entry(id.clone())
            .or_default() += 1;
        Session {
            id,
            sessions: Arc::clone(self),
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let mut state = self.sessions.state.lock().unwrap();
        if let Some(count) = state.connected.get_mut(&self.id) {
            *count -= 1;
            if *count == 0 {
                state.connected.remove(&self.id);
            }
        }
    }
}
impl Session {
    pub fn call(
        &self,
        config: &Config,
        id: &Value,
        name: &str,
        args: Value,
        cancelled: &AtomicBool,
    ) -> Value {
        if !matches!(name, "orchestrator_claim" | "orchestrator_release") {
            return forward::call(config, id, name, args, cancelled);
        }
        // Apply the forwarding boundary's local checks before any automatic
        // mutation. Tool schemas and lease authority still belong to the cloud.
        if let Err(error) = forward::validate(config, id, name, &args) {
            return error;
        }
        let _serial = self.sessions.ownership.lock().unwrap();
        let mission = args["missionId"].as_str().unwrap_or("").to_owned();
        if name == "orchestrator_claim" {
            let gone = {
                let state = self.sessions.state.lock().unwrap();
                state
                    .leases
                    .get(&mission)
                    .filter(|lease| {
                        lease
                            .owners
                            .iter()
                            .all(|s| !state.connected.contains_key(s))
                    })
                    .map(|lease| lease.authority.clone())
            };
            if let Some(mut authority) = gone {
                authority["missionId"] = json!(mission);
                // No retry of an uncertain mutation. If release fails, retain the
                // capability for the next claim; the cloud still fences every write.
                let release = forward::call(
                    config,
                    &json!(0),
                    "orchestrator_release",
                    authority,
                    cancelled,
                );
                let stale = release["isError"] == true
                    && release["structuredContent"]["error"] == "FORBIDDEN"
                    && matches!(
                        release["structuredContent"]["details"]["refusal"].as_str(),
                        Some(
                            "no_live_lease"
                                | "lease_expired"
                                | "stale_fencing_token"
                                | "invalid_lease_capability"
                        )
                    );
                if release["structuredContent"]["released"] == true || stale {
                    // These cloud refusals definitively invalidate our cached
                    // capability. Let the requested claim ask the cloud afresh.
                    self.sessions.state.lock().unwrap().leases.remove(&mission);
                } else {
                    return release;
                }
            }
        }
        let result = forward::call(config, id, name, args.clone(), cancelled);
        if result["isError"] != true {
            let mut state = self.sessions.state.lock().unwrap();
            if name == "orchestrator_claim" {
                let authority = &result["structuredContent"]["authority"];
                if authority["capability"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty())
                    && authority["fencingToken"].is_u64()
                {
                    let lease = state.leases.entry(mission).or_insert_with(|| Lease {
                        authority: authority.clone(),
                        owners: HashSet::new(),
                    });
                    if lease.authority != *authority {
                        lease.authority = authority.clone();
                        lease.owners.clear();
                    }
                    lease.owners.insert(self.id.clone());
                }
            } else if result["structuredContent"]["released"] == true
                && state.leases.get(&mission).is_some_and(|lease| {
                    lease.authority["capability"] == args["capability"]
                        && lease.authority["fencingToken"] == args["fencingToken"]
                })
            {
                state.leases.remove(&mission);
            }
        }
        result
    }
}
