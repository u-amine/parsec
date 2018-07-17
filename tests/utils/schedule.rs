// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Environment;
use parsec::mock::{PeerId, Transaction};
use rand::Rng;
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Debug)]
pub enum ScheduleEvent {
    LocalStep {
        global_step: usize,
        peer: PeerId,
        recipient: Option<PeerId>,
    },
    Fail(PeerId),
    VoteFor(PeerId, Transaction),
}

impl ScheduleEvent {
    pub fn gen_random<R: Rng>(
        rng: &mut R,
        step: usize,
        peers: &[PeerId],
        pending: Option<&mut PendingTransactions>,
        options: &ScheduleOptions,
    ) -> Vec<ScheduleEvent> {
        let mut result = vec![];
        for peer in peers {
            if rng.gen::<f64>() < options.prob_local_step {
                let recipient = if rng.gen::<f64>() < options.prob_send_gossip {
                    let mut recipient = peer;
                    while recipient == peer {
                        recipient = unwrap!(rng.choose(peers));
                    }
                    Some(recipient.clone())
                } else {
                    None
                };
                result.push(ScheduleEvent::LocalStep {
                    global_step: step,
                    peer: peer.clone(),
                    recipient,
                });
            }
        }

        if let Some(pending) = pending {
            for peer in pending.nonempty_peers() {
                if rng.gen::<f64>() < options.prob_recv_trans {
                    if let Some(transaction) = pending.next_for_peer(&peer) {
                        result.push(ScheduleEvent::VoteFor(peer, transaction));
                    }
                }
            }
        }

        if rng.gen::<f64>() < options.prob_failure {
            let peer = unwrap!(rng.choose(peers));
            result.push(ScheduleEvent::Fail(peer.clone()));
        }

        result
    }
}

pub struct PendingTransactions(HashMap<PeerId, Vec<Transaction>>);

impl PendingTransactions {
    pub fn new<R: Rng>(
        rng: &mut R,
        peers: &[PeerId],
        transactions: &Vec<Transaction>,
    ) -> PendingTransactions {
        let mut inner = HashMap::new();
        for peer in peers {
            let mut trans = transactions.clone();
            rng.shuffle(&mut trans);
            let _ = inner.insert(peer.clone(), trans);
        }
        PendingTransactions(inner)
    }

    pub fn next_for_peer(&mut self, peer: &PeerId) -> Option<Transaction> {
        self.0.get_mut(peer).and_then(|trans| trans.pop())
    }

    pub fn nonempty_peers(&self) -> Vec<PeerId> {
        self.0
            .iter()
            .filter(|&(_, v)| !v.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.values().all(|v| v.is_empty())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ScheduleOptions {
    pub prob_local_step: f64,
    pub prob_send_gossip: f64,
    pub prob_recv_trans: f64,
    pub prob_failure: f64,
    pub delay_lambda: f64,
}

impl Default for ScheduleOptions {
    fn default() -> ScheduleOptions {
        ScheduleOptions {
            prob_local_step: 0.15,
            prob_send_gossip: 0.8,
            prob_recv_trans: 0.05,
            prob_failure: 0.0,
            delay_lambda: 4.0,
        }
    }
}

pub struct Schedule(pub Vec<ScheduleEvent>);

impl fmt::Debug for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "----------------------------\n")?;
        write!(f, " Schedule:\n")?;
        for event in &self.0 {
            write!(f, "- {:?}\n", event)?;
        }
        write!(f, "----------------------------\n")
    }
}

impl Schedule {
    pub fn new(env: &mut Environment, options: &ScheduleOptions) -> Schedule {
        let peers: Vec<_> = env.network.peers.iter().map(|p| p.id.clone()).collect();
        let mut pending = PendingTransactions::new(&mut env.rng, &peers, &env.transactions);
        let mut result = vec![];
        let mut step = 0;
        while !pending.is_empty() {
            let event =
                ScheduleEvent::gen_random(&mut env.rng, step, &peers, Some(&mut pending), options);
            result.extend(event);
            step += 1;
        }
        let n = env.network.peers.len() as f32;
        let additional_events = (30.0 * n * n.ln()) as usize;
        for _ in 0..additional_events {
            let event = ScheduleEvent::gen_random(&mut env.rng, step, &peers, None, options);
            result.extend(event);
            step += 1;
        }
        Schedule(result)
    }
}
