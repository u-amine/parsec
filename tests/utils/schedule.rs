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
use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Clone, Debug)]
pub enum ScheduleEvent {
    SendGossip(PeerId, PeerId),
    ReceiveAndRespond(PeerId),
    VoteFor(PeerId, Transaction),
}

impl ScheduleEvent {
    pub fn gen_random<R: Rng>(
        rng: &mut R,
        peers: &[PeerId],
        unvoted: Option<&mut UnvotedTransactions>,
    ) -> ScheduleEvent {
        let num_variants = if unvoted.is_none() { 2 } else { 3 };
        let variant = rng.gen_range(0, num_variants);
        match variant {
            0 => {
                let peer1 = unwrap!(rng.choose(peers));
                let mut peer2 = peer1;
                while peer2 == peer1 {
                    peer2 = unwrap!(rng.choose(peers));
                }
                ScheduleEvent::SendGossip(peer1.clone(), peer2.clone())
            }
            1 => {
                let peer = unwrap!(rng.choose(peers));
                ScheduleEvent::ReceiveAndRespond(peer.clone())
            }
            2 => {
                // we only get here if unvoted isn't None
                let unvoted = unvoted.unwrap();
                let peers = unvoted.nonempty_peers();
                let peer = unwrap!(rng.choose(&peers));
                let transaction = unwrap!(unvoted.next_for_peer(&peer));
                ScheduleEvent::VoteFor(peer.clone(), transaction)
            }
            _ => unreachable!(),
        }
    }
}

pub struct UnvotedTransactions(HashMap<PeerId, Vec<Transaction>>);

impl UnvotedTransactions {
    pub fn new<R: Rng>(
        rng: &mut R,
        peers: &[PeerId],
        transactions: &Vec<Transaction>,
    ) -> UnvotedTransactions {
        let mut inner = HashMap::new();
        for peer in peers {
            let mut trans = transactions.clone();
            rng.shuffle(&mut trans);
            let _ = inner.insert(peer.clone(), trans);
        }
        UnvotedTransactions(inner)
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

pub struct ScheduleOptions {
    pub not_responding: HashSet<PeerId>,
}

impl Default for ScheduleOptions {
    fn default() -> Self {
        ScheduleOptions {
            not_responding: HashSet::new(),
        }
    }
}

impl Schedule {
    pub fn new(env: &mut Environment, options: &ScheduleOptions) -> Schedule {
        let peers: Vec<_> = env
            .network
            .peers
            .iter()
            .map(|p| p.id.clone())
            .filter(|p| !options.not_responding.contains(p))
            .collect();
        let mut not_voted = UnvotedTransactions::new(&mut env.rng, &peers, &env.transactions);
        let mut result = vec![];
        while !not_voted.is_empty() {
            let event = ScheduleEvent::gen_random(&mut env.rng, &peers, Some(&mut not_voted));
            result.push(event);
        }
        let n = env.network.peers.len() as f32;
        let additional_events = (30.0 * n * n.ln()) as usize;
        for _ in 0..additional_events {
            let event = ScheduleEvent::gen_random(&mut env.rng, &peers, None);
            result.push(event);
        }
        Schedule(result)
    }
}
