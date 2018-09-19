// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Observation;
use block::Block;
use mock::{PeerId, Transaction};
use parsec::{self, Parsec};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

#[derive(Clone, Copy, PartialEq)]
pub enum PeerStatus {
    Active,
    Pending,
    Removed,
    Failed,
}

pub struct Peer {
    pub id: PeerId,
    pub parsec: Parsec<Transaction, PeerId>,
    /// The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    pub blocks: Vec<Block<Transaction, PeerId>>,
    pub status: PeerStatus,
}

impl Peer {
    pub fn new(id: PeerId, genesis_group: &BTreeSet<PeerId>, status: PeerStatus) -> Self {
        Self {
            id: id.clone(),
            parsec: Parsec::from_genesis(id, genesis_group, parsec::is_supermajority),
            blocks: vec![],
            status: status,
        }
    }

    pub fn vote_for(&mut self, observation: &Observation) -> bool {
        if !self.parsec.have_voted_for(observation) {
            unwrap!(self.parsec.vote_for(observation.clone()));
            true
        } else {
            false
        }
    }

    pub fn poll(&mut self) {
        while let Some(block) = self.parsec.poll() {
            self.blocks.push(block)
        }
    }

    /// Returns the payloads of `self.blocks` in the order in which they were returned by `poll()`.
    pub fn blocks_payloads(&self) -> Vec<&Observation> {
        self.blocks.iter().map(Block::payload).collect()
    }
}

impl Debug for Peer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}: Blocks: {:?}", self.id, self.blocks)
    }
}

pub struct Peers(BTreeMap<PeerId, PeerStatus>);

impl Peers {
    /// Creates a new Peers struct with the given active peers
    pub fn new(names: &BTreeSet<PeerId>) -> Peers {
        Peers(
            names
                .into_iter()
                .map(|x| (x.clone(), PeerStatus::Active))
                .collect(),
        )
    }

    fn choose_name_to_remove<R: Rng>(&self, rng: &mut R) -> PeerId {
        let names: Vec<&PeerId> = self
            .0
            .iter()
            .filter(|&(_, status)| *status == PeerStatus::Active || *status == PeerStatus::Failed)
            .map(|(id, _)| id)
            .collect();
        (*rng.choose(&names).unwrap()).clone()
    }

    fn choose_name_to_fail<R: Rng>(&self, rng: &mut R) -> PeerId {
        let names: Vec<&PeerId> = self
            .0
            .iter()
            .filter(|&(_, status)| *status == PeerStatus::Active)
            .map(|(id, _)| id)
            .collect();
        (*rng.choose(&names).unwrap()).clone()
    }

    fn num_active_peers(&self) -> usize {
        self.0
            .values()
            .filter(|&status| *status == PeerStatus::Active)
            .count()
    }

    /// Returns an iterator through the list of the active peers
    pub fn active_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.0
            .iter()
            .filter(|&(_, status)| *status == PeerStatus::Active)
            .map(|(id, _)| id)
    }

    /// Returns an iterator through the list of the active peers
    pub fn present_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.0
            .iter()
            .filter(|&(_, status)| *status == PeerStatus::Active || *status == PeerStatus::Failed)
            .map(|(id, _)| id)
    }

    fn num_failed_peers(&self) -> usize {
        self.0
            .values()
            .filter(|&status| *status == PeerStatus::Failed)
            .count()
    }

    /// Adds an active peer.
    pub fn add_peer(&mut self, p: PeerId) {
        let _ = self.0.insert(p, PeerStatus::Active);
    }

    // Randomly chooses a peer to remove. Only actually removes if removing won't cause the failed
    // peers to go over N/3.
    // Returns the removed peer's name if removing occurred.
    pub fn remove_peer<R: Rng>(&mut self, rng: &mut R, min_active: usize) -> Option<PeerId> {
        let mut active_peers = self.num_active_peers();
        let mut failed_peers = self.num_failed_peers();
        let name = self.choose_name_to_remove(rng);
        {
            let status = self.0.get(&name).unwrap();
            if *status == PeerStatus::Active {
                active_peers -= 1;
            } else if *status == PeerStatus::Failed {
                failed_peers -= 1;
            } else {
                return None;
            }
        }
        if 2 * failed_peers < active_peers && active_peers >= min_active {
            let status = self.0.get_mut(&name).unwrap();
            *status = PeerStatus::Removed;
            Some(name)
        } else {
            None
        }
    }

    /// Randomly chooses a peer to fail. Only actually fails if it won't cause the failed peers to
    /// go over N/3.
    /// Returns the failed peer's name if failing occurred.
    pub fn fail_peer<R: Rng>(&mut self, rng: &mut R, min_active: usize) -> Option<PeerId> {
        let active_peers = self.num_active_peers() - 1;
        let failed_peers = self.num_failed_peers() + 1;
        if 2 * failed_peers < active_peers && active_peers >= min_active {
            let name = self.choose_name_to_fail(rng);
            let status = self.0.get_mut(&name).unwrap();
            *status = PeerStatus::Failed;
            Some(name)
        } else {
            None
        }
    }
}
