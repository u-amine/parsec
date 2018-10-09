// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{MetaVote, MetaVotes};
use hash::Hash;
use id::PublicId;
use round_hash::RoundHash;
use std::collections::BTreeMap;
use std::{iter, mem};

struct MetaElection<P: PublicId> {
    meta_votes: MetaVotes<P>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<P, Vec<RoundHash>>,
}

impl<P: PublicId> MetaElection<P> {
    fn new() -> Self {
        MetaElection {
            meta_votes: BTreeMap::new(),
            round_hashes: BTreeMap::new(),
        }
    }

    fn initialise_round_hashes<'a, I>(&mut self, peer_ids: I, initial_hash: Hash)
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        self.round_hashes = peer_ids
            .into_iter()
            .map(|peer_id| {
                let round_hash = RoundHash::new(peer_id, initial_hash);
                (peer_id.clone(), vec![round_hash])
            }).collect();
    }
}

pub struct MetaElections<P: PublicId> {
    current_hash: Hash,
    current_election: MetaElection<P>,

    old_hashes: Vec<Hash>,
    old_elections: BTreeMap<Hash, MetaElection<P>>,
}

impl<P: PublicId> MetaElections<P> {
    pub fn new() -> Self {
        MetaElections {
            current_hash: Hash::all_zero(),
            current_election: MetaElection::new(),

            old_hashes: vec![],
            old_elections: BTreeMap::new(),
        }
    }

    pub fn meta_votes(
        &self,
        payload_hash: &Hash,
        event_hash: &Hash,
    ) -> Option<&BTreeMap<P, Vec<MetaVote>>> {
        self.election(payload_hash)
            .and_then(|e| e.meta_votes.get(event_hash))
    }

    pub fn meta_votes_from_current_election(
        &self,
        event_hash: &Hash,
    ) -> Option<&BTreeMap<P, Vec<MetaVote>>> {
        self.current_election.meta_votes.get(event_hash)
    }

    pub(crate) fn round_hashes(&self, payload_hash: &Hash, peer_id: &P) -> Option<&Vec<RoundHash>> {
        self.election(payload_hash)
            .and_then(|e| e.round_hashes.get(peer_id))
    }

    pub fn consensus_history(&self) -> impl Iterator<Item = &Hash> {
        self.old_hashes.iter().chain(iter::once(&self.current_hash))
    }

    pub fn new_election(&mut self, payload_hash: Hash) {
        let previous_election = mem::replace(&mut self.current_election, MetaElection::new());
        let _ = self
            .old_elections
            .insert(self.current_hash, previous_election);
        self.old_hashes.push(self.current_hash);
        self.current_hash = payload_hash;
    }

    pub fn insert(
        &mut self,
        payload_hash: &Hash,
        event_hash: Hash,
        meta_votes: BTreeMap<P, Vec<MetaVote>>,
    ) {
        if let Some(election) = self.election_mut(payload_hash) {
            let _ = election.meta_votes.insert(event_hash, meta_votes);
        } else {
            log_or_panic!(
                "Meta election for payload hash {:?} not found",
                payload_hash
            );
        }
    }

    pub fn restart_current_election_round_hashes<'a, I>(&mut self, peer_ids: I)
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let latest_block_hash = self.current_hash;
        self.initialise_current_election_round_hashes(peer_ids, latest_block_hash);
    }

    pub fn update_round_hashes(&mut self, payload_hash: &Hash, event_hash: &Hash) {
        let meta_votes = if let Some(meta_votes) = self
            .election(payload_hash)
            .and_then(|e| e.meta_votes.get(event_hash))
        {
            meta_votes.clone()
        } else {
            return;
        };

        for (peer_id, event_votes) in meta_votes {
            for meta_vote in event_votes {
                let hashes = if let Some(hashes) = self
                    .election_mut(payload_hash)
                    .and_then(|e| e.round_hashes.get_mut(&peer_id))
                {
                    hashes
                } else {
                    continue;
                };
                while hashes.len() < meta_vote.round + 1 {
                    let next_round_hash = hashes[hashes.len() - 1].increment_round();
                    hashes.push(next_round_hash);
                }
            }
        }
    }

    pub fn initialise_current_election_round_hashes<'a, I>(
        &mut self,
        peer_ids: I,
        initial_hash: Hash,
    ) where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        self.current_election
            .initialise_round_hashes(peer_ids, initial_hash);
    }

    pub fn current_meta_votes(&self) -> &MetaVotes<P> {
        &self.current_election.meta_votes
    }

    fn election(&self, payload_hash: &Hash) -> Option<&MetaElection<P>> {
        if *payload_hash == self.current_hash {
            Some(&self.current_election)
        } else {
            self.old_elections.get(payload_hash)
        }
    }

    fn election_mut(&mut self, payload_hash: &Hash) -> Option<&mut MetaElection<P>> {
        if *payload_hash == self.current_hash {
            Some(&mut self.current_election)
        } else {
            self.old_elections.get_mut(payload_hash)
        }
    }
}

#[cfg(test)]
impl<P: PublicId> MetaElections<P> {
    pub fn new_from_parsed(votes: MetaVotes<P>) -> Self {
        let mut new = Self::new();
        new.current_election.meta_votes = votes;
        new
    }
}
