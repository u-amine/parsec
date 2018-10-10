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
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::{iter, mem, usize};

/// Handle that uniquely identifies a `MetaElection`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct MetaElectionHandle(usize);

impl MetaElectionHandle {
    /// Handle to the current election.
    pub const CURRENT: Self = MetaElectionHandle(usize::MAX);
}

struct MetaElection<P: PublicId> {
    meta_votes: MetaVotes<P>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<P, Vec<RoundHash>>,
    // Set of peers who haven't decided this election yet.
    undecided_peers: BTreeSet<P>,
}

impl<P: PublicId> MetaElection<P> {
    fn new<'a, I>(voters: I) -> Self
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        MetaElection {
            meta_votes: BTreeMap::new(),
            round_hashes: BTreeMap::new(),
            undecided_peers: voters.into_iter().cloned().collect(),
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
    // Current ongoing meta-election.
    current: MetaElection<P>,
    // Meta-elections decided by us, but not by all peers.
    decided: BTreeMap<MetaElectionHandle, MetaElection<P>>,
    // Hashes of the consensused blocks in the order they were consensused.
    history: Vec<Hash>,
    // Index of next decided meta-election
    next_index: usize,
}

impl<P: PublicId> MetaElections<P> {
    pub fn new<'a, I>(voters: I) -> Self
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        MetaElections {
            current: MetaElection::new(voters),
            decided: BTreeMap::new(),
            history: Vec::new(),
            next_index: 0,
        }
    }

    pub fn all<'a>(&'a self) -> impl Iterator<Item = MetaElectionHandle> + 'a {
        self.decided
            .keys()
            .cloned()
            .chain(iter::once(MetaElectionHandle::CURRENT))
    }

    /// Elections that were already decided by us, but not by all peers.
    pub fn decided<'a>(&'a self) -> impl Iterator<Item = MetaElectionHandle> + 'a {
        self.decided.keys().cloned()
    }

    pub fn meta_votes(
        &self,
        handle: MetaElectionHandle,
        event_hash: &Hash,
    ) -> Option<&BTreeMap<P, Vec<MetaVote>>> {
        self.get(handle).and_then(|e| e.meta_votes.get(event_hash))
    }

    pub(crate) fn round_hashes(
        &self,
        handle: MetaElectionHandle,
        peer_id: &P,
    ) -> Option<&Vec<RoundHash>> {
        self.get(handle).and_then(|e| e.round_hashes.get(peer_id))
    }

    pub fn consensus_history(&self) -> &[Hash] {
        &self.history
    }

    /// Creates new election and returns handle of the previous elections.
    pub fn new_election<'a, I>(&mut self, payload_hash: Hash, voters: I) -> MetaElectionHandle
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let previous = mem::replace(&mut self.current, MetaElection::new(voters));
        let handle = self.next_handle();

        let _ = self.decided.insert(handle, previous);
        self.history.push(payload_hash);

        handle
    }

    /// Mark the given election as decided by the given peer. If there are no more undecided peers,
    /// the election is removed.
    pub fn mark_as_decided(&mut self, election: MetaElectionHandle, peer_id: &P) {
        if let Entry::Occupied(mut entry) = self.decided.entry(election) {
            let _ = entry.get_mut().undecided_peers.remove(peer_id);
            if entry.get().undecided_peers.is_empty() {
                let _ = entry.remove();
            }
        }
    }

    pub fn handle_peer_removed(&mut self, peer_id: &P) {
        let mut to_remove = Vec::new();

        for (handle, election) in &mut self.decided {
            let _ = election.undecided_peers.remove(peer_id);
            if election.undecided_peers.is_empty() {
                to_remove.push(*handle);
            }
        }

        for handle in to_remove {
            let _ = self.decided.remove(&handle);
        }
    }

    pub fn insert(
        &mut self,
        handle: MetaElectionHandle,
        event_hash: Hash,
        meta_votes: BTreeMap<P, Vec<MetaVote>>,
    ) {
        if let Some(election) = self.get_mut(handle) {
            let _ = election.meta_votes.insert(event_hash, meta_votes);
        }
    }

    pub fn restart_current_election_round_hashes<'a, I>(&mut self, peer_ids: I)
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let hash = self.history.last().cloned().unwrap_or_else(Hash::all_zero);
        self.initialise_current_election_round_hashes(peer_ids, hash);
    }

    pub fn update_round_hashes(&mut self, handle: MetaElectionHandle, event_hash: &Hash) {
        let election = if let Some(election) = self.get_mut(handle) {
            election
        } else {
            return;
        };

        let meta_votes = if let Some(meta_votes) = election.meta_votes.get(event_hash) {
            meta_votes
        } else {
            return;
        };

        for (peer_id, event_votes) in meta_votes {
            for meta_vote in event_votes {
                let hashes = if let Some(hashes) = election.round_hashes.get_mut(&peer_id) {
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
        self.current.initialise_round_hashes(peer_ids, initial_hash);
    }

    pub fn current_meta_votes(&self) -> &MetaVotes<P> {
        &self.current.meta_votes
    }

    fn get(&self, handle: MetaElectionHandle) -> Option<&MetaElection<P>> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&self.current)
        } else {
            self.decided.get(&handle)
        }
    }

    fn get_mut(&mut self, handle: MetaElectionHandle) -> Option<&mut MetaElection<P>> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&mut self.current)
        } else {
            self.decided.get_mut(&handle)
        }
    }

    fn next_handle(&mut self) -> MetaElectionHandle {
        let handle = MetaElectionHandle(self.next_index);

        if self.next_index == usize::MAX - 1 {
            self.next_index = 0;
        } else {
            self.next_index += 1;
        }

        handle
    }
}

#[cfg(test)]
impl<P: PublicId> MetaElections<P> {
    pub fn new_from_parsed<'a, I>(voters: I, votes: MetaVotes<P>) -> Self
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let mut new = Self::new(voters);
        new.current.meta_votes = votes;
        new
    }
}
