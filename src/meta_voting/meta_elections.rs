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
use network_event::NetworkEvent;
use observation::Observation;
use round_hash::RoundHash;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug};
use std::{iter, mem, usize};

/// Handle that uniquely identifies a `MetaElection`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct MetaElectionHandle(usize);

impl MetaElectionHandle {
    /// Handle to the current election.
    pub const CURRENT: Self = MetaElectionHandle(usize::MAX);
}

impl Debug for MetaElectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MetaElectionHandle(")?;

        if *self == Self::CURRENT {
            write!(f, "CURRENT")?
        } else {
            write!(f, "{}", self.0)?
        }

        write!(f, ")")
    }
}

struct MetaElection<T: NetworkEvent, P: PublicId> {
    meta_votes: BTreeMap<Hash, MetaVotes<P>>,
    meta_events: BTreeMap<Hash, MetaEvent<P>>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<P, Vec<RoundHash>>,
    // Set of peers who haven't decided this election yet.
    undecided_peers: BTreeSet<P>,
    outcome: Option<Outcome<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> MetaElection<T, P> {
    fn new<'a, I>(voters: I) -> Self
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        MetaElection {
            meta_votes: BTreeMap::new(),
            meta_events: BTreeMap::new(),
            round_hashes: BTreeMap::new(),
            undecided_peers: voters.into_iter().cloned().collect(),
            outcome: None,
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

// Outcome of a meta-election.
struct Outcome<T: NetworkEvent, P: PublicId> {
    // Payload decided by this election
    payload: Observation<T, P>,
    // Number of voters at the time this election was decided.
    voter_count: usize,
}

pub(crate) struct MetaEvent<P> {
    // The set of peers for which this event can strongly-see an event by that peer which carries a
    // valid block.  If there are a supermajority of peers here, this event is an "observer".
    pub observations: BTreeSet<P>,
}

impl<P: PublicId> MetaEvent<P> {
    fn new() -> Self {
        MetaEvent {
            observations: BTreeSet::new(),
        }
    }
}

pub(crate) struct MetaElections<T: NetworkEvent, P: PublicId> {
    // Current ongoing meta-election.
    current_election: MetaElection<T, P>,
    // Meta-elections that are already decided by us, but not by all the other peers.
    previous_elections: BTreeMap<MetaElectionHandle, MetaElection<T, P>>,
    // Hashes of the consensused blocks in the order they were consensused.
    consensus_history: Vec<Hash>,
    // Index of next decided meta-election
    next_index: usize,
}

impl<T: NetworkEvent, P: PublicId> MetaElections<T, P> {
    pub fn new<'a, I>(voters: I) -> Self
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        MetaElections {
            current_election: MetaElection::new(voters),
            previous_elections: BTreeMap::new(),
            consensus_history: Vec::new(),
            next_index: 0,
        }
    }

    pub fn all<'a>(&'a self) -> impl Iterator<Item = MetaElectionHandle> + 'a {
        self.previous_elections
            .keys()
            .cloned()
            .chain(iter::once(MetaElectionHandle::CURRENT))
    }

    /// Elections that were already decided by us, but not by the given peer.
    pub fn undecided_by<'a, 'b: 'a, 'c: 'a>(
        &'b self,
        peer_id: &'c P,
    ) -> impl Iterator<Item = MetaElectionHandle> + 'a {
        self.previous_elections
            .iter()
            .filter(move |(_, election)| election.undecided_peers.contains(peer_id))
            .map(|(handle, _)| *handle)
    }

    pub fn meta_votes(
        &self,
        handle: MetaElectionHandle,
        event_hash: &Hash,
    ) -> Option<&BTreeMap<P, Vec<MetaVote>>> {
        self.get(handle).and_then(|e| e.meta_votes.get(event_hash))
    }

    pub fn add_meta_event(&mut self, handle: MetaElectionHandle, event_hash: Hash) {
        if let Some(election) = self.get_mut(handle) {
            let _ = election.meta_events.insert(event_hash, MetaEvent::new());
        }
    }

    pub fn meta_event(
        &self,
        handle: MetaElectionHandle,
        event_hash: &Hash,
    ) -> Option<&MetaEvent<P>> {
        self.get(handle)
            .and_then(|election| election.meta_events.get(event_hash))
    }

    pub fn meta_event_mut(
        &mut self,
        handle: MetaElectionHandle,
        event_hash: &Hash,
    ) -> Option<&mut MetaEvent<P>> {
        self.get_mut(handle)
            .and_then(|election| election.meta_events.get_mut(event_hash))
    }

    pub fn round_hashes(&self, handle: MetaElectionHandle, peer_id: &P) -> Option<&Vec<RoundHash>> {
        self.get(handle).and_then(|e| e.round_hashes.get(peer_id))
    }

    /// Payload decided by the given meta-election, if any.
    pub fn decided_payload(&self, handle: MetaElectionHandle) -> Option<&Observation<T, P>> {
        self.get(handle)
            .and_then(|election| election.outcome.as_ref())
            .map(|outcome| &outcome.payload)
    }

    /// Number of voters at the time the given meta-election was decided. `None` if not yet decided.
    pub fn decided_voter_count(&self, handle: MetaElectionHandle) -> Option<usize> {
        self.get(handle)
            .and_then(|election| election.outcome.as_ref())
            .map(|outcome| outcome.voter_count)
    }

    pub fn consensus_history(&self) -> &[Hash] {
        &self.consensus_history
    }

    /// Creates new election and returns handle of the previous elections.
    pub fn new_election<'a, I>(
        &mut self,
        payload: Observation<T, P>,
        voters: I,
    ) -> MetaElectionHandle
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let hash = payload.create_hash();
        let new = MetaElection::new(voters);
        let voter_count = new.undecided_peers.len();

        let mut previous = mem::replace(&mut self.current_election, new);
        previous.outcome = Some(Outcome {
            payload,
            voter_count,
        });

        let handle = self.next_handle();
        let _ = self.previous_elections.insert(handle, previous);
        self.consensus_history.push(hash);

        handle
    }

    /// Mark the given election as decided by the given peer. If there are no more undecided peers,
    /// the election is removed.
    pub fn mark_as_decided(&mut self, handle: MetaElectionHandle, peer_id: &P) {
        if let Entry::Occupied(mut entry) = self.previous_elections.entry(handle) {
            let _ = entry.get_mut().undecided_peers.remove(peer_id);
            if entry.get().undecided_peers.is_empty() {
                let _ = entry.remove();
            }
        } else {
            Self::not_found(handle)
        }
    }

    pub fn handle_peer_removed(&mut self, peer_id: &P) {
        let mut to_remove = Vec::new();

        for (handle, election) in &mut self.previous_elections {
            let _ = election.undecided_peers.remove(peer_id);
            if election.undecided_peers.is_empty() {
                to_remove.push(*handle);
            }
        }

        for handle in to_remove {
            let _ = self.previous_elections.remove(&handle);
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
        let hash = self.consensus_history.last().cloned().unwrap_or(Hash::ZERO);
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
        self.current_election
            .initialise_round_hashes(peer_ids, initial_hash);
    }

    pub fn current_meta_votes(&self) -> &BTreeMap<Hash, MetaVotes<P>> {
        &self.current_election.meta_votes
    }

    fn get(&self, handle: MetaElectionHandle) -> Option<&MetaElection<T, P>> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&self.current_election)
        } else if let Some(election) = self.previous_elections.get(&handle) {
            Some(election)
        } else {
            Self::not_found(handle);
            None
        }
    }

    fn get_mut(&mut self, handle: MetaElectionHandle) -> Option<&mut MetaElection<T, P>> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&mut self.current_election)
        } else if let Some(election) = self.previous_elections.get_mut(&handle) {
            Some(election)
        } else {
            Self::not_found(handle);
            None
        }
    }

    fn not_found(handle: MetaElectionHandle) {
        log_or_panic!("Meta-election at {:?} not found", handle);
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
impl<T: NetworkEvent, P: PublicId> MetaElections<T, P> {
    pub fn new_from_parsed<'a, I>(voters: I, votes: BTreeMap<Hash, MetaVotes<P>>) -> Self
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let mut new = Self::new(voters);
        new.current_election.meta_votes = votes;
        new
    }
}
