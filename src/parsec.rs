// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
use error::Error;
use gossip::{Event, Request, Response};
use hash::Hash;
use id::{PublicId, SecretId};
use network_event::NetworkEvent;
use peer_manager::PeerManager;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use vote::Vote;

// The struct holds an event's meta votes towards a candidate voter, according to the PARSEC.
#[derive(Default)]
struct BinaryVote {
    round: u32,
    step: u32,
    estimate: BTreeSet<bool>,
    bin_values: BTreeSet<bool>,
    aux_vote: Option<bool>,
    decision: Option<bool>,
}

// The struct used to collect the meta votes of other events according to the PARSEC algorithm.
#[derive(Default)]
struct MetaVoteCollection<P: PublicId> {
    // Voters that casted that estimate value.
    estimates: BTreeMap<bool, BTreeSet<P>>,
    // Voters that casted that bin_value.
    bin_values: BTreeMap<bool, BTreeSet<P>>,
    // Voters that casted that aux_vote value.
    aux_vote: BTreeMap<bool, BTreeSet<P>>,
}

impl<P: PublicId> MetaVoteCollection<P> {
    fn union(&mut self, voter: &P, binary_vote: &BinaryVote) {
        for est in &binary_vote.estimate {
            let _ = self
                .estimates
                .entry(*est)
                .or_insert_with(BTreeSet::new)
                .insert(voter.clone());
        }
        for bin_val in &binary_vote.bin_values {
            let _ = self
                .bin_values
                .entry(*bin_val)
                .or_insert_with(BTreeSet::new)
                .insert(voter.clone());
        }
        if let Some(aux_vote) = binary_vote.aux_vote {
            let _ = self
                .aux_vote
                .entry(aux_vote)
                .or_insert_with(BTreeSet::new)
                .insert(voter.clone());
        }
    }
}

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // Holding PeerInfo of other nodes.
    peer_manager: PeerManager<S>,
    // Gossip events created locally and received from other peers.
    events: BTreeMap<Hash, Event<T, S::PublicId>>,
    // The hash of every stable block already returned via `poll()`.
    polled_blocks: BTreeSet<Hash>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: Vec<Block<T, S::PublicId>>,
    // Holding meta votes of the events
    meta_votes: BTreeMap<Hash, BTreeMap<S::PublicId, BinaryVote>>,
}

// TODO - remove
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Create a new `Parsec` for a peer with the given ID and genesis peer IDs.
    pub fn new(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Result<Self, Error> {
        let mut peer_manager = PeerManager::new(our_id);
        for peer_id in genesis_group.iter() {
            peer_manager.add_peer(peer_id.clone());
        }
        Ok(Parsec {
            peer_manager,
            events: BTreeMap::new(),
            polled_blocks: BTreeSet::new(),
            consensused_blocks: Vec::new(),
            meta_votes: BTreeMap::new(),
        })
    }

    /// Add a vote for `network_event`.
    pub fn vote_for(&mut self, network_event: T) -> Result<(), Error> {
        let our_pub_id = self.peer_manager.our_id().public_id();
        let next_index = if let Some(last_index) = self.peer_manager.last_event_index(our_pub_id) {
            last_index + 1
        } else {
            return Err(Error::InvalidEvent);
        };
        let self_parent_hash =
            if let Some(last_hash) = self.peer_manager.last_event_hash(our_pub_id) {
                last_hash
            } else {
                return Err(Error::InvalidEvent);
            };
        let event = Event::new_from_observation(
            self.peer_manager.our_id(),
            *self_parent_hash,
            network_event,
        )?;
        let _ = self.events.insert(*event.hash(), event);
        Ok(())
    }

    /// Create a new message to be gossiped to a random peer.
    pub fn create_gossip(&self) -> Request<T, S::PublicId> {
        Request::new(self.events.values())
    }

    /// Handle a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>, Error> {
        unimplemented!();
    }

    /// Handle a received `Response` from `src` peer.  Returns `Err` if the response was not valid.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        unimplemented!();
    }

    /// Step the algorithm and return the next stable block, if any.
    pub fn poll(&mut self) -> Result<Option<Block<T, S::PublicId>>, Error> {
        unimplemented!();
    }

    /// Check if the given `network_event` has already been voted for by us.
    pub fn have_voted_for(&self, network_event: &T) -> bool {
        let our_pub_id = self.peer_manager.our_id().public_id();
        self.events.values().any(|event| {
            if event.creator() == our_pub_id {
                if let Some(voted) = event.vote() {
                    voted.payload() == network_event
                } else {
                    false
                }
            } else {
                false
            }
        })
    }

    fn self_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.self_parent().and_then(|hash| self.events.get(hash))
    }

    fn other_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.other_parent().and_then(|hash| self.events.get(hash))
    }

    // This should only be called once `event` has had its `index` set correctly.
    fn set_last_ancestors(&self, event: &mut Event<T, S::PublicId>) -> Result<(), Error> {
        let event_index = if let Some(index) = event.index {
            index
        } else {
            return Err(Error::InvalidEvent);
        };

        if let Some(self_parent) = self.self_parent(event) {
            event.last_ancestors = self_parent.last_ancestors.clone();

            if let Some(other_parent) = self.other_parent(event) {
                for (peer_id, _) in self.peer_manager.iter() {
                    if let Some(other_index) = other_parent.last_ancestors.get(peer_id) {
                        let existing_index = event
                            .last_ancestors
                            .entry(peer_id.clone())
                            .or_insert(*other_index);
                        if *existing_index < *other_index {
                            *existing_index = *other_index;
                        }
                    }
                }
            }
        } else if let Some(other_parent) = self.other_parent(event) {
            // If we have no self-parent, we should also have no other-parent.
            return Err(Error::InvalidEvent);
        }

        let creator_id = event.creator().clone();
        let _ = event.last_ancestors.insert(creator_id, event_index);
        Ok(())
    }

    // This should be called only once `event` has had its `index` and `last_ancestors` set
    // correctly (i.e. after calling `Parsec::set_last_ancestors()` on it)
    fn set_first_descendants(&mut self, event: &mut Event<T, S::PublicId>) -> Result<(), Error> {
        if event.last_ancestors.is_empty() {
            return Err(Error::InvalidEvent);
        }

        let event_index = if let Some(index) = event.index {
            index
        } else {
            return Err(Error::InvalidEvent);
        };
        let creator_id = event.creator().clone();
        let _ = event.first_descendants.insert(creator_id, event_index);

        for (peer_id, peer_info) in self.peer_manager.iter() {
            let mut opt_hash = event
                .last_ancestors
                .get(peer_id)
                .and_then(|index| peer_info.get(index))
                .cloned();

            loop {
                if let Some(hash) = opt_hash {
                    if let Some(other_event) = self.events.get_mut(&hash) {
                        if !other_event.first_descendants.contains_key(event.creator()) {
                            let _ = other_event
                                .first_descendants
                                .insert(event.creator().clone(), event_index);
                            opt_hash = other_event.self_parent().cloned();
                            continue;
                        }
                    }
                }
                break;
            }
        }

        Ok(())
    }

    // Returns whether event X can strongly see the event Y.
    fn does_strongly_see(&self, x: &Event<T, S::PublicId>, y: &Event<T, S::PublicId>) -> bool {
        let count = y
            .first_descendants
            .iter()
            .filter(|(peer_id, descendant)| {
                x.last_ancestors
                    .get(&peer_id)
                    .map(|last_ancestor| last_ancestor >= *descendant)
                    .unwrap_or(false)
            })
            .count();

        self.peer_manager.is_super_majority(count)
    }

    // Returns whether event X is seeing event Y.
    fn does_see(x: &Event<T, S::PublicId>, y: &Event<T, S::PublicId>) -> bool {
        let target_index = if let Some(index) = x.index {
            index
        } else {
            return false;
        };
        y.first_descendants
            .get(x.creator())
            .map(|&index| index <= target_index)
            .unwrap_or(false)
    }

    // Crawls along the graph started from the event till the events of last consensused, to collect
    // the meta votes.
    fn collect_meta_votes(
        &self,
        cur_round: u32,
        cur_step: u32,
        voter: &S::PublicId,
        event: &Event<T, S::PublicId>,
        collections: &mut MetaVoteCollection<S::PublicId>,
        last_consensed_events: &BTreeMap<S::PublicId, Event<T, S::PublicId>>,
    ) {
        self.collect_parent_meta_votes(
            cur_round,
            cur_step,
            voter,
            self.self_parent(event),
            collections,
            last_consensed_events,
        );
        self.collect_parent_meta_votes(
            cur_round,
            cur_step,
            voter,
            self.other_parent(event),
            collections,
            last_consensed_events,
        );
    }

    // Collects the meta votes of the parent event.
    fn collect_parent_meta_votes(
        &self,
        cur_round: u32,
        cur_step: u32,
        voter: &S::PublicId,
        parent_event: Option<&Event<T, S::PublicId>>,
        collections: &mut MetaVoteCollection<S::PublicId>,
        last_consensed_events: &BTreeMap<S::PublicId, Event<T, S::PublicId>>,
    ) {
        if let Some(parent) = parent_event {
            if let Some(meta_vote) = self
                .meta_votes
                .get(parent.hash())
                .and_then(|votes| votes.get(voter))
            {
                if meta_vote.round == cur_round && meta_vote.step == cur_step {
                    collections.union(parent.creator(), meta_vote);
                }
            }
            let cur_index = parent.index.unwrap_or(0);
            let boundary_index = last_consensed_events
                .get(parent.creator())
                .and_then(|event| event.index)
                .unwrap_or(0);
            if cur_index > boundary_index {
                self.collect_meta_votes(
                    cur_round,
                    cur_step,
                    voter,
                    parent,
                    collections,
                    last_consensed_events,
                );
            }
        }
    }
}
