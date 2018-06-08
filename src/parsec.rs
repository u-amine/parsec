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
use meta_vote::MetaVote;
use network_event::NetworkEvent;
use peer_manager::PeerManager;
use round_hash::RoundHash;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use vote::Vote;

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_manager: PeerManager<S>,
    // Gossip events created locally and received from other peers.
    events: BTreeMap<Hash, Event<T, S::PublicId>>,
    // The hash of every stable block already returned via `poll()`.
    polled_blocks: BTreeSet<Hash>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: Vec<Block<T, S::PublicId>>,
    // The meta votes of the events.
    meta_votes: BTreeMap<Hash, BTreeMap<S::PublicId, MetaVote>>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<S::PublicId, Vec<RoundHash>>,
    responsiveness_threshold: usize,
}

// TODO - remove
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs.
    pub fn new(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Result<Self, Error> {
        unimplemented!();
    }

    /// Adds a vote for `network_event`.
    pub fn vote_for(&mut self, network_event: T) {
        unimplemented!();
    }

    /// Creates a new message to be gossiped to a random peer.
    pub fn create_gossip(&self) -> Request<T, S::PublicId> {
        unimplemented!();
    }

    /// Handles a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>, Error> {
        unimplemented!();
    }

    /// Handles a received `Response` from `src` peer.  Returns `Err` if the response was not valid.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        unimplemented!();
    }

    /// Steps the algorithm and returns the next stable block, if any.
    pub fn poll(&mut self) -> Result<Option<Block<T, S::PublicId>>, Error> {
        unimplemented!();
    }

    /// Checks if the given `network_event` has already been voted for by us.
    pub fn have_voted_for(&self, network_event: &T) -> bool {
        unimplemented!();
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

    fn add_event(&mut self, mut event: Event<T, S::PublicId>) -> Result<(), Error> {
        if self.events.contains_key(event.hash()) {
            return Ok(());
        }

        if self.self_parent(&event).is_none() || self.other_parent(&event).is_none() {
            return Err(Error::UnknownParent);
        }

        self.set_index(&mut event);
        self.peer_manager.add_event(event.creator(), &event)?;
        self.set_last_ancestors(&mut event)?;
        self.set_first_descendants(&mut event)?;
        self.set_valid_blocks_carried(&mut event)?;
        self.set_observations(&mut event)?;
        self.set_meta_votes(&event)?;
        let _ = self.events.insert(*event.hash(), event);
        Ok(())
    }

    fn set_index(&self, event: &mut Event<T, S::PublicId>) {
        event.index = Some(
            self.self_parent(event)
                .and_then(|parent| parent.index)
                .map_or(0, |index| index + 1),
        );
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

    fn set_valid_blocks_carried(&mut self, event: &mut Event<T, S::PublicId>) -> Result<(), Error> {
        // If this node already has meta votes running, no need to calculate `valid_blocks_carried`.
        if self
            .self_parent(event)
            .and_then(|parent| self.meta_votes.get(parent.hash()))
            .is_some()
        {
            return Ok(());
        }
        unimplemented!();
    }

    fn set_observations(&mut self, event: &mut Event<T, S::PublicId>) -> Result<(), Error> {
        // If this node already has meta votes running, no need to calculate `observations`.
        if self
            .self_parent(event)
            .and_then(|parent| self.meta_votes.get(parent.hash()))
            .is_some()
        {
            return Ok(());
        }
        unimplemented!();
    }

    fn set_meta_votes(&mut self, event: &Event<T, S::PublicId>) -> Result<(), Error> {
        let total_peers = self.peer_manager.iter().count();
        if let Some(parent_votes) = self
            .self_parent(event)
            .and_then(|parent| self.meta_votes.get(parent.hash()))
        {
            for (peer_id, parent_vote) in parent_votes {
                // Safe to unwrap as `self_parent(event)` returned `Some` just above.
                let parent_hash = *unwrap!(event.self_parent());
                let coin_toss = self.toss_coin(peer_id, parent_vote, parent_hash);
                let other_votes = if parent_vote.estimates.is_empty() {
                    // If `estimates` is empty, we've been waiting for the result of a coin toss.
                    // In that case, we don't care about any other votes, we just need the coin toss
                    // result.
                    vec![]
                } else {
                    self.meta_votes
                        .values()
                        .filter_map(|meta_votes| meta_votes.get(peer_id))
                        .collect::<Vec<_>>()
                };
                let meta_vote =
                    MetaVote::next(parent_vote, other_votes.as_slice(), coin_toss, total_peers);
            }
        } else {
        }
        // For each peer {
        //     For each peer {
        //         Get the meta vote from the parent event
        //         Get all other meta votes
        //         Get the round hash
        //         Construct new meta vote
        //         Update round hash if returned meta vote shows its changed
        //     }
        // }
        // if we have decisions for all meta vote sets {
        //     calculate next stable block
        //     clear all meta votes, valid-blocks-carried, and observers
        //     re-evaluate if we need to start new meta votes (set valid-blocks-carried and observers again)
        // }
        unimplemented!();
    }

    fn toss_coin(
        &self,
        peer_id: &S::PublicId,
        parent_vote: &MetaVote,
        parent_hash: Hash,
    ) -> Option<bool> {
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            parent_vote.round - 1
        } else if parent_vote.step == 2 {
            parent_vote.round
        } else {
            return None;
        };
        let round_hash = if let Some(hashes) = self.round_hashes.get(peer_id) {
            hashes[round].value()
        } else {
            // Should be unreachable.
            return None;
        };
        let mut all_peers = self.peer_manager.all_ids();
        None
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

    // // Crawls along the graph started from the event till the events of last consensused, to collect
    // // the meta votes.
    // fn collect_meta_votes(
    //     &self,
    //     cur_round: usize,
    //     cur_step: usize,
    //     voter: &S::PublicId,
    //     event: &Event<T, S::PublicId>,
    //     collections: &mut MetaVoteCollection<S::PublicId>,
    //     last_consensused_events: &BTreeMap<S::PublicId, Event<T, S::PublicId>>,
    // ) {
    //     self.collect_parent_meta_votes(
    //         cur_round,
    //         cur_step,
    //         voter,
    //         self.self_parent(event),
    //         collections,
    //         last_consensused_events,
    //     );
    //     self.collect_parent_meta_votes(
    //         cur_round,
    //         cur_step,
    //         voter,
    //         self.other_parent(event),
    //         collections,
    //         last_consensused_events,
    //     );
    // }

    // // Collects the meta votes of the parent event.
    // fn collect_parent_meta_votes(
    //     &self,
    //     cur_round: usize,
    //     cur_step: usize,
    //     voter: &S::PublicId,
    //     parent_event: Option<&Event<T, S::PublicId>>,
    //     collections: &mut MetaVoteCollection<S::PublicId>,
    //     last_consensused_events: &BTreeMap<S::PublicId, Event<T, S::PublicId>>,
    // ) {
    //     if let Some(parent) = parent_event {
    //         if let Some(meta_vote) = self
    //             .meta_votes
    //             .get(parent.hash())
    //             .and_then(|votes| votes.get(voter))
    //         {
    //             if meta_vote.round == cur_round && meta_vote.step == cur_step {
    //                 collections.union(parent.creator(), meta_vote);
    //             }
    //         }
    //         let cur_index = parent.index.unwrap_or(0);
    //         let boundary_index = last_consensused_events
    //             .get(parent.creator())
    //             .and_then(|event| event.index)
    //             .unwrap_or(0);
    //         if cur_index > boundary_index {
    //             self.collect_meta_votes(
    //                 cur_round,
    //                 cur_step,
    //                 voter,
    //                 parent,
    //                 collections,
    //                 last_consensused_events,
    //             );
    //         }
    //     }
    // }
}
