// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use gossip::cause::Cause;
use gossip::content::Content;
use gossip::packed_event::PackedEvent;
use hash::Hash;
use id::{PublicId, SecretId};
use network_event::NetworkEvent;
use peer_list::PeerList;
use serialise;
use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use vote::Vote;

pub(crate) struct Event<T: NetworkEvent, P: PublicId> {
    content: Content<T, P>,
    // Creator's signature of `content`.
    signature: P::Signature,
    hash: Hash,
    // Sequential index of this event: this event is the `index`-th one made by its creator.
    index: u64,
    // Index of each peer's latest event that is an ancestor of this event.
    last_ancestors: BTreeMap<P, u64>,
    // Payloads of all the blocks made valid by this event
    pub valid_blocks_carried: BTreeSet<T>,
    // The set of peers for which this event can strongly-see an event by that peer which carries a
    // valid block.  If there are a supermajority of peers here, this event is an "observer".
    pub observations: BTreeSet<P>,
}

impl<T: NetworkEvent, P: PublicId> Event<T, P> {
    // Creates a new event as the result of receiving a gossip request message.
    pub fn new_from_request<S: SecretId<PublicId = P>>(
        self_parent: Hash,
        other_parent: Hash,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Self {
        Self::new(
            Cause::Request {
                self_parent,
                other_parent,
            },
            events,
            peer_list,
        )
    }

    // Creates a new event as the result of receiving a gossip response message.
    pub fn new_from_response<S: SecretId<PublicId = P>>(
        self_parent: Hash,
        other_parent: Hash,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Self {
        Self::new(
            Cause::Response {
                self_parent,
                other_parent,
            },
            events,
            peer_list,
        )
    }

    // Creates a new event as the result of observing a network event.
    pub fn new_from_observation<S: SecretId<PublicId = P>>(
        self_parent: Hash,
        network_event: T,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Self {
        let vote = Vote::new(peer_list.our_id(), network_event);
        Self::new(Cause::Observation { self_parent, vote }, events, peer_list)
    }

    // Creates an initial event.  This is the first event by its creator in the graph.
    pub fn new_initial<S: SecretId<PublicId = P>>(peer_list: &PeerList<S>) -> Self {
        Self::new(Cause::Initial, &BTreeMap::new(), peer_list)
    }

    // Creates an event from a `PackedEvent`.
    //
    // Returns:
    //   * `Ok(None)` if the event already exists
    //   * `Err(Error::SignatureFailure)` if signature validation fails
    //   * `Err(Error::UnknownParent)` if the event indicates it should have an ancestor, but the
    //     ancestor isn't in `events`.
    pub(crate) fn unpack<S: SecretId<PublicId = P>>(
        packed_event: PackedEvent<T, P>,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Result<Option<Self>, Error> {
        let serialised_content = serialise(&packed_event.content);
        let hash = if packed_event
            .content
            .creator
            .verify_signature(&packed_event.signature, &serialised_content)
        {
            Hash::from(serialised_content.as_slice())
        } else {
            return Err(Error::SignatureFailure);
        };
        if events.contains_key(&hash) {
            return Ok(None);
        }

        let (index, last_ancestors) =
            Self::index_and_last_ancestors(&packed_event.content, events, peer_list)?;

        // `valid_blocks_carried` and `observations` still need to be set correctly by the caller.
        Ok(Some(Self {
            content: packed_event.content,
            signature: packed_event.signature,
            hash,
            index,
            last_ancestors,
            valid_blocks_carried: BTreeSet::default(),
            observations: BTreeSet::default(),
        }))
    }

    // Creates a `PackedEvent` from this `Event`.
    pub(super) fn pack(&self) -> PackedEvent<T, P> {
        PackedEvent {
            content: self.content.clone(),
            signature: self.signature.clone(),
        }
    }

    // Returns whether this event can see `other`, i.e. whether there's a directed path from `other`
    // to `self` in the graph.
    pub fn sees(&self, other: &Event<T, P>) -> bool {
        self.last_ancestors
            .get(other.creator())
            .map_or(false, |last_index| *last_index >= other.index())
    }

    /// Returns `Some(vote)` if the event is for a vote of network event, otherwise returns `None`.
    pub fn vote(&self) -> Option<&Vote<T, P>> {
        if let Cause::Observation { ref vote, .. } = self.content.cause {
            Some(vote)
        } else {
            None
        }
    }

    pub fn creator(&self) -> &P {
        &self.content.creator
    }

    pub fn self_parent(&self) -> Option<&Hash> {
        self.content.self_parent()
    }

    #[cfg(feature = "dump-graphs")]
    pub fn other_parent(&self) -> Option<&Hash> {
        self.content.other_parent()
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn last_ancestors(&self) -> &BTreeMap<P, u64> {
        &self.last_ancestors
    }

    pub fn is_response(&self) -> bool {
        if let Cause::Response { .. } = self.content.cause {
            true
        } else {
            false
        }
    }

    pub fn is_initial(&self) -> bool {
        if let Cause::Initial = self.content.cause {
            true
        } else {
            false
        }
    }

    fn new<S: SecretId<PublicId = P>>(
        cause: Cause<T, P>,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Self {
        let content = Content {
            creator: peer_list.our_id().public_id().clone(),
            cause,
        };
        let serialised_content = serialise(&content);

        let (index, last_ancestors) = if let Ok((index, last_ancestors)) =
            Self::index_and_last_ancestors(&content, events, peer_list)
        {
            (index, last_ancestors)
        } else {
            log_or_panic!(
                "{:?} constructed an invalid event.",
                peer_list.our_id().public_id()
            );
            (0, BTreeMap::default())
        };

        // `valid_blocks_carried` and `observations` still need to be set correctly by the caller.
        Self {
            content,
            signature: peer_list.our_id().sign_detached(&serialised_content),
            hash: Hash::from(serialised_content.as_slice()),
            index,
            last_ancestors,
            valid_blocks_carried: BTreeSet::default(),
            observations: BTreeSet::default(),
        }
    }

    fn index_and_last_ancestors<S: SecretId<PublicId = P>>(
        content: &Content<T, P>,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Result<(u64, BTreeMap<P, u64>), Error> {
        let self_parent = if let Some(self_parent_hash) = content.self_parent() {
            if let Some(event) = events.get(&self_parent_hash) {
                event
            } else {
                debug!(
                    "{:?} missing self parent for {:?}",
                    peer_list.our_id().public_id(),
                    content
                );
                return Err(Error::UnknownParent);
            }
        } else {
            // This must be an initial event, i.e. having index 0
            let mut last_ancestors = BTreeMap::default();
            let _ = last_ancestors.insert(content.creator.clone(), 0);
            return Ok((0, last_ancestors));
        };

        let index = self_parent.index + 1;
        let mut last_ancestors = self_parent.last_ancestors().clone();

        if let Some(other_parent_hash) = content.other_parent() {
            if let Some(other_parent) = events.get(&other_parent_hash) {
                for (peer_id, _) in peer_list.iter() {
                    if let Some(other_index) = other_parent.last_ancestors().get(peer_id) {
                        let existing_index = last_ancestors
                            .entry(peer_id.clone())
                            .or_insert(*other_index);
                        *existing_index = cmp::max(*existing_index, *other_index);
                    }
                }
            } else {
                debug!(
                    "{:?} missing other parent for {:?}",
                    peer_list.our_id().public_id(),
                    content
                );
                return Err(Error::UnknownParent);
            }
        }
        let _ = last_ancestors.insert(content.creator.clone(), index);
        Ok((index, last_ancestors))
    }
}

impl<T: NetworkEvent, P: PublicId> Debug for Event<T, P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Event{{ {:?}[{}] {:?}",
            self.content.creator, self.index, self.hash,
        )?;
        write!(
            formatter,
            ", {}",
            match &self.content.cause {
                Cause::Request { .. } => "Request".to_string(),
                Cause::Response { .. } => "Response".to_string(),
                Cause::Observation { vote, .. } => format!("Observation({:?})", vote.payload()),
                Cause::Initial => "Initial".to_string(),
            }
        )?;
        write!(
            formatter,
            ", self_parent: {:?}, other_parent: {:?}",
            self.content.self_parent(),
            self.content.other_parent()
        )?;
        write!(formatter, ", last_ancestors: {:?}", self.last_ancestors)?;
        write!(
            formatter,
            ", valid_blocks_carried: {:?}",
            self.valid_blocks_carried
        )?;
        write!(formatter, ", observations: {:?}", self.observations)?;
        write!(formatter, " }}")
    }
}
