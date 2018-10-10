// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use gossip::Event;
use hash::Hash;
use id::{PublicId, SecretId};
#[cfg(test)]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use parsec::is_more_than_two_thirds;
use serialise;
use std::collections::btree_map::{self, BTreeMap, Entry};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::ops::{BitOr, BitOrAssign};

pub(crate) struct PeerList<S: SecretId> {
    our_id: S,
    peers: BTreeMap<S::PublicId, Peer<S::PublicId>>,
    // Map of Hash(peer_id) => peer_id.
    peer_id_hashes: Vec<(Hash, S::PublicId)>,
}

impl<S: SecretId> PeerList<S> {
    pub fn new(our_id: S) -> Self {
        PeerList {
            our_id,
            peers: BTreeMap::new(),
            peer_id_hashes: vec![],
        }
    }

    pub fn our_id(&self) -> &S {
        &self.our_id
    }

    /// Returns all sorted peer_ids.
    pub fn all_ids(&self) -> impl Iterator<Item = &S::PublicId> {
        self.peers.keys()
    }

    /// Returns ids of all peers that can vote.
    pub fn voter_ids(&self) -> impl Iterator<Item = &S::PublicId> {
        self.voters().map(|(id, _)| id)
    }

    /// Returns an unsorted map of Hash(peer_id) => peer_id.
    pub fn peer_id_hashes(&self) -> &Vec<(Hash, S::PublicId)> {
        &self.peer_id_hashes
    }

    /// Returns an iterator of peers.
    pub fn iter(&self) -> btree_map::Iter<S::PublicId, Peer<S::PublicId>> {
        self.peers.iter()
    }

    /// Returns an iterator of peers that can vote.
    pub fn voters(&self) -> impl Iterator<Item = (&S::PublicId, &Peer<S::PublicId>)> {
        self.peers.iter().filter(|(_, peer)| peer.state.can_vote())
    }

    // TODO: remove the allow(unused) attribute.
    #[allow(unused)]
    pub fn peer(&self, peer_id: &S::PublicId) -> Option<&Peer<S::PublicId>> {
        self.peers.get(peer_id)
    }

    pub fn peer_mut(&mut self, peer_id: &S::PublicId) -> Option<&mut Peer<S::PublicId>> {
        self.peers.get_mut(peer_id)
    }

    pub fn peer_state(&self, peer_id: &S::PublicId) -> PeerState {
        self.peers
            .get(peer_id)
            .map(|peer| peer.state)
            .unwrap_or_else(PeerState::inactive)
    }

    pub fn our_state(&self) -> PeerState {
        self.peer_state(self.our_id.public_id())
    }

    /// Adds a peer in the given state into the map. If the peer has already been added, merges its
    /// state with the one given.
    pub fn add_peer(&mut self, peer_id: S::PublicId, state: PeerState) -> &mut Peer<S::PublicId> {
        match self.peers.entry(peer_id.clone()) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().state |= state;
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                self.peer_id_hashes
                    .push((Hash::from(serialise(&peer_id).as_slice()), peer_id));
                entry.insert(Peer::new(state))
            }
        }
    }

    pub fn remove_peer(&mut self, peer_id: &S::PublicId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = PeerState::inactive();
        } else {
            debug!(
                "{:?} tried to remove unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            );
        }
    }

    /// Checks whether the input count becomes the super majority of the members that can vote.
    pub fn is_super_majority(&self, count: usize) -> bool {
        is_more_than_two_thirds(count, self.voters().count())
    }

    /// Returns the hash of the last event created by this peer. Returns `None` if cannot find.
    pub fn last_event(&self, peer_id: &S::PublicId) -> Option<&Hash> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.events().rev().next())
    }

    /// Returns the hash of the indexed event.
    pub fn event_by_index(&self, peer_id: &S::PublicId, index: u64) -> Option<&Hash> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.event_by_index(index))
    }

    /// Adds event created by the peer. Returns an error if the creator is not known, or if we
    /// already held an event from this peer with this index, but that event's hash is different to
    /// the one being added (in which case `peers` is left unmodified).
    pub fn add_event<T: NetworkEvent>(
        &mut self,
        event: &Event<T, S::PublicId>,
    ) -> Result<(), Error> {
        if let Some(peer) = self.peers.get_mut(event.creator()) {
            if *event.creator() != *self.our_id.public_id() && !peer.state.can_send() {
                return Err(Error::InvalidPeerState {
                    required: PeerState::SEND,
                    actual: peer.state,
                });
            }

            match peer.events.entry(event.index()) {
                Entry::Occupied(entry) => {
                    if entry.get() != event.hash() {
                        return Err(Error::InvalidEvent);
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(*event.hash());
                }
            }
            Ok(())
        } else {
            Err(Error::UnknownPeer)
        }
    }

    /// Removes the event from its creator.
    #[cfg(test)]
    pub fn remove_event<T: NetworkEvent>(&mut self, event: &Event<T, S::PublicId>) {
        if let Some(peer) = self.peers.get_mut(event.creator()) {
            let _ = peer.events.remove(&event.index());
        }
    }

    /// Hashes of events of the given creator, in insertion order.
    pub fn peer_events(&self, peer_id: &S::PublicId) -> impl DoubleEndedIterator<Item = &Hash> {
        self.peers
            .get(peer_id)
            .into_iter()
            .flat_map(|peer| peer.events())
    }

    /// Hashes of our events in insertion order.
    pub fn our_events(&self) -> impl DoubleEndedIterator<Item = &Hash> {
        self.peer_events(self.our_id.public_id())
    }
}

impl<S: SecretId> Debug for PeerList<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(
            formatter,
            "PeerList{{ our_id: {:?}",
            self.our_id.public_id()
        )?;
        for peer in &self.peers {
            writeln!(formatter, "    {:?},", peer)?;
        }
        writeln!(formatter, "    {:?}", self.peer_id_hashes)?;
        write!(formatter, "}}")
    }
}

#[cfg(test)]
impl PeerList<PeerId> {
    // Creates a new PeerList using the input parameters directly.
    pub(super) fn new_from_dot_input(
        our_id: PeerId,
        events_graph: &BTreeMap<Hash, Event<Transaction, PeerId>>,
        peer_states: &BTreeMap<PeerId, PeerState>,
    ) -> Self {
        let mut peers = BTreeMap::new();
        let mut peer_id_hashes = Vec::new();
        for (peer_id, &state) in peer_states {
            let mut events = BTreeMap::new();
            for event in events_graph.values() {
                if event.creator() == peer_id {
                    if let Some(prev_hash) = events.insert(event.index(), *event.hash()) {
                        debug!(
                            "index of {:?} updated from {:?} to {:?}",
                            event.index(),
                            prev_hash,
                            event.hash()
                        );
                    }
                } else if !peer_states.contains_key(event.creator()) {
                    debug!(
                        "peer_states list doesn't contain the creator of event {:?}",
                        event
                    );
                }
            }

            let _ = peers.insert(
                peer_id.clone(),
                Peer {
                    state,
                    events,
                    peers: BTreeSet::new(),
                },
            );
            peer_id_hashes.push((Hash::from(serialise(&peer_id).as_slice()), peer_id.clone()))
        }

        PeerList {
            our_id,
            peers,
            peer_id_hashes,
        }
    }
}

/// Peer state is a bitflag with these flags:
///
/// - `VOTE`: if enabled, the peer can vote, which means they are counted towards the supermajority.
/// - `SEND`: if enabled, the peer can send gossips. For us it means we can send gossips to others.
///           For others it means we can receive gossips from them.
/// - `RECV`: if enabled, the peer can receive gossips. For us, it means we can receive gossips from
///           others. For others it means we can send gossips to them.
///
/// If all three are enabled, the state is called `active`. If none is enabled, it's `inactive`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerState(u8);

impl PeerState {
    /// The peer is counted towards supermajority.
    pub const VOTE: Self = PeerState(0b0000_0001);
    /// The peer can send gossips.
    pub const SEND: Self = PeerState(0b0000_0010);
    /// The peer can receive gossips.
    pub const RECV: Self = PeerState(0b0000_0100);

    pub fn inactive() -> Self {
        PeerState(0)
    }

    pub fn active() -> Self {
        Self::VOTE | Self::SEND | Self::RECV
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn can_vote(self) -> bool {
        self.contains(Self::VOTE)
    }

    pub fn can_send(self) -> bool {
        self.contains(Self::SEND)
    }

    pub fn can_recv(self) -> bool {
        self.contains(Self::RECV)
    }
}

impl BitOr for PeerState {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        PeerState(self.0 | rhs.0)
    }
}

impl BitOrAssign for PeerState {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

impl Debug for PeerState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut separator = false;

        write!(f, "PeerState(");

        if self.contains(Self::VOTE) {
            separator = true;
            write!(f, "VOTE");
        }

        if self.contains(Self::SEND) {
            if separator {
                write!(f, "|");
            }
            separator = true;
            write!(f, "SEND");
        }

        if self.contains(Self::RECV) {
            if separator {
                write!(f, "|");
            }
            write!(f, "RECV");
        }

        write!(f, ")")
    }
}

#[derive(Debug)]
pub struct Peer<P: PublicId> {
    state: PeerState,
    events: BTreeMap<u64, Hash>,
    peers: BTreeSet<P>,
}

impl<P: PublicId> Peer<P> {
    fn new(state: PeerState) -> Self {
        Self {
            state,
            events: BTreeMap::new(),
            peers: BTreeSet::new(),
        }
    }

    pub fn state(&self) -> PeerState {
        self.state
    }

    pub fn events(&self) -> impl DoubleEndedIterator<Item = &Hash> {
        self.events.values()
    }

    pub fn indexed_events(&self) -> impl DoubleEndedIterator<Item = (u64, &Hash)> {
        self.events.iter().map(|(index, hash)| (*index, hash))
    }

    pub fn event_by_index(&self, index: u64) -> Option<&Hash> {
        self.events.get(&index)
    }

    pub fn add_peer(&mut self, peer_id: P) {
        let _ = self.peers.insert(peer_id);
    }

    pub fn add_peers<'a, I>(&mut self, peer_ids: I)
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        self.peers.extend(peer_ids.into_iter().cloned())
    }

    pub fn remove_peer(&mut self, peer_id: &P) {
        let _ = self.peers.remove(peer_id);
    }

    // TODO: remove the allow(unused) attribute.
    #[allow(unused)]
    pub fn has_peer(&self, peer_id: &P) -> bool {
        self.peers.contains(peer_id)
    }
}
