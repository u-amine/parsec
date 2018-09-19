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
use id::SecretId;
#[cfg(test)]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use serialise;
use std::collections::btree_map::{self, BTreeMap, Entry};

pub(crate) struct PeerList<S: SecretId> {
    our_id: S,
    peers: BTreeMap<S::PublicId, Peer>,
    // Map of Hash(peer_id) => peer_id
    peer_id_hashes: Vec<(Hash, S::PublicId)>,
}

impl<S: SecretId> PeerList<S> {
    /// Constructor of `PeerList`.
    pub fn new(our_id: S) -> Self {
        PeerList {
            our_id,
            peers: BTreeMap::new(),
            peer_id_hashes: vec![],
        }
    }

    /// Returns `our_id`.
    pub fn our_id(&self) -> &S {
        &self.our_id
    }

    /// Returns all sorted peer_ids.
    pub fn all_ids(&self) -> Vec<&S::PublicId> {
        self.peers.keys().collect()
    }

    /// Returns an unsorted map of Hash(peer_id) => peer_id
    pub fn peer_id_hashes(&self) -> &Vec<(Hash, S::PublicId)> {
        &self.peer_id_hashes
    }

    /// Returns an iterator of peers.
    pub fn iter(&self) -> btree_map::Iter<S::PublicId, Peer> {
        self.peers.iter()
    }

    /// Returns the number of peers.
    pub fn num_peers(&self) -> usize {
        self.peers.len()
    }

    pub fn is_active(&self, peer_id: &S::PublicId) -> bool {
        self.peers.get(peer_id).map_or(false, Peer::is_active)
    }

    pub fn is_removed(&self, peer_id: &S::PublicId) -> bool {
        self.peers.get(peer_id).map_or(false, Peer::is_removed)
    }

    /// Adds a pending peer.
    pub fn add_pending_peer(&mut self, peer_id: S::PublicId) {
        match self.peers.entry(peer_id.clone()) {
            Entry::Occupied(_) => return,
            Entry::Vacant(entry) => {
                let _ = entry.insert(Peer::new_pending());
                self.peer_id_hashes
                    .push((Hash::from(serialise(&peer_id).as_slice()), peer_id));
            }
        }
    }

    /// Adds a peer into the map. If the peer has already been added as pending, activate it.
    pub fn add_peer(&mut self, peer_id: S::PublicId) {
        match self.peers.entry(peer_id.clone()) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().state = PeerState::Active;
            }
            Entry::Vacant(entry) => {
                let _ = entry.insert(Peer::new_active());
                self.peer_id_hashes
                    .push((Hash::from(serialise(&peer_id).as_slice()), peer_id));
            }
        }
    }

    pub fn remove_peer(&mut self, peer_id: &S::PublicId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = PeerState::Removed;
        } else {
            debug!(
                "{:?} tried to remove unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            );
        }
    }

    /// Checks whether the input count becomes the super majority of the network.
    pub fn is_super_majority(&self, count: usize) -> bool {
        3 * count > 2 * self.peers.len()
    }

    /// Returns the hash of the last event created by this peer. Returns `None` if cannot find.
    pub fn last_event_hash(&self, peer_id: &S::PublicId) -> Option<&Hash> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.events.values().rev().next())
    }

    /// Returns the hash of the indexed event.
    pub fn event_by_index(&self, peer_id: &S::PublicId, index: u64) -> Option<&Hash> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.events.get(&index))
    }

    /// Adds event created by the peer. Returns an error if the creator is not known, or if we
    /// already held an event from this peer with this index, but that event's hash is different to
    /// the one being added (in which case `peers` is left unmodified).
    pub fn add_event<T: NetworkEvent>(
        &mut self,
        event: &Event<T, S::PublicId>,
    ) -> Result<(), Error> {
        if let Some(peer) = self.peers.get_mut(event.creator()) {
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
}

#[cfg(test)]
impl PeerList<PeerId> {
    // Creates a new PeerList using the input parameters directly
    pub(super) fn new_from_dot_input(
        our_id: PeerId,
        events_graph: &BTreeMap<Hash, Event<Transaction, PeerId>>,
        peer_states: &BTreeMap<PeerId, String>,
    ) -> Self {
        let mut peers = BTreeMap::new();
        let mut peer_id_hashes = Vec::new();
        for (peer_id, state_str) in peer_states {
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
            let state = match state_str.as_ref() {
                "Pending" => PeerState::Pending,
                "Active" => PeerState::Active,
                "Removed" => PeerState::Removed,
                _ => panic!("wrong state string: {:?}", state_str),
            };
            let _ = peers.insert(peer_id.clone(), Peer { state, events });
            peer_id_hashes.push((Hash::from(serialise(&peer_id).as_slice()), peer_id.clone()))
        }

        PeerList {
            our_id,
            peers,
            peer_id_hashes,
        }
    }
}

#[derive(Debug)]
enum PeerState {
    Pending,
    Active,
    Removed,
}

pub(crate) struct Peer {
    state: PeerState,
    pub events: BTreeMap<u64, Hash>,
}

impl Peer {
    pub fn is_active(&self) -> bool {
        match self.state {
            PeerState::Active => true,
            PeerState::Pending | PeerState::Removed => false,
        }
    }

    pub fn is_removed(&self) -> bool {
        match self.state {
            PeerState::Removed => true,
            PeerState::Active | PeerState::Pending => false,
        }
    }

    fn new_active() -> Self {
        Self {
            state: PeerState::Active,
            events: BTreeMap::new(),
        }
    }

    fn new_pending() -> Self {
        Self {
            state: PeerState::Pending,
            events: BTreeMap::new(),
        }
    }

    #[cfg(feature = "dump-graphs")]
    pub fn print_state(&self) -> String {
        format!("{:?}", self.state)
    }
}
