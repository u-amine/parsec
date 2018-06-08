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
use network_event::NetworkEvent;
use std::collections::btree_map::{self, BTreeMap, Entry};

pub(crate) struct PeerManager<S: SecretId> {
    our_id: S,
    peers: BTreeMap<S::PublicId, BTreeMap<u64, Hash>>,
}

impl<S: SecretId> PeerManager<S> {
    /// Constructor of `PeerManager`.
    pub fn new(our_id: S) -> Self {
        let mut peers = BTreeMap::default();
        let _ = peers.insert(our_id.public_id().clone(), BTreeMap::new());

        PeerManager { our_id, peers }
    }

    /// Returns `our_id`.
    pub fn our_id(&self) -> &S {
        &self.our_id
    }

    /// Returns our info: created events index and hash.
    pub fn our_info(&self) -> &BTreeMap<u64, Hash> {
        &self.peers[self.our_id.public_id()]
    }

    /// Returns peer info: created events index and hash.
    pub fn peer_info(&self, peer_id: &S::PublicId) -> Option<&BTreeMap<u64, Hash>> {
        self.peers.get(peer_id)
    }

    /// Returns all sorted peer_ids.
    pub fn all_ids(&self) -> Vec<&S::PublicId> {
        self.peers.keys().collect()
    }

    /// Returns an iterator of peers.
    pub fn iter(&self) -> btree_map::Iter<S::PublicId, BTreeMap<u64, Hash>> {
        self.peers.iter()
    }

    /// Adds a peer into the map.
    pub fn add_peer(&mut self, peer_id: S::PublicId) {
        let _ = self.peers.entry(peer_id).or_insert_with(BTreeMap::new);
    }

    /// Checks whether the input count becomes the super majority of the network.
    pub fn is_super_majority(&self, count: usize) -> bool {
        3 * count > 2 * self.peers.len()
    }

    /// Returns the index of the last event created by this peer. Returns `None` if cannot find.
    pub fn last_event_index(&self, peer_id: &S::PublicId) -> Option<u64> {
        self.peers
            .get(peer_id)
            .and_then(|events| events.keys().rev().next().cloned())
    }

    /// Returns the hash of the last event created by this peer. Returns `None` if cannot find.
    pub fn last_event_hash(&self, peer_id: &S::PublicId) -> Option<&Hash> {
        self.peers
            .get(peer_id)
            .and_then(|events| events.values().rev().next())
    }

    /// Returns the hash of the indexed event.
    pub fn event_by_index(&self, peer_id: &S::PublicId, index: u64) -> Option<&Hash> {
        self.peers
            .get(peer_id)
            .and_then(|events| events.get(&index))
    }

    /// Adds event created by the peer. Returns an error if `peer_id` is not known, or if we already
    /// held an event from this peer with this index, but that event's hash is different to the one
    /// being added (in which case `peers` is left unmodified).
    pub fn add_event<T: NetworkEvent, P: PublicId>(
        &mut self,
        peer_id: &S::PublicId,
        event: &Event<T, P>,
    ) -> Result<(), Error> {
        let (peer, index) = if let Some(index) = event.index {
            if let Some(peer) = self.peers.get_mut(peer_id) {
                (peer, index)
            } else {
                return Err(Error::UnknownPeer);
            }
        } else {
            return Err(Error::InvalidEvent);
        };

        match peer.entry(index) {
            Entry::Occupied(mut entry) => {
                if entry.get() != event.hash() {
                    return Err(Error::InvalidEvent);
                }
            }
            Entry::Vacant(mut entry) => {
                let _ = entry.insert(*event.hash());
            }
        }

        Ok(())
    }
}
