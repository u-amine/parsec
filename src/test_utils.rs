// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities for tests and examples.

use gossip::{Request, Response};
use id::{PublicId, SecretId};
use maidsafe_utilities::serialisation;
use network_event::NetworkEvent;
use parsec::Parsec;
use rand::{self, Rng, SeedableRng, XorShiftRng};
use rust_sodium;
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug};
use std::panic;

/// Test network.
pub struct Network {
    peers: BTreeMap<PeerId, Parsec<Transaction, FullId>>,
}

impl Network {
    /// Create test network with the given initial number of peers (the genesis group).
    pub fn new(count: usize) -> Self {
        let mut genesis_group = BTreeSet::default();
        let mut peers = Vec::with_capacity(count);

        for _ in 0..count {
            let id = FullId::new();

            let _ = genesis_group.insert(*id.public_id());
            peers.push(id);
        }

        let peers = peers
            .into_iter()
            .map(|id| (*id.public_id(), Parsec::new(id, &genesis_group).unwrap()))
            .collect();

        Network { peers }
    }

    pub fn peer(&self, id: &PeerId) -> &Parsec<Transaction, FullId> {
        &self.peers[id]
    }

    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peers.keys().cloned().collect()
    }

    pub fn peers(&self) -> &BTreeMap<PeerId, Parsec<Transaction, FullId>> {
        &self.peers
    }

    pub fn peers_mut(&mut self) -> &mut BTreeMap<PeerId, Parsec<Transaction, FullId>> {
        &mut self.peers
    }

    /// Send sync between two peers.
    pub fn send_sync(&mut self, sender_id: &PeerId, receiver_id: &PeerId) {
        self.exchange_messages(sender_id, receiver_id);
    }

    /// Send syncs from random senders to random receivers.
    pub fn send_random_syncs<R: Rng>(&mut self, rng: &mut R) {
        let peers = self.peer_ids();

        for sender_id in &peers {
            while let Some(receiver_id) = rng.choose(&peers) {
                if receiver_id != sender_id {
                    self.exchange_messages(sender_id, receiver_id);
                    break;
                }
            }
        }
    }

    fn peer_mut(&mut self, id: &PeerId) -> &mut Parsec<Transaction, FullId> {
        self.peers.get_mut(id).unwrap()
    }

    fn exchange_messages(&mut self, sender_id: &PeerId, receiver_id: &PeerId) {
        let request = self.peer(sender_id).create_gossip();

        let response = self
            .peer_mut(receiver_id)
            .handle_request(sender_id, request)
            .unwrap();

        assert!(
            self.peer_mut(sender_id)
                .handle_response(receiver_id, response)
                .is_ok()
        )
    }
}

#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PeerId {
    pk: PublicKey,
}

impl PeerId {
    pub fn new(pk: PublicKey) -> Self {
        PeerId { pk }
    }
}

impl Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(name) = friendly_names::get(self) {
            write!(f, "{}", name)
        } else {
            write!(
                f,
                "PeerId({:02x}{:02x}{:02x}..)",
                (self.pk).0[0],
                (self.pk).0[1],
                (self.pk).0[2]
            )
        }
    }
}

impl PublicId for PeerId {
    type Signature = sign::Signature;
    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        sign::verify_detached(signature, data, &self.pk)
    }
}

#[derive(Clone)]
pub struct FullId {
    pk: PeerId,
    sk: SecretKey,
}

impl FullId {
    pub fn new() -> Self {
        let (pk, sk) = sign::gen_keypair();
        Self {
            pk: PeerId::new(pk),
            sk,
        }
    }
}

impl Default for FullId {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretId for FullId {
    type PublicId = PeerId;

    fn public_id(&self) -> &Self::PublicId {
        &self.pk
    }

    fn sign_detached(&self, data: &[u8]) -> sign::Signature {
        sign::sign_detached(data, &self.sk)
    }
}

#[derive(Clone, Eq, Serialize, Deserialize, Debug)]
pub enum Transaction {
    InsertPeer(PeerId),
    RemovePeer(PeerId),
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Transaction::InsertPeer(ref self_peer_id),
                Transaction::InsertPeer(ref other_peer_id),
            )
            | (
                Transaction::RemovePeer(ref self_peer_id),
                Transaction::RemovePeer(ref other_peer_id),
            ) => self_peer_id == other_peer_id,
            _ => false,
        }
    }
}

impl PartialOrd<Self> for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Transaction {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (
                Transaction::InsertPeer(ref self_peer_id),
                Transaction::InsertPeer(ref other_peer_id),
            )
            | (
                Transaction::RemovePeer(ref self_peer_id),
                Transaction::RemovePeer(ref other_peer_id),
            ) => self_peer_id.cmp(other_peer_id),
            (Transaction::InsertPeer(_), Transaction::RemovePeer(_)) => Ordering::Less,
            (Transaction::RemovePeer(_), Transaction::InsertPeer(_)) => Ordering::Greater,
        }
    }
}

impl NetworkEvent for Transaction {}

/// Initialize random number generator with the given seed. Pass `None` fors random seed.
pub fn init_rng(seed: Option<[u32; 4]>) -> XorShiftRng {
    let seed = seed.unwrap_or_else(|| rand::thread_rng().gen());
    println!("Random seed: {:?}", seed);

    let hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        hook(info);
        println!("Random seed: {:?}", seed)
    }));

    let mut rng = XorShiftRng::from_seed(seed);
    rust_sodium::init_with_rng(&mut rng).unwrap();

    rng
}

pub mod friendly_names {
    use super::PeerId;
    use std::collections::BTreeMap;
    use std::sync::RwLock;

    const NAMES: &[&str] = &["Alice", "Bob", "Carol", "Dave"];

    pub fn get(peer_id: &PeerId) -> Option<&str> {
        if let Some(&index) = INDICES.read().unwrap().get(peer_id) {
            return Some(NAMES[index]);
        }

        let mut indices = INDICES.write().unwrap();
        if indices.len() >= NAMES.len() {
            return None;
        }

        let index = indices.len();
        let _ = indices.insert(peer_id.clone(), index);

        Some(NAMES[index])
    }

    pub fn reset() {
        INDICES.write().unwrap().clear()
    }

    lazy_static! {
        static ref INDICES: RwLock<BTreeMap<PeerId, usize>> = RwLock::new(BTreeMap::default());
    }
}
