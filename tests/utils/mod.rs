// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities for tests and examples.

use parsec::{NetworkEvent, Parsec, PublicId, SecretId};
use rand::{self, Rng, SeedableRng, XorShiftRng};
use rust_sodium;
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug};
use std::panic;

/// Test network.
pub struct Network {
    pub peers: BTreeMap<PeerId, Parsec<Transaction, FullId>>,
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
            .map(|id| (*id.public_id(), unwrap!(Parsec::new(id, &genesis_group))))
            .collect();

        Network { peers }
    }

    /// Node of `sender_id` sends a parsec request to the node of `receiver_id`, which causes
    /// `receiver_id` node to reply with a parsec response.
    pub fn send_sync(&mut self, sender_id: &PeerId, receiver_id: &PeerId) {
        self.exchange_messages(sender_id, receiver_id);
    }

    /// For each node of `sender_id`, which sends a parsec request to a randomly chosen peer of
    /// `receiver_id`, which causes `receiver_id` node to reply with a parsec response.
    pub fn send_random_syncs<R: Rng>(&mut self, rng: &mut R) {
        let peers: Vec<PeerId> = self.peers.keys().cloned().collect();

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
        unwrap!(self.peers.get_mut(id))
    }

    fn exchange_messages(&mut self, sender_id: &PeerId, receiver_id: &PeerId) {
        let request = self.peers[sender_id].create_gossip();

        let response = unwrap!(
            self.peer_mut(receiver_id)
                .handle_request(sender_id, request)
        );

        unwrap!(
            self.peer_mut(sender_id)
                .handle_response(receiver_id, response)
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
    fn first_char(&self) -> char {
        if let Some(name) = friendly_names::get(self) {
            name.chars().next().unwrap()
        } else {
            self.pk.0[0] as char
        }
    }
}

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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Debug)]
pub enum Transaction {
    InsertPeer(PeerId),
    RemovePeer(PeerId),
}

impl NetworkEvent for Transaction {}

/// Initialise random number generator with the given seed. Pass `None` for a random seed.
pub fn init_rng(seed: Option<[u32; 4]>) -> XorShiftRng {
    let seed = seed.unwrap_or_else(|| rand::thread_rng().gen());
    println!("Random seed: {:?}", seed);

    let hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        hook(info);
        println!("Random seed: {:?}", seed)
    }));

    let mut rng = XorShiftRng::from_seed(seed);
    unwrap!(rust_sodium::init_with_rng(&mut rng));

    rng
}

pub mod friendly_names {
    use super::PeerId;
    use std::collections::BTreeMap;
    use std::sync::RwLock;

    const NAMES: &[&str] = &["Alice", "Bob", "Carol", "Dave"];

    pub fn get(peer_id: &PeerId) -> Option<&str> {
        if let Some(&index) = unwrap!(INDICES.read()).get(peer_id) {
            return Some(NAMES[index]);
        }

        let mut indices = unwrap!(INDICES.write());
        if indices.len() >= NAMES.len() {
            return None;
        }

        let index = indices.len();
        let _ = indices.insert(peer_id.clone(), index);

        Some(NAMES[index])
    }

    pub fn reset() {
        unwrap!(INDICES.write()).clear()
    }

    lazy_static! {
        static ref INDICES: RwLock<BTreeMap<PeerId, usize>> = RwLock::new(BTreeMap::default());
    }
}
