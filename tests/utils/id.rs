// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use parsec::{PublicId, SecretId};
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey};
use std::fmt::{self, Debug};

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

mod friendly_names {
    use super::PeerId;
    use std::collections::BTreeMap;
    use std::sync::RwLock;

    const NAMES: &[&str] = &[
        "Alice", "Bob", "Carol", "Dave", "Eric", "Fred", "Gina", "Hank", "Iris", "Judy", "Kent",
        "Lucy", "Mike", "Nina", "Oran", "Paul", "Quin", "Rose", "Stan", "Tina",
    ];

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

    lazy_static! {
        static ref INDICES: RwLock<BTreeMap<PeerId, usize>> = RwLock::new(BTreeMap::default());
    }
}
