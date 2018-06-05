// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use id::{Proof, PublicId};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use vote::Vote;

#[serde(bound = "")]
#[derive(Serialize, Debug, Deserialize, PartialEq, Eq, Ord, PartialOrd, Clone)]
pub struct Block<T: Serialize + DeserializeOwned + Debug + PartialEq, P: PublicId> {
    payload: T,
    proofs: BTreeSet<Proof<P>>,
}

impl<T: Serialize + DeserializeOwned + Debug + PartialEq, P: PublicId> Block<T, P> {
    /// Creates a `Block` from `payload` and `votes`.
    pub fn new(payload: T, votes: &BTreeMap<P, Vote<T, P>>) -> Result<Self, Error> {
        let proofs: BTreeSet<Proof<P>> = votes
            .iter()
            .filter_map(|(public_id, vote)| {
                if let Ok(proof) = vote.create_proof(public_id) {
                    Some(proof.clone())
                } else {
                    None
                }
            })
            .collect();
        if proofs.len() != votes.len() {
            return Err(Error::SignatureFailure);
        }
        Ok(Self { payload, proofs })
    }

    /// Returns the payload of this block.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Returns the proofs of this block.
    pub fn proofs(&self) -> &BTreeSet<Proof<P>> {
        &self.proofs
    }

    /// Convert the vote to a proof and insert it into proofs of the block.
    pub fn add_vote(&mut self, peer_id: &P, vote: &Vote<T, P>) -> Result<bool, Error> {
        if &self.payload != vote.payload() {
            return Err(Error::MismatchedPayload);
        }
        let proof = vote.create_proof(peer_id)?;
        Ok(self.proofs.insert(proof))
    }
}
