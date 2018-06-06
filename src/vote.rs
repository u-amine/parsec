// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use id::{Proof, PublicId, SecretId};
use maidsafe_utilities::serialisation::serialise;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// A helper struct carrying some data and a signature of this data.
#[serde(bound = "")]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Vote<T: Serialize + DeserializeOwned + Debug + Eq, P: PublicId> {
    payload: T,
    signature: P::Signature,
}

impl<T: Serialize + DeserializeOwned + Debug + Eq, P: PublicId> Vote<T, P> {
    /// Creates a `Vote` for `payload`.
    pub fn new<S: SecretId<PublicId = P>>(secret_id: &S, payload: T) -> Result<Self, Error> {
        let signature = secret_id.sign_detached(&serialise(&payload)?[..]);
        Ok(Self { payload, signature })
    }

    /// Returns the payload being voted for.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Returns the signature of this `Vote`'s payload.
    pub fn signature(&self) -> &P::Signature {
        &self.signature
    }

    /// Validates this `Vote`'s signature and payload against the given public ID.
    pub fn is_valid(&self, public_id: &P) -> bool {
        match serialise(&self.payload) {
            Ok(data) => public_id.verify_signature(&self.signature, &data[..]),
            Err(_) => false,
        }
    }

    /// Creates a `Proof` from this `Vote`.  Returns `Err` if this `Vote` is not valid (i.e. if
    /// `!self.is_valid()`).
    pub fn create_proof(&self, public_id: &P) -> Result<Proof<P>, Error> {
        if self.is_valid(public_id) {
            return Ok(Proof {
                public_id: public_id.clone(),
                signature: self.signature.clone(),
            });
        }
        Err(Error::SignatureFailure)
    }
}
