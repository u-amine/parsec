// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Cause;
use hash::Hash;
use id::PublicId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

pub struct Content<T: Serialize + DeserializeOwned + Debug + Eq, P: PublicId> {
    // ID of peer which created this `Event`.
    creator: P,
    // Whether it was created by receiving a gossip request, response or by being
    // given a network event to vote for.
    cause: Cause<T, P>,
    // Hash of our own immediate ancestor. Only `None` for our first `Event`.
    self_parent: Option<Hash>,
}

impl<T: Serialize + DeserializeOwned + Debug + Eq, P: PublicId> Content<T, P> {
    pub fn other_parent(&self) -> Option<Hash> {
        match self.cause {
            Cause::Request(hash) | Cause::Response(hash) => Some(hash),
            Cause::Observation(_) => None,
        }
    }
}
