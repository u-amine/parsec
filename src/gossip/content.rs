// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::cause::Cause;
use hash::Hash;
use id::PublicId;
use network_event::NetworkEvent;

#[serde(bound = "")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(super) struct Content<T: NetworkEvent, P: PublicId> {
    // ID of peer which created this `Event`.
    pub creator: P,
    // Whether it was created by receiving a gossip request, response or by being given a network
    // event to vote for.
    pub cause: Cause<T, P>,
    // Hash of our own immediate ancestor.  Only `None` for our first `Event`.
    pub self_parent: Option<Hash>,
}

impl<T: NetworkEvent, P: PublicId> Content<T, P> {
    // Hash of sender's latest event if the `cause` is a request or response; otherwise `None`.
    pub fn other_parent(&self) -> Option<&Hash> {
        match &self.cause {
            Cause::Request(hash) | Cause::Response(hash) => Some(hash),
            Cause::Observation(_) | Cause::Initial => None,
        }
    }
}
