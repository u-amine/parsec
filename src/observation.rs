// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use id::PublicId;
use network_event::NetworkEvent;

/// An enum of the various network events for which a peer can vote.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum Observation<T: NetworkEvent, P: PublicId> {
    /// Vote to add the indicated peer to the network.
    Add(P),
    /// Vote to remove the indicated peer from the network.
    Remove(P),
    /// Vote for an event which is opaque to Parsec.
    OpaquePayload(T),
}
