// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use hash::Hash;
use id::SecretId;
use std::collections::BTreeMap;

pub struct PeerInfo {
    // Events created by this peer (index => hash).
    created_events: BTreeMap<u64, Hash>,
    last_created_event: u64,
}

pub struct PeerManager<S: SecretId> {
    our_id: S,
    peers: BTreeMap<S::PublicId, PeerInfo>,
}
