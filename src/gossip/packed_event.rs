// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::content::Content;
use id::PublicId;
use network_event::NetworkEvent;
use std::fmt::{self, Debug, Formatter};

#[serde(bound = "")]
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct PackedEvent<T: NetworkEvent, P: PublicId> {
    pub(super) content: Content<T, P>,
    pub(super) signature: P::Signature,
}

impl<T: NetworkEvent, P: PublicId> Debug for PackedEvent<T, P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Event{{ {:?}, creator: {:?}, self_parent: {:?}, other_parent: {:?} }}",
            self.content.cause,
            self.content.creator,
            self.content.self_parent(),
            self.content.other_parent()
        )
    }
}
