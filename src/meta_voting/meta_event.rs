// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_vote::{MetaVote, MetaVotes};
use id::PublicId;
use network_event::NetworkEvent;
use observation::Observation;
use std::collections::BTreeSet;

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct MetaEvent<T: NetworkEvent, P: PublicId> {
    // The set of peers for which this event can strongly-see an event by that peer which carries a
    // valid block.  If there are a supermajority of peers here, this event is an "observer".
    pub observations: BTreeSet<P>,
    // Payloads of all the votes deemed interesting by this event.
    pub interesting_content: Vec<Observation<T, P>>,
    pub meta_votes: MetaVotes<P>,
}

impl<T: NetworkEvent, P: PublicId> MetaEvent<T, P> {
    pub fn new() -> Self {
        MetaEvent {
            observations: BTreeSet::new(),
            interesting_content: Vec::new(),
            meta_votes: MetaVotes::new(),
        }
    }

    pub fn add_meta_votes(&mut self, peer_id: P, votes: Vec<MetaVote>) {
        let _ = self.meta_votes.insert(peer_id, votes);
    }
}
