// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_elections::MetaElectionHandle;
use super::meta_vote::{MetaVote, MetaVotes};
use gossip::Event;
use id::PublicId;
use network_event::NetworkEvent;
use observation::Observation;
use std::collections::BTreeSet;

#[serde(bound = "")]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub(crate) struct MetaEvent<T: NetworkEvent, P: PublicId> {
    // The set of peers for which this event can strongly-see an event by that peer which carries a
    // valid block.  If there are a supermajority of peers here, this event is an "observer".
    pub observees: BTreeSet<P>,
    // Payloads of all the votes deemed interesting by this event.
    pub interesting_content: Vec<Observation<T, P>>,
    pub meta_votes: MetaVotes<P>,
}

impl<T: NetworkEvent, P: PublicId> MetaEvent<T, P> {
    pub fn build(election: MetaElectionHandle, event: &Event<T, P>) -> MetaEventBuilder<T, P> {
        MetaEventBuilder {
            election,
            event,
            meta_event: MetaEvent {
                observees: BTreeSet::new(),
                interesting_content: Vec::new(),
                meta_votes: MetaVotes::new(),
            },
        }
    }
}

pub(crate) struct MetaEventBuilder<'a, T: NetworkEvent + 'a, P: PublicId + 'a> {
    election: MetaElectionHandle,
    event: &'a Event<T, P>,
    meta_event: MetaEvent<T, P>,
}

impl<'a, T: NetworkEvent + 'a, P: PublicId + 'a> MetaEventBuilder<'a, T, P> {
    pub fn election(&self) -> MetaElectionHandle {
        self.election
    }

    pub fn event(&self) -> &Event<T, P> {
        self.event
    }

    pub fn observee_count(&self) -> usize {
        self.meta_event.observees.len()
    }

    pub fn has_observee(&self, peer_id: &P) -> bool {
        self.meta_event.observees.contains(peer_id)
    }

    pub fn set_observees(&mut self, observees: BTreeSet<P>) {
        self.meta_event.observees = observees;
    }

    pub fn set_interesting_content(&mut self, content: Vec<Observation<T, P>>) {
        self.meta_event.interesting_content = content;
    }

    pub fn add_meta_votes(&mut self, peer_id: P, votes: Vec<MetaVote>) {
        let _ = self.meta_event.meta_votes.insert(peer_id, votes);
    }

    pub fn finish(self) -> MetaEvent<T, P> {
        self.meta_event
    }
}
