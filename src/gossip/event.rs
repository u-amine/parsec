// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use gossip::cause::Cause;
use gossip::content::Content;
use gossip::packed_event::PackedEvent;
use hash::Hash;
use id::{PublicId, SecretId};
use maidsafe_utilities::serialisation::serialise;
use network_event::NetworkEvent;
use std::collections::BTreeMap;
use vote::Vote;

pub(crate) struct Event<T: NetworkEvent, P: PublicId> {
    content: Content<T, P>,
    // Creator's signature of `content`.
    signature: P::Signature,
    hash: Hash,
    // Sequential index of this event: this event is the `index`-th one made by its creator.
    pub index: Option<u64>,
    // Index of each peer's latest event that is an ancestor of this event.
    pub last_ancestors: BTreeMap<P, u64>,
    // Index of each peer's earliest event that is a descendant of this event.
    pub first_descendants: BTreeMap<P, u64>,
}

impl<T: NetworkEvent, P: PublicId> Event<T, P> {
    // Creates a new event as the result of receiving a gossip request message.
    pub fn new_from_request<S: SecretId<PublicId = P>>(
        secret_id: &S,
        self_parent: Hash,
        other_parent: Hash,
    ) -> Result<Self, Error> {
        Self::new(secret_id, Cause::Request(other_parent), Some(self_parent))
    }

    // Creates a new event as the result of receiving a gossip response message.
    pub fn new_from_response<S: SecretId<PublicId = P>>(
        secret_id: &S,
        self_parent: Hash,
        other_parent: Hash,
    ) -> Result<Self, Error> {
        Self::new(secret_id, Cause::Response(other_parent), Some(self_parent))
    }

    // Creates a new event as the result of observing a network event.
    pub fn new_from_observation<S: SecretId<PublicId = P>>(
        secret_id: &S,
        self_parent: Hash,
        network_event: T,
    ) -> Result<Self, Error> {
        let vote = Vote::new(secret_id, network_event)?;
        Self::new(secret_id, Cause::Observation(vote), Some(self_parent))
    }

    // Creates an initial event.  This is the first event by its creator in the graph.
    pub fn new_initial<S: SecretId<PublicId = P>>(secret_id: &S) -> Result<Self, Error> {
        Self::new(secret_id, Cause::Initial, None)
    }

    // Creates an event from a `PackedEvent`.
    pub(super) fn unpack(packed_event: PackedEvent<T, P>) -> Result<Self, Error> {
        let serialised_content = serialise(&packed_event.content)?;
        let hash = if packed_event
            .content
            .creator
            .verify_signature(&packed_event.signature, &serialised_content)
        {
            Hash::from(serialised_content.as_slice())
        } else {
            return Err(Error::SignatureFailure);
        };

        Ok(Self {
            content: packed_event.content,
            signature: packed_event.signature,
            hash,
            index: Some(0),
            last_ancestors: BTreeMap::default(),
            first_descendants: BTreeMap::default(),
        })
    }

    // Creates a `PackedEvent` from this `Event`.
    pub(super) fn pack(&self) -> PackedEvent<T, P> {
        PackedEvent {
            content: self.content.clone(),
            signature: self.signature.clone(),
        }
    }

    pub fn creator(&self) -> &P {
        &self.content.creator
    }

    pub fn self_parent(&self) -> Option<&Hash> {
        self.content.self_parent.as_ref()
    }

    pub fn other_parent(&self) -> Option<&Hash> {
        self.content.other_parent()
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn signature(&self) -> &P::Signature {
        &self.signature
    }

    fn new<S: SecretId<PublicId = P>>(
        secret_id: &S,
        cause: Cause<T, P>,
        self_parent: Option<Hash>,
    ) -> Result<Self, Error> {
        let content = Content {
            creator: secret_id.public_id().clone(),
            cause,
            self_parent,
        };
        let serialised_content = serialise(&content)?;
        Ok(Self {
            content,
            signature: secret_id.sign_detached(&serialised_content),
            hash: Hash::from(serialised_content.as_slice()),
            index: Some(0),
            last_ancestors: BTreeMap::default(),
            first_descendants: BTreeMap::default(),
        })
    }
}
