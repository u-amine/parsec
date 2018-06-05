// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Content;
use hash::Hash;
use id::PublicId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Debug;

pub struct Event<T: Serialize + DeserializeOwned + Debug + Eq, P: PublicId> {
    content: Content<T, P>,
    // Creator's signature of `content`. signature: P::Signature,
    hash: Hash,
    // Index used to simplify some calculations. It's always one more than the index
    // of the self-parent, or 1 for events without self-parent (0 is reserved).
    pub(super) index: u64,
    // Index of last (latest) event by each peer that is ancestor of this event.
    pub(super) last_ancestors: BTreeMap<P, u64>,
    // Index of first (earliest) event by each peer that is descendant of this event.
    pub(super) first_descendants: BTreeMap<P, u64>,
}
