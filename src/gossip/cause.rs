// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use hash::Hash;
use id::PublicId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use vote::Vote;

pub enum Cause<T: Serialize + DeserializeOwned + Debug, P: PublicId> {
    // Hash is of the latest `Event` of the peer which sent the request.
    Request(Hash),
    // Hash is of the latest `Event` of the peer which sent the response.
    Response(Hash),
    // Vote for a single network event of type `T`.
    Observation(Vote<T, P>),
}
