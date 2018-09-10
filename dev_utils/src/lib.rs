// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate parsec;
#[macro_use]
extern crate proptest as proptest_crate;
extern crate rand;
#[macro_use]
extern crate unwrap;

mod environment;
mod network;
mod peer;
pub mod proptest;
mod schedule;

pub use self::environment::{Environment, ObservationCount, PeerCount, RngChoice};
pub use self::network::Network;
pub use self::peer::Peer;
pub use self::schedule::*;

type Observation = parsec::Observation<parsec::mock::Transaction, parsec::mock::PeerId>;
