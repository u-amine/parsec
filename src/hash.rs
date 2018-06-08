// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::fmt::{self, Debug, Formatter};
use tiny_keccak;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) struct Hash([u8; 32]);

impl<'a> From<&'a [u8]> for Hash {
    fn from(src: &'a [u8]) -> Self {
        Hash(tiny_keccak::sha3_256(src))
    }
}

impl Debug for Hash {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{:02x}{:02x}{:02x}..",
            self.0[0], self.0[1], self.0[2]
        )
    }
}
