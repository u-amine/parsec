// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::usize;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) struct EventIndex(pub(super) usize);

impl EventIndex {
    pub const MIN: Self = EventIndex(0);

    #[cfg(any(test, feature = "testing"))]
    pub fn phony(index: usize) -> Self {
        EventIndex(index)
    }

    pub fn topological_index(self) -> usize {
        self.0
    }
}
