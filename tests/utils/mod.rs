// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod id;
mod network;
mod peer;

pub use self::id::{FullId, PeerId};
pub use self::network::{Network, Transaction};
pub use self::peer::Peer;

use maidsafe_utilities::SeededRng;
use rust_sodium;

/// Initialise random number generator with the given seed.  Pass `None` for a random seed.
pub fn init_rng(optional_seed: Option<[u32; 4]>) -> SeededRng {
    let mut rng = if let Some(seed) = optional_seed {
        SeededRng::from_seed(seed)
    } else {
        SeededRng::new()
    };
    unwrap!(rust_sodium::init_with_rng(&mut rng));
    rng
}

/// Runs `closure` in a loop until it returns `true` (in which case this function returns), or until
/// it has looped `max_iterations` times (in which case it panics).
pub fn loop_with_max_iterations<F: FnMut() -> bool>(max_iterations: usize, mut closure: F) {
    let mut iterations = 0;
    loop {
        assert!(iterations < max_iterations);
        if closure() {
            return;
        }
        iterations += 1;
    }
}
