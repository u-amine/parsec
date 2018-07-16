// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use maidsafe_utilities::SeededRng;
use parsec::mock::Transaction;
use rand::Rng;
use utils::Network;

pub struct PeerCount(pub usize);
pub struct TransactionCount(pub usize);

pub struct Environment {
    pub network: Network,
    pub transactions: Vec<Transaction>,
    pub rng: SeededRng,
}

impl Environment {
    /// Initialise the test environment with the given number of peers and transactions.  The random
    /// number generator will be seeded with `seed` or randomly if this is `None`.
    pub fn new(
        peer_count: &PeerCount,
        transaction_count: &TransactionCount,
        seed: Option<[u32; 4]>,
    ) -> Self {
        let network = Network::new(peer_count.0);

        let mut rng = if let Some(seed) = seed {
            SeededRng::from_seed(seed)
        } else {
            SeededRng::new()
        };
        println!("Using {:?}", rng);

        let transactions = (0..transaction_count.0)
            .map(|_| rng.gen())
            .collect::<Vec<Transaction>>();

        Self {
            network,
            transactions,
            rng,
        }
    }
}
