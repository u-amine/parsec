// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use maidsafe_utilities::SeededRng;
use network::Network;
use parsec::mock::Transaction;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::fmt;

pub struct PeerCount(pub usize);
pub struct TransactionCount(pub usize);

pub trait RngDebug: Rng + fmt::Debug {}

impl RngDebug for SeededRng {}
impl RngDebug for XorShiftRng {}

pub struct Environment {
    pub network: Network,
    pub transactions: Vec<Transaction>,
    pub rng: Box<RngDebug>,
}

#[derive(Clone, Copy, Debug)]
pub enum RngChoice {
    SeededRandom,
    #[allow(unused)]
    Seeded([u32; 4]),
    SeededXor([u32; 4]),
}

impl Environment {
    /// Initialise the test environment with the given number of peers and transactions.  The random
    /// number generator will be seeded with `seed` or randomly if this is `SeededRandom`.
    pub fn new(
        peer_count: &PeerCount,
        transaction_count: &TransactionCount,
        seed: RngChoice,
    ) -> Self {
        let network = Network::new(peer_count.0);

        let mut rng: Box<RngDebug> = match seed {
            RngChoice::SeededRandom => Box::new(SeededRng::new()),
            RngChoice::Seeded(seed) => Box::new(SeededRng::from_seed(seed)),
            RngChoice::SeededXor(seed) => Box::new(XorShiftRng::from_seed(seed)),
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

impl fmt::Debug for Environment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Environment({} peers, {} transactions, {:?})",
            self.network.peers.len(),
            self.transactions.len(),
            self.rng
        )
    }
}
