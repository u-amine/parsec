// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use parsec::mock::{self, PeerId, Transaction};
use rand::Rng;
use std::collections::BTreeSet;
use utils::Peer;

pub struct Network {
    pub peers: Vec<Peer>,
}

impl Network {
    /// Create test network with the given initial number of peers (the genesis group).
    pub fn new(count: usize) -> Self {
        let all_ids = mock::create_ids(count);
        let genesis_group = all_ids.iter().cloned().collect::<BTreeSet<_>>();
        let peers = genesis_group
            .iter()
            .map(|id| Peer::new(id.clone(), &genesis_group))
            .collect();
        Network { peers }
    }

    /// For each node of `sender_id`, which sends a parsec request to a randomly chosen peer of
    /// `receiver_id`, which causes `receiver_id` node to reply with a parsec response.
    pub fn send_random_syncs<R: Rng>(&mut self, rng: &mut R) {
        let peer_ids = self
            .peers
            .iter()
            .map(|peer| peer.id.clone())
            .collect::<Vec<_>>();
        for sender_id in &peer_ids {
            let receiver_id = unwrap!(
                peer_ids
                    .iter()
                    .filter(|&id| id != sender_id)
                    .nth(rng.gen_range(0, peer_ids.len() - 1))
            );
            self.exchange_messages(sender_id, receiver_id, None);
        }
    }

    pub fn interleave_syncs_and_votes<R: Rng>(
        &mut self,
        rng: &mut R,
        transactions: &mut [Transaction],
    ) {
        let peer_ids = self
            .peers
            .iter()
            .map(|peer| peer.id.clone())
            .collect::<Vec<_>>();
        for sender_id in &peer_ids {
            let receiver_id = unwrap!(
                peer_ids
                    .iter()
                    .filter(|&id| id != sender_id)
                    .nth(rng.gen_range(0, peer_ids.len() - 1))
            );
            rng.shuffle(transactions);
            if rng.gen_weighted_bool(10) {
                self.peer_mut(sender_id)
                    .vote_for_first_not_already_voted_for(&transactions);
            }
            let opt_transactions = if rng.gen_weighted_bool(10) {
                Some(&*transactions)
            } else {
                None
            };
            self.exchange_messages(sender_id, receiver_id, opt_transactions);
        }
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    pub fn blocks_all_in_sequence(&self) -> bool {
        let payloads = self.peers[0].blocks_payloads();
        self.peers
            .iter()
            .all(|peer| peer.blocks_payloads() == payloads)
    }

    fn peer(&mut self, id: &PeerId) -> &Peer {
        unwrap!(self.peers.iter().find(|peer| peer.id == *id))
    }

    fn peer_mut(&mut self, id: &PeerId) -> &mut Peer {
        unwrap!(self.peers.iter_mut().find(|peer| peer.id == *id))
    }

    fn exchange_messages(
        &mut self,
        sender_id: &PeerId,
        receiver_id: &PeerId,
        transactions: Option<&[Transaction]>,
    ) {
        let request = unwrap!(
            self.peer(sender_id)
                .parsec
                .create_gossip(Some(receiver_id.clone()))
        );

        let response = unwrap!(
            self.peer_mut(receiver_id)
                .parsec
                .handle_request(sender_id, request)
        );

        if let Some(transactns) = transactions {
            self.peer_mut(sender_id)
                .vote_for_first_not_already_voted_for(transactns);
        }

        unwrap!(
            self.peer_mut(sender_id)
                .parsec
                .handle_response(receiver_id, response)
        )
    }
}
