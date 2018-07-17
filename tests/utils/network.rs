// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use parsec::mock::{self, PeerId, Transaction};
use parsec::{Request, Response};
use rand::Rng;
use std::collections::{BTreeSet, HashMap};
use utils::{ScheduleEvent, Peer, Schedule};

enum Message {
    Request(Request<Transaction, PeerId>),
    Response(Response<Transaction, PeerId>),
}

pub struct Network {
    pub peers: Vec<Peer>,
    msg_queue: HashMap<PeerId, Vec<(PeerId, Message)>>,
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
        Network {
            peers,
            msg_queue: HashMap::new(),
        }
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

    pub fn execute_schedule(&mut self, schedule: Schedule) {
        for event in schedule.0 {
            match event {
                ScheduleEvent::SendGossip(peer1, peer2) => {
                    let request =
                        unwrap!(self.peer(&peer1).parsec.create_gossip(Some(peer2.clone())));
                    self.msg_queue
                        .entry(peer2)
                        .or_insert_with(Vec::new)
                        .push((peer1, Message::Request(request)));
                }
                ScheduleEvent::ReceiveAndRespond(peer) => {
                    if let Some(msgs) = self.msg_queue.remove(&peer) {
                        for (sender, msg) in msgs {
                            match msg {
                                Message::Request(req) => {
                                    let response = unwrap!(
                                        self.peer_mut(&peer).parsec.handle_request(&sender, req)
                                    );
                                    self.peer_mut(&peer).poll();
                                    self.msg_queue
                                        .entry(sender)
                                        .or_insert_with(Vec::new)
                                        .push((peer.clone(), Message::Response(response)));
                                }
                                Message::Response(resp) => {
                                    unwrap!(
                                        self.peer_mut(&peer).parsec.handle_response(&sender, resp)
                                    );
                                }
                            }
                        }
                    }
                }
                ScheduleEvent::VoteFor(peer, transaction) => {
                    let _ = self.peer_mut(&peer).vote_for(&transaction);
                }
            }
        }
    }
}
