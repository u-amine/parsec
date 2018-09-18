// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::peer::{Peer, PeerStatus};
use super::schedule::{self, RequestTiming, Schedule, ScheduleEvent};
use super::Observation;
use gossip::{Request, Response};
use mock::{self, PeerId, Transaction};
use std::collections::{BTreeMap, BTreeSet};

enum Message {
    Request(Request<Transaction, PeerId>, usize),
    Response(Response<Transaction, PeerId>),
}

struct QueueEntry {
    pub sender: PeerId,
    pub message: Message,
    pub deliver_after: usize,
}

pub struct Network {
    pub peers: BTreeMap<PeerId, Peer>,
    msg_queue: BTreeMap<PeerId, Vec<QueueEntry>>,
}

type DifferingBlocksOrder<'a> = (
    &'a PeerId,
    Vec<&'a Observation>,
    &'a PeerId,
    Vec<&'a Observation>,
);

impl Network {
    /// Create test network with the given initial number of peers (the genesis group).
    pub fn new(count: usize) -> Self {
        let all_ids = mock::create_ids(count);
        Self::with_peers(all_ids)
    }

    /// Create a test network with initial peers constructed from the given IDs
    pub fn with_peers<I: IntoIterator<Item = PeerId>>(all_ids: I) -> Self {
        let genesis_group = all_ids.into_iter().collect::<BTreeSet<_>>();
        let peers = genesis_group
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    Peer::new(id.clone(), &genesis_group, PeerStatus::Active),
                )
            }).collect();
        Network {
            peers,
            msg_queue: BTreeMap::new(),
        }
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    pub fn blocks_all_in_sequence(&self) -> Result<(), DifferingBlocksOrder> {
        let first_peer = unwrap!(self.peers.iter().next()).1;
        let payloads = first_peer.blocks_payloads();
        if let Some(peer) = self
            .peers
            .values()
            .find(|peer| peer.blocks_payloads() != payloads)
        {
            Err((&first_peer.id, payloads, &peer.id, peer.blocks_payloads()))
        } else {
            Ok(())
        }
    }

    fn peer(&mut self, id: &PeerId) -> &Peer {
        unwrap!(self.peers.get(id))
    }

    fn peer_mut(&mut self, id: &PeerId) -> &mut Peer {
        unwrap!(self.peers.get_mut(id))
    }

    fn send_message(&mut self, src: PeerId, dst: &PeerId, message: Message, deliver_after: usize) {
        self.msg_queue
            .entry(dst.clone())
            .or_insert_with(Vec::new)
            .push(QueueEntry {
                sender: src,
                message,
                deliver_after,
            });
    }

    /// Handles incoming requests and responses
    fn handle_messages(&mut self, peer: &PeerId, step: usize) -> bool {
        if let Some(msgs) = self.msg_queue.remove(peer) {
            let (to_handle, rest) = msgs
                .into_iter()
                .partition(|entry| entry.deliver_after <= step);
            let _ = self.msg_queue.insert(peer.clone(), rest);
            let result = !to_handle.is_empty();
            for entry in to_handle {
                match entry.message {
                    Message::Request(req, resp_delay) => {
                        let response = unwrap!(
                            self.peer_mut(peer)
                                .parsec
                                .handle_request(&entry.sender, req)
                        );
                        self.send_message(
                            peer.clone(),
                            &entry.sender,
                            Message::Response(response),
                            step + resp_delay,
                        );
                    }
                    Message::Response(resp) => {
                        unwrap!(
                            self.peer_mut(peer)
                                .parsec
                                .handle_response(&entry.sender, resp)
                        );
                    }
                }
            }
            result
        } else {
            false
        }
    }

    fn consensus_broken(&self) -> bool {
        let mut block_order = BTreeMap::new();
        for peer in self.peers.values() {
            for (index, block) in peer.blocks_payloads().into_iter().enumerate() {
                let old_index = block_order.insert(block, index);
                if old_index.map(|idx| idx != index).unwrap_or(false) {
                    // old index exists and isn't equal to the new one
                    return true;
                }
            }
        }
        false
    }

    fn consensus_complete(&self, num_observations: usize) -> bool {
        self.peers.iter().next().unwrap().1.blocks_payloads().len() == num_observations
            && self.blocks_all_in_sequence().is_ok()
    }

    /// Simulates the network according to the given schedule
    pub fn execute_schedule(&mut self, schedule: Schedule) {
        let mut started_up = BTreeSet::new();
        let Schedule {
            num_observations,
            events,
        } = schedule;
        for event in events {
            match event {
                ScheduleEvent::LocalStep {
                    global_step,
                    peer,
                    request_timing,
                } => {
                    let has_new_data = self.handle_messages(&peer, global_step);
                    self.peer_mut(&peer).poll();
                    let mut handle_req = |req: schedule::Request| {
                        let request =
                            unwrap!(self.peer(&peer).parsec.create_gossip(Some(&req.recipient)));
                        self.send_message(
                            peer.clone(),
                            &req.recipient,
                            Message::Request(request, req.resp_delay),
                            global_step + req.req_delay,
                        );
                    };
                    match request_timing {
                        RequestTiming::DuringThisStep(req) => {
                            handle_req(req);
                        }
                        RequestTiming::DuringThisStepIfNewData(req) => {
                            if has_new_data || !started_up.contains(&peer) {
                                let _ = started_up.insert(peer.clone());
                                handle_req(req);
                            }
                        }
                        RequestTiming::Later => (),
                    }
                }
                ScheduleEvent::VoteFor(peer, observation) => {
                    let _ = self.peer_mut(&peer).vote_for(&observation);
                }
                ScheduleEvent::Fail(peer) => {
                    (*self.peer_mut(&peer)).status = PeerStatus::Failed;
                }
            }
            if self.consensus_broken() || self.consensus_complete(num_observations) {
                break;
            }
        }
    }
}
