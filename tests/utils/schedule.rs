// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Environment;
use parsec::mock::{PeerId, Transaction};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::mem;

/// This struct holds the data necessary to make a simulated request when a node executes a local
/// step.
#[derive(Clone, Debug)]
pub struct Request {
    /// The recipient of the request - it will then respond back to the sender
    pub recipient: PeerId,
    /// The delay, in steps, between sending and reception of the request
    pub req_delay: usize,
    /// The delay, in steps, between sending and reception of the response
    pub resp_delay: usize,
}

/// Describes whether the node should make a request during its local step
#[derive(Clone, Debug)]
pub enum RequestTiming {
    /// Don't make a request
    Later,
    /// Make a request
    DuringThisStep(Request),
    /// Make a request if new data is available
    DuringThisStepIfNewData(Request),
}

/// Represents an event the network is supposed to simulate.
/// The simulation proceeds in steps. During every global step, every node has some probability
/// of being scheduled to perform a local step, consisting of receiving messages that reached it
/// by this time, generating appropriate responses and optionally sending a gossip request.
#[derive(Clone, Debug)]
pub enum ScheduleEvent {
    /// This event variant represents a node being scheduled to execute a local step. It contains a
    /// global step number, the ID of the node being scheduled, and optionally data of the request
    /// the node will send.
    LocalStep {
        global_step: usize,
        peer: PeerId,
        request_timing: RequestTiming,
    },
    /// This event causes the node with the given ID to stop responding. All further events
    /// concerning that node will be ignored.
    Fail(PeerId),
    /// This event makes a node vote on the given transaction.
    VoteFor(PeerId, Transaction),
}

// A function generating a Poisson-distributed random number.
fn poisson<R: Rng>(rng: &mut R, lambda: f64) -> usize {
    let mut result = 0;
    let mut p = 1.0;
    let l = (-lambda).exp();
    loop {
        p *= rng.gen::<f64>();
        if p <= l {
            break;
        }
        result += 1;
    }
    result
}

impl ScheduleEvent {
    fn gen_request<R: Rng>(
        rng: &mut R,
        peer: &PeerId,
        peers: &[PeerId],
        options: &ScheduleOptions,
    ) -> Request {
        let mut recipient = peer;
        while recipient == peer {
            recipient = unwrap!(rng.choose(peers));
        }
        let req_delay = options.gen_delay(rng);
        let resp_delay = options.gen_delay(rng);
        Request {
            recipient: recipient.clone(),
            req_delay,
            resp_delay,
        }
    }

    /// Generates a random network event.
    pub fn gen_random<R: Rng>(
        rng: &mut R,
        step: usize,
        peers: &[PeerId],
        // note: first &mut required below to enable reborrowing
        pending: &mut Option<&mut PendingTransactions>,
        options: &ScheduleOptions,
    ) -> Vec<ScheduleEvent> {
        let mut result = vec![];
        for peer in peers {
            if rng.gen::<f64>() < options.prob_local_step {
                let request_timing = match options.gossip_strategy {
                    GossipStrategy::Probabilistic(prob) => if rng.gen::<f64>() < prob {
                        RequestTiming::DuringThisStep(Self::gen_request(rng, peer, peers, options))
                    } else {
                        RequestTiming::Later
                    },
                    GossipStrategy::AfterReceive => RequestTiming::DuringThisStepIfNewData(
                        Self::gen_request(rng, peer, peers, options),
                    ),
                };
                result.push(ScheduleEvent::LocalStep {
                    global_step: step,
                    peer: peer.clone(),
                    request_timing,
                });
            }
        }

        if let Some(pending) = pending {
            for peer in pending.nonempty_peers() {
                if rng.gen::<f64>() < options.prob_recv_trans {
                    if let Some(transaction) = pending.next_for_peer(&peer) {
                        result.push(ScheduleEvent::VoteFor(peer, transaction));
                    }
                }
            }
        }

        if rng.gen::<f64>() < options.prob_failure {
            let peer = unwrap!(rng.choose(peers));
            result.push(ScheduleEvent::Fail(peer.clone()));
        }

        result
    }

    pub fn fail(&self) -> Option<&PeerId> {
        if let ScheduleEvent::Fail(ref peer) = self {
            Some(peer)
        } else {
            None
        }
    }

    pub fn get_peer(&self) -> &PeerId {
        match *self {
            ScheduleEvent::LocalStep { ref peer, .. } => peer,
            ScheduleEvent::Fail(ref peer) => peer,
            ScheduleEvent::VoteFor(ref peer, _) => peer,
        }
    }
}

/// Stores pending transactions per node, so that nodes only vote for each transaction once.
pub struct PendingTransactions(HashMap<PeerId, Vec<Transaction>>);

impl PendingTransactions {
    pub fn new<R: Rng>(
        rng: &mut R,
        peers: &[PeerId],
        transactions: &Vec<Transaction>,
    ) -> PendingTransactions {
        let mut inner = HashMap::new();
        for peer in peers {
            let mut trans = transactions.clone();
            rng.shuffle(&mut trans);
            let _ = inner.insert(peer.clone(), trans);
        }
        PendingTransactions(inner)
    }

    /// Gets the next transaction for a given node, and removes it from the cache
    pub fn next_for_peer(&mut self, peer: &PeerId) -> Option<Transaction> {
        self.0.get_mut(peer).and_then(|trans| trans.pop())
    }

    /// Returns the list of names of peers that still have pending transactions
    pub fn nonempty_peers(&self) -> Vec<PeerId> {
        self.0
            .iter()
            .filter(|&(_, v)| !v.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Returns true if no more peers have pending transactions
    pub fn is_empty(&self) -> bool {
        self.0.values().all(|v| v.is_empty())
    }

    /// Removes peers that failed
    pub fn remove_peers<I: IntoIterator<Item = PeerId>>(&mut self, peers: I) {
        for peer in peers {
            let _ = self.0.remove(&peer);
        }
    }

    /// Returns an iterator of all (peer, transaction) pairs, clearing the transaction cache in the
    /// process.
    pub fn all_transactions(&mut self) -> impl Iterator<Item = (PeerId, Transaction)> {
        let data = mem::replace(&mut self.0, HashMap::new());
        data.into_iter()
            .flat_map(|(peer, x)| x.into_iter().map(move |trans| (peer.clone(), trans)))
    }
}

/// The condition on which a node gossips when it's scheduled
#[derive(Clone, Copy, Debug)]
pub enum GossipStrategy {
    /// Gossiping with a constant probability per local step
    Probabilistic(f64),
    /// Always gossip after receiving new data
    AfterReceive,
}

/// A struct aggregating the options controlling schedule generation
#[derive(Clone, Debug)]
pub struct ScheduleOptions {
    /// Probability per global step that a node will be scheduled to execute a local step
    pub prob_local_step: f64,
    /// Probability per global step that a node will make a vote
    pub prob_recv_trans: f64,
    /// Probabilitity per step that a random node will fail
    pub prob_failure: f64,
    /// A map: step number → num of nodes to fail
    pub deterministic_failures: HashMap<usize, usize>,
    /// The Poisson distribution parameter controlling the delay lengths
    pub delay_lambda: f64,
    /// When a node gossips
    pub gossip_strategy: GossipStrategy,
    /// When true, nodes will first insert all votes into the graph, then start gossiping
    pub votes_before_gossip: bool,
}

impl ScheduleOptions {
    pub fn gen_delay<R: Rng>(&self, rng: &mut R) -> usize {
        poisson(rng, self.delay_lambda)
    }
}

impl Default for ScheduleOptions {
    fn default() -> ScheduleOptions {
        ScheduleOptions {
            // local step on average every 6-7 steps - not too often
            prob_local_step: 0.15,
            // vote every 20 steps on average; so that there are local steps scheduled in between
            prob_recv_trans: 0.05,
            // no randomised failures
            prob_failure: 0.0,
            // no deterministic failures
            deterministic_failures: HashMap::new(),
            // randomised delays, 4 steps on average
            delay_lambda: 4.0,
            // gossip when we receive new data
            gossip_strategy: GossipStrategy::AfterReceive,
            votes_before_gossip: false,
        }
    }
}

/// Stores the list of network events to be simulated.
pub struct Schedule(pub Vec<ScheduleEvent>);

impl fmt::Debug for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "----------------------------\n")?;
        write!(f, " Schedule:\n")?;
        for event in &self.0 {
            write!(f, "- {:?}\n", event)?;
        }
        write!(f, "----------------------------\n")
    }
}

impl Schedule {
    fn perform_step<R: Rng>(
        rng: &mut R,
        step: usize,
        peers: &mut Vec<PeerId>,
        // note: mut required below for reborrowing in ScheduleEvent::gen_random
        mut pending: Option<&mut PendingTransactions>,
        result: &mut Vec<ScheduleEvent>,
        num_peers: usize,
        options: &ScheduleOptions,
    ) {
        // first, generate deterministic failures that are supposed to happen
        let num_deterministic_fails = options
            .deterministic_failures
            .get(&step)
            .cloned()
            .unwrap_or(0);
        // take random peers to fail
        let mut peers_to_fail = peers.clone();
        rng.shuffle(&mut peers_to_fail);
        let mut events: Vec<_> = peers_to_fail
            .into_iter()
            .take(num_deterministic_fails)
            .map(|p| ScheduleEvent::Fail(p))
            .collect();
        // extend that with random events
        events.extend(ScheduleEvent::gen_random(
            rng,
            step,
            peers,
            &mut pending,
            options,
        ));
        // now, we can have more than max number of failures among events
        // we need to limit that
        // first, we will calculate the max number of failures we can add
        // note: num_peers is the original number of peers, and `peers` only contains
        // active peers, which means they may differ if some peers already failed
        let less_than_a_third_malicious_nodes = (num_peers - 1) / 3;
        let min_honest_nodes = num_peers - less_than_a_third_malicious_nodes;
        let max_number_of_failures = peers.len() - min_honest_nodes;
        // we take out all the failures
        let (fails, mut other): (Vec<_>, _) = events.into_iter().partition(|e| e.fail().is_some());
        // limit them to the max number
        let fails: Vec<_> = fails.into_iter().take(max_number_of_failures).collect();
        // since we have fails separated, take this opportunity to remove failed peers from
        // the peers vector
        let failed_peers: HashSet<_> = fails.iter().filter_map(|e| e.fail().cloned()).collect();
        // other events can still refer to failed peers, as they were drawn using the full peer
        // list
        other.retain(|ev| !failed_peers.contains(ev.get_peer()));
        peers.retain(|p| !failed_peers.contains(p));
        if let Some(pending) = pending {
            pending.remove_peers(failed_peers);
        }
        // finally, add all events to results
        result.extend(fails);
        result.extend(other);
    }

    /// Creates a new pseudo-random schedule based on the given options
    pub fn new(env: &mut Environment, options: &ScheduleOptions) -> Schedule {
        println!("Generating a schedule with options: {:?}", options);
        let mut peers: Vec<_> = env.network.peers.iter().map(|p| p.id.clone()).collect();
        let num_peers = env.network.peers.len();
        let mut pending = PendingTransactions::new(&mut env.rng, &peers, &env.transactions);
        let mut result = vec![];
        let mut step = 0;

        // if votes before gossip enabled, insert all votes
        if options.votes_before_gossip {
            for (peer, transaction) in pending.all_transactions() {
                result.push(ScheduleEvent::VoteFor(peer, transaction));
            }
        }

        while !pending.is_empty() {
            Self::perform_step(
                &mut env.rng,
                step,
                &mut peers,
                Some(&mut pending),
                &mut result,
                num_peers,
                options,
            );
            step += 1;
        }
        let n = peers.len() as f32;
        let additional_events = (30.0 * n * n.ln()) as usize;
        for _ in 0..additional_events {
            Self::perform_step(
                &mut env.rng,
                step,
                &mut peers,
                None,
                &mut result,
                num_peers,
                options,
            );
            step += 1;
        }
        Schedule(result)
    }
}
