// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Environment;
use super::Observation;
use super::Peers;
#[cfg(feature = "dump-graphs")]
use dump_graph::DIR;
use mock::{PeerId, Transaction, NAMES};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(feature = "dump-graphs")]
use std::fs::File;
#[cfg(feature = "dump-graphs")]
use std::io::Write;
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
    /// This event makes a node vote on the given observation.
    VoteFor(PeerId, Observation),
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

    fn gen_local_step<R: Rng>(
        rng: &mut R,
        step: usize,
        peer: &PeerId,
        peers: &[PeerId],
        options: &ScheduleOptions,
    ) -> ScheduleEvent {
        let request_timing = match options.gossip_strategy {
            GossipStrategy::Probabilistic(prob) => if rng.gen::<f64>() < prob {
                RequestTiming::DuringThisStep(Self::gen_request(rng, peer, peers, options))
            } else {
                RequestTiming::Later
            },
            GossipStrategy::AfterReceive => {
                RequestTiming::DuringThisStepIfNewData(Self::gen_request(rng, peer, peers, options))
            }
        };
        ScheduleEvent::LocalStep {
            global_step: step,
            peer: peer.clone(),
            request_timing,
        }
    }

    fn gen_votes<R: Rng>(
        rng: &mut R,
        pending: &mut PendingObservations,
        options: &ScheduleOptions,
    ) -> Vec<ScheduleEvent> {
        let mut result = vec![];
        for peer in pending.nonempty_peers() {
            if rng.gen::<f64>() < options.prob_opaque {
                let observation = if rng.gen::<f64>() < options.prob_vote_duplication {
                    pending.peek_next_for_peer(&peer)
                } else {
                    pending.next_for_peer(&peer)
                };
                if let Some(observation) = observation {
                    result.push(ScheduleEvent::VoteFor(peer, observation));
                }
            }
        }
        result
    }

    /// Generates a random network event.
    pub fn gen_random<R: Rng>(
        rng: &mut R,
        step: usize,
        peers: &[PeerId],
        // note: first &mut required below to enable reborrowing
        pending: &mut Option<&mut PendingObservations>,
        options: &ScheduleOptions,
    ) -> Vec<ScheduleEvent> {
        let mut result = vec![];
        for peer in peers {
            if rng.gen::<f64>() < options.prob_local_step {
                result.push(Self::gen_local_step(rng, step, peer, peers, options));
            }
        }

        if let Some(pending) = pending {
            result.extend(Self::gen_votes(rng, pending, options));
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

fn binomial<R: Rng>(rng: &mut R, n: usize, p: f64) -> usize {
    let mut successes = 0;
    for _ in 0..n {
        if rng.gen::<f64>() < p {
            successes += 1;
        }
    }
    successes
}

/// Stores pending observations per node, so that nodes only vote for each observation once.
pub struct PendingObservations {
    min_delay: usize,
    max_delay: usize,
    p_delay: f64,
    queues: BTreeMap<PeerId, BTreeMap<usize, Vec<Observation>>>,
}

impl PendingObservations {
    pub fn new() -> PendingObservations {
        PendingObservations {
            min_delay: 1,
            max_delay: 21,
            p_delay: 0.4,
            queues: BTreeMap::new(),
        }
    }

    /// Add the observation to peers' queues at a random step after the event happened
    pub fn peers_make_observation<'a, R: Rng, I: Iterator<Item = &'a PeerId>>(
        &mut self,
        rng: &mut R,
        peers: I,
        step: usize,
        observation: Observation,
    ) {
        for peer in peers {
            let observations = self
                .queues
                .entry(peer.clone())
                .or_insert_with(BTreeMap::new);
            let tgt_step = step
                + self.min_delay
                + binomial(rng, self.max_delay - self.min_delay, self.p_delay);
            let step_observations = observations.entry(tgt_step).or_insert_with(Vec::new);
            step_observations.push(observation);
        }
    }

    /// Pops all the observations that should be made at `step` at the latest
    pub fn pop_at_step(&mut self, step: usize) -> Vec<(PeerId, Observation)> {
        let mut result = vec![];
        for (peer, queue) in &mut self.queues {
            let to_leave = queue.split_off(&(step + 1));
            let popped = mem::replace(queue, to_leave);
            for (_, observations) in popped {
                result.extend(observations.into_iter().map(|o| (peer.clone(), o)));
            }
        }
        result
    }

    /// Returns true if no more peers have pending observations
    pub fn is_empty(&self) -> bool {
        self.queues.values().all(|v| v.is_empty())
    }

    /// Removes peers that failed
    pub fn remove_peers<I: IntoIterator<Item = PeerId>>(&mut self, peers: I) {
        for peer in peers {
            let _ = self.queues.remove(&peer);
        }
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

/// Available options for the distribution of message delays
#[derive(Clone, Copy, Debug)]
pub enum DelayDistribution {
    Poisson(f64),
    Constant(usize),
}

/// A struct aggregating the options controlling schedule generation
#[derive(Clone, Debug)]
pub struct ScheduleOptions {
    /// Size of the genesis group
    pub genesis_size: usize,
    /// Probability per global step that a node will be scheduled to execute a local step
    pub prob_local_step: f64,
    /// Probabilitity per step that a random node will fail
    pub prob_failure: f64,
    /// Probability that a vote will get repeated
    pub prob_vote_duplication: f64,
    /// A map: step number → num of nodes to fail
    pub deterministic_failures: BTreeMap<usize, usize>,
    /// The distribution of message delays
    pub delay_distr: DelayDistribution,
    /// The strategy that defines when a node gossips
    pub gossip_strategy: GossipStrategy,
    /// When true, nodes will first insert all votes into the graph, then start gossiping
    pub votes_before_gossip: bool,
    /// Number of opaque observations to make
    pub opaque_to_add: usize,
    /// Probability per global step that a node will make a vote
    pub prob_opaque: f64,
    /// The number of peers to be added during the simulation
    pub peers_to_add: usize,
    /// Probability per step that a peer will get added
    pub prob_add: f64,
    /// The number of peers to be removed during the simulation
    pub peers_to_remove: usize,
    /// Probability per step that a peer will get removed
    pub prob_remove: f64,
    /// Minimum number of non-failed peers
    pub min_peers: usize,
    /// Maximum number of peers
    pub max_peers: usize,
}

impl ScheduleOptions {
    /// Generates a delay according to the delay distribution
    pub fn gen_delay<R: Rng>(&self, rng: &mut R) -> usize {
        match self.delay_distr {
            DelayDistribution::Poisson(lambda) => poisson(rng, lambda),
            DelayDistribution::Constant(x) => x,
        }
    }
}

impl Default for ScheduleOptions {
    fn default() -> ScheduleOptions {
        ScheduleOptions {
            // default genesis of 6 peers
            genesis_size: 6,
            // local step on average every 6-7 steps - not too often
            prob_local_step: 0.15,
            // no randomised failures
            prob_failure: 0.0,
            // no vote duplication
            prob_vote_duplication: 0.0,
            // no deterministic failures
            deterministic_failures: BTreeMap::new(),
            // randomised delays, 4 steps on average
            delay_distr: DelayDistribution::Poisson(4.0),
            // gossip when we receive new data
            gossip_strategy: GossipStrategy::AfterReceive,
            // vote while gossiping
            votes_before_gossip: false,
            // add 5 opaque observations
            opaque_to_add: 5,
            // vote for an opaque observation every ~20 steps
            prob_opaque: 0.05,
            // no adds
            peers_to_add: 0,
            // add a node every 50 steps, on average
            prob_add: 0.02,
            // no removes
            peers_to_remove: 0,
            // remove a node every 50 steps, on average
            prob_remove: 0.02,
            // always keep at least 3 active peers
            min_peers: 3,
            // allow at most as many peers as we have names
            max_peers: NAMES.len(),
        }
    }
}

enum ObservationEvent {
    Genesis(BTreeSet<PeerId>),
    Opaque(Transaction),
    AddPeer(PeerId),
    RemovePeer(PeerId),
    Fail(PeerId),
}

type ObservationSchedule = Vec<(usize, ObservationEvent)>;

fn gen_observation_schedule<R: Rng>(rng: &mut R, options: &ScheduleOptions) -> ObservationSchedule {
    let mut schedule = vec![];
    let mut names_iter = NAMES.iter();

    // a counter for peer adds/removes and opaque transactions
    // (so not counting genesis and failures)
    let mut num_observations: usize = 0;
    let mut added_peers: usize = 0;
    let mut removed_peers: usize = 0;
    // schedule genesis first
    let genesis_names = names_iter
        .by_ref()
        .take(options.genesis_size)
        .map(|s| PeerId::new(*s))
        .collect();
    let mut peers = Peers::new(&genesis_names);
    schedule.push((0, ObservationEvent::Genesis(genesis_names)));

    let mut step: usize = 1;
    while num_observations < options.opaque_to_add + options.peers_to_add + options.peers_to_remove
    {
        if rng.gen::<f64>() < options.prob_opaque {
            schedule.push((step, ObservationEvent::Opaque(rng.gen())));
            num_observations += 1;
        }
        if added_peers < options.peers_to_add && rng.gen::<f64>() < options.prob_add {
            let next_id = PeerId::new(names_iter.next().unwrap());
            peers.add_peer(next_id.clone());
            schedule.push((step, ObservationEvent::AddPeer(next_id)));
            num_observations += 1;
            added_peers += 1;
        }
        if removed_peers < options.peers_to_remove && rng.gen::<f64>() < options.prob_remove {
            if let Some(id) = peers.remove_peer(rng, options.min_peers) {
                schedule.push((step, ObservationEvent::RemovePeer(id)));
                num_observations += 1;
                removed_peers += 1;
            }
        }
        if rng.gen::<f64>() < options.prob_failure {
            if let Some(id) = peers.fail_peer(rng, options.min_peers) {
                schedule.push((step, ObservationEvent::Fail(id)));
            }
        }
        step += 1;
    }

    schedule
}

/// Stores the list of network events to be simulated.
#[derive(Clone)]
pub struct Schedule {
    pub num_observations: usize,
    pub events: Vec<ScheduleEvent>,
}

impl fmt::Debug for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "----------------------------")?;
        writeln!(f, " Schedule:")?;
        for event in &self.events {
            writeln!(f, "- {:?}", event)?;
        }
        writeln!(f, "----------------------------")
    }
}

impl Schedule {
    #[cfg(feature = "dump-graphs")]
    fn save(&self, options: &ScheduleOptions) {
        let path = DIR.with(|dir| dir.join("schedule.txt"));
        if let Ok(mut file) = File::create(&path) {
            unwrap!(writeln!(
                file,
                "Generating a schedule with options: {:?}",
                options
            ));
            unwrap!(write!(file, "{:?}", self));
        } else {
            println!("Failed to create {:?}", path);
        }
    }

    fn perform_step<R: Rng>(
        rng: &mut R,
        step: usize,
        peers: &mut Vec<PeerId>,
        // note: mut required below for reborrowing in ScheduleEvent::gen_random
        mut pending: Option<&mut PendingObservations>,
        schedule: &mut Vec<ScheduleEvent>,
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
            .map(ScheduleEvent::Fail)
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
        let failed_peers: BTreeSet<_> = fails.iter().filter_map(|e| e.fail().cloned()).collect();
        // other events can still refer to failed peers, as they were drawn using the full peer
        // list
        other.retain(|ev| !failed_peers.contains(ev.get_peer()));
        peers.retain(|p| !failed_peers.contains(p));
        if let Some(pending) = pending {
            pending.remove_peers(failed_peers);
        }
        // finally, add all events to results
        schedule.extend(fails);
        schedule.extend(other);
    }

    /// Creates a new pseudo-random schedule based on the given options
    ///
    /// The `let_and_return` clippy lint is allowed since it is actually necessary to create the
    /// `result` variable so the result can be saved when the `dump-graphs` feature is used.
    #[cfg_attr(feature = "cargo-clippy", allow(let_and_return))]
    pub fn new(env: &mut Environment, options: &ScheduleOptions) -> Schedule {
        let mut peers: Vec<_> = env.network.peers.iter().map(|(id, _)| id.clone()).collect();
        let num_peers = env.network.peers.len();
        let mut pending = PendingObservations::new(&mut env.rng, &peers, &env.observations);
        let mut step = 0;

        // if votes before gossip enabled, insert all votes
        let mut schedule = if options.votes_before_gossip {
            pending
                .all_observations()
                .map(|(p, tx)| ScheduleEvent::VoteFor(p, tx))
                .collect()
        } else {
            vec![]
        };

        while !pending.is_empty() {
            Self::perform_step(
                &mut env.rng,
                step,
                &mut peers,
                Some(&mut pending),
                &mut schedule,
                num_peers,
                options,
            );
            step += 1;
        }
        let n = peers.len() as f64;
        // Gossip should theoretically complete in O(log N) steps
        // But the number of local steps taken by each node depends on the probability
        // of a local step - each node will take on avg [num steps]*[prob] local steps
        // Thus, we divide log N by the probability.
        // The constant (adjustment_coeff) is for making the number big enough.
        let adjustment_coeff = 200.0;
        let additional_steps = (adjustment_coeff * n.ln() / options.prob_local_step) as usize;
        for _ in 0..additional_steps {
            Self::perform_step(
                &mut env.rng,
                step,
                &mut peers,
                None,
                &mut schedule,
                num_peers,
                options,
            );
            step += 1;
        }
        let result = Schedule {
            // HACK: + 1 is for the `Genesis` observation
            num_observations: env.observations.len() + 1,
            events: schedule,
        };
        #[cfg(feature = "dump-graphs")]
        result.save(options);
        result
    }
}
