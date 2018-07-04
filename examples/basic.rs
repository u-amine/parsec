// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A basic example of running some nodes which reach consensus on the order of some random events.

#![forbid(
    exceeding_bitshifts, mutable_transmutes, no_mangle_const_items, unknown_crate_types, warnings
)]
#![deny(
    bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
    overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
    stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
    unused_attributes, unused_comparisons, unused_features, unused_parens, while_true
)]
#![warn(
    trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
    unused_qualifications, unused_results
)]
#![allow(
    box_pointers, missing_copy_implementations, missing_debug_implementations,
    variant_size_differences
)]

#[macro_use]
extern crate clap;
extern crate maidsafe_utilities;
extern crate parsec;
extern crate rand;
#[macro_use]
extern crate unwrap;

use clap::{App, Arg};
use maidsafe_utilities::SeededRng;
use parsec::mock::{self, PeerId, Transaction};
use parsec::{Block, Parsec};
use rand::Rng;
use std::collections::BTreeSet;
use std::process;

const MIN_PEER_COUNT: usize = 2;
const MIN_EVENT_COUNT: usize = 1;
const MAX_EVENT_COUNT: usize = 1000;
const PEERS_ARG_NAME: &str = "peers";
const EVENTS_ARG_NAME: &str = "events";
const MAX_ROUNDS_ARG_NAME: &str = "max-rounds";
const SEED_ARG_NAME: &str = "seed";

type Seed = [u32; 4];

struct Peer {
    id: PeerId,
    parsec: Parsec<Transaction, PeerId>,
    // The random network events which this node has voted for, held in the order in which the votes
    // were made.
    transactions: Vec<Transaction>,
    // The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    blocks: Vec<Block<Transaction, PeerId>>,
}

impl Peer {
    fn new(our_id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self {
        Self {
            id: our_id.clone(),
            parsec: unwrap!(Parsec::new(our_id, genesis_group)),
            transactions: vec![],
            blocks: vec![],
        }
    }

    fn vote_for_first_not_already_voted_for(&mut self, transactions: &[Transaction]) {
        for transaction in transactions {
            if !self.transactions.iter().any(|t| t == transaction) {
                unwrap!(self.parsec.vote_for(transaction.clone()));
                self.transactions.push(transaction.clone());
                break;
            }
        }
    }

    fn poll(&mut self) {
        while let Some(block) = self.parsec.poll() {
            self.blocks.push(block)
        }
    }

    fn blocks_payloads(&self) -> Vec<&Transaction> {
        self.blocks.iter().map(Block::payload).collect::<Vec<_>>()
    }

    fn display_id(&self) -> String {
        format!("{:?}: ", self.id)
    }
}

#[derive(Default)]
struct Params {
    event_count: usize,
    peer_count: usize,
    max_rounds: usize,
    seed: Option<Seed>,
}

fn parse_seed(seed_str: &str) -> Result<Seed, ()> {
    let parts = seed_str
        .split(',')
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    if parts.len() != 4 {
        return Err(());
    }
    let mut seed = [0; 4];
    for (index, part) in parts.iter().enumerate() {
        seed[index] = part
            .trim_matches(|c: char| !c.is_digit(10))
            .parse::<u32>()
            .map_err(|_| ())?;
    }
    Ok(seed)
}

fn get_params() -> Params {
    let events_info = format!(
        "must be a value between {} and {} inclusive.",
        MIN_EVENT_COUNT, MAX_EVENT_COUNT
    );
    let peers_info = format!(
        "must be a value between {} and {} inclusive.",
        MIN_PEER_COUNT,
        mock::names_len()
    );
    let seed_info = format!(
        "should be quoted and in the form of four unsigned integers e.g. --{}=\"1, 2, 3, 4\".",
        SEED_ARG_NAME
    );
    let matches = App::new("Parsec basic example")
        .version(crate_version!())
        .about(
            "This example creates a mock network of peers, each running the Parsec protocol to \
             reach consensus on a number of random network events.  To dump each node's gossip \
             graph in dot format to a file in your system temp dir, build the example with \
             `--features=dump-graphs`.",
        )
        .set_term_width(100)
        .arg(
            Arg::with_name(EVENTS_ARG_NAME)
                .short("e")
                .long(EVENTS_ARG_NAME)
                .default_value("3")
                .value_name("COUNT")
                .help(&format!(
                    "Number of random network events to reach consensus on; {}",
                    events_info
                ))
                .takes_value(true),
        )
        .arg(
            Arg::with_name(PEERS_ARG_NAME)
                .short("p")
                .long(PEERS_ARG_NAME)
                .default_value("4")
                .value_name("COUNT")
                .help(&format!("Number of peers in the network; {}", peers_info))
                .takes_value(true),
        )
        .arg(
            Arg::with_name(MAX_ROUNDS_ARG_NAME)
                .short("r")
                .long(MAX_ROUNDS_ARG_NAME)
                .default_value("1000")
                .value_name("COUNT")
                .help(
                    "Max. number of rounds of gossip between peers in the network.  If consensus \
                     on all events is achieved by all peers in fewer rounds than this, the example \
                     will exit.",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(SEED_ARG_NAME)
                .short("s")
                .long(SEED_ARG_NAME)
                .value_name("VALUE")
                .help(&format!(
                    "Seed used to initialise the random number generator; {}",
                    seed_info
                ))
                .takes_value(true),
        )
        .get_matches();
    let mut params = Params::default();
    match value_t!(matches.value_of(EVENTS_ARG_NAME), usize) {
        Ok(count) if count >= MIN_EVENT_COUNT && count <= MAX_EVENT_COUNT => {
            params.event_count = count
        }
        _ => {
            println!("'{}' {}", EVENTS_ARG_NAME, events_info);
            process::exit(-1);
        }
    }
    match value_t!(matches.value_of(PEERS_ARG_NAME), usize) {
        Ok(count) if count >= MIN_PEER_COUNT && count <= mock::names_len() => {
            params.peer_count = count
        }
        _ => {
            println!("'{}' {}", PEERS_ARG_NAME, peers_info);
            process::exit(-2);
        }
    }
    match value_t!(matches.value_of(MAX_ROUNDS_ARG_NAME), usize) {
        Ok(count) => params.max_rounds = count,
        _ => {
            println!(
                "Failed to parse '{}' as a positive integer.",
                MAX_ROUNDS_ARG_NAME
            );
            process::exit(-3);
        }
    }
    params.seed = matches
        .value_of(SEED_ARG_NAME)
        .map(|seed_str| match parse_seed(seed_str) {
            Ok(seed) => seed,
            Err(()) => {
                println!("'{}' {}", SEED_ARG_NAME, seed_info);
                process::exit(-3);
            }
        });

    println!(
        "Running example with {} random network event{} and {} peers...",
        params.event_count,
        if params.event_count > 1 { "s" } else { "" },
        params.peer_count
    );
    params
}

fn main() {
    let params = get_params();

    // Set up the requested number of peers and random network events.
    let all_ids = mock::create_ids(params.peer_count);
    let genesis_group = all_ids.iter().cloned().collect::<BTreeSet<_>>();
    let mut peers = genesis_group
        .iter()
        .map(|id| Peer::new(id.clone(), &genesis_group))
        .collect::<Vec<_>>();

    let mut rng = params
        .seed
        .map_or_else(SeededRng::new, SeededRng::from_seed);
    println!("Using {:?}", rng);
    let mut transactions = (0..params.event_count)
        .map(|_| rng.gen())
        .collect::<Vec<Transaction>>();

    for round in 0..params.max_rounds {
        println!("\nGossip Round {:03}\n================", round);

        rng.shuffle(&mut peers);
        // Each peer will send a request and handle the corresponding response.  For each peer,
        // there is also a chance that they will vote for one of the transactions if they haven't
        // already done so.
        for sender_index in 0..peers.len() {
            let receiver_index = (sender_index + 1) % peers.len();
            let receiver_id = peers[receiver_index].id.clone();
            let sender_id = peers[sender_index].id.clone();
            let request = unwrap!(
                peers[sender_index]
                    .parsec
                    .create_gossip(Some(receiver_id.clone()))
            );
            let response = unwrap!(
                peers[receiver_index]
                    .parsec
                    .handle_request(&sender_id, request)
            );
            unwrap!(
                peers[sender_index]
                    .parsec
                    .handle_response(&receiver_id, response)
            );

            let peer = &mut peers[sender_index];
            if peer.transactions.len() < params.event_count && rng.gen_weighted_bool(3) {
                rng.shuffle(&mut transactions);
                peer.vote_for_first_not_already_voted_for(&transactions);
            }

            peer.poll();
        }

        peers.sort_by_key(|peer| peer.id.clone());
        println!("Votes:");
        let max_width = unwrap!(peers.iter().map(|peer| peer.display_id().len()).max());
        for peer in &peers {
            println!(
                "  {:2$}{:?}",
                peer.display_id(),
                peer.transactions,
                max_width
            );
        }
        println!("Stable Blocks:");
        for peer in &peers {
            println!(
                "  {:2$}{:?}",
                peer.display_id(),
                peer.blocks_payloads(),
                max_width
            );
        }
        println!();

        peers.sort_by_key(|peer| usize::max_value() - peer.blocks.len());
        let mut payloads = peers[0].blocks_payloads();
        for peer in peers.iter().skip(1) {
            payloads.truncate(peer.blocks.len());
            if peer.blocks_payloads() != payloads {
                println!(
                    "\n!!! {:?} and {:?} have failed to agree on stable block order !!!",
                    peers[0].id, peer.id
                );
                return;
            }
        }

        if peers
            .iter()
            .all(|peer| peer.blocks.len() == params.event_count)
        {
            break;
        } else if round == params.max_rounds - 1 {
            println!(
                "\n!!! Failed to reach consensus within {} rounds of gossip... giving up !!!",
                params.max_rounds
            );
        }
    }
}
