// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    html_root_url = "https://docs.rs/parsec"
)]
#![forbid(
    exceeding_bitshifts, mutable_transmutes, no_mangle_const_items, unknown_crate_types, warnings
)]
#![deny(
    bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
    overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
    stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused_allocation,
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
extern crate lazy_static;
extern crate maidsafe_utilities;
extern crate parsec;
extern crate rand;
extern crate rust_sodium;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate unwrap;

mod utils;

use self::utils::{Environment, PeerCount, TransactionCount};
use rand::Rng;
use std::collections::BTreeSet;

#[test]
fn minimal_network() {
    // 4 is the minimal network size for which the super majority is less than it.
    let num_peers = 4;
    let mut env = Environment::new(&PeerCount(num_peers), &TransactionCount(1), None);

    for peer in &mut env.network.peers {
        assert!(!peer.parsec.have_voted_for(&env.transactions[0]));
        unwrap!(peer.parsec.vote_for(env.transactions[0].clone()));
    }

    let mut consensued_peers = BTreeSet::new();
    utils::loop_with_max_iterations(100, || {
        env.network.send_random_syncs(&mut env.rng);
        for peer in &mut env.network.peers {
            if peer.parsec.poll().is_some() {
                let _ = consensued_peers.insert(peer.id);
            }
        }
        consensued_peers.len() == num_peers
    });

    for peer in &env.network.peers {
        assert!(peer.parsec.have_voted_for(&env.transactions[0]));
    }
}

#[ignore]
#[test]
fn multiple_votes_before_gossip() {
    let num_transactions = 10;
    let mut env = Environment::new(&PeerCount(4), &TransactionCount(num_transactions), None);

    // Have each peer vote for all transactions in random order.
    for peer in &mut env.network.peers {
        env.rng.shuffle(&mut env.transactions);
        for transaction in &env.transactions {
            unwrap!(peer.parsec.vote_for(transaction.clone()));
        }
    }

    // Gossip to let all peers reach consensus on all the blocks.
    utils::loop_with_max_iterations(100, || {
        env.network.send_random_syncs(&mut env.rng);
        for peer in &mut env.network.peers {
            peer.poll();
        }
        env.network
            .peers
            .iter()
            .all(|peer| peer.blocks.len() >= num_transactions)
    });

    assert!(env.network.blocks_all_in_sequence());
}

#[ignore]
#[test]
fn duplicate_votes_before_gossip() {
    let mut env = Environment::new(&PeerCount(4), &TransactionCount(1), None);

    // Have each peer vote for the single transaction multiple times.
    for peer in &mut env.network.peers {
        unwrap!(peer.parsec.vote_for(env.transactions[0].clone()));
        for _ in 0..9 {
            assert!(peer.parsec.vote_for(env.transactions[0].clone()).is_err())
        }
    }

    // Gossip to let all peers reach consensus on all the blocks.
    utils::loop_with_max_iterations(100, || {
        env.network.send_random_syncs(&mut env.rng);
        for peer in &mut env.network.peers {
            peer.poll();
        }
        env.network.peers.iter().all(|peer| !peer.blocks.is_empty())
    });

    assert!(env.network.peers.iter().all(|peer| peer.blocks.len() == 1));
}

#[ignore]
#[test]
fn faulty_third_never_gossip() {
    let num_peers = 10;
    let num_transactions = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(
        &PeerCount(num_peers),
        &TransactionCount(num_transactions),
        None,
    );

    // Remove faulty peers from `network`.
    env.rng.shuffle(&mut env.network.peers);
    env.network.peers.truncate(num_peers - num_faulty);

    // Have each remaining peer vote for all transactions in random order.
    for peer in &mut env.network.peers {
        env.rng.shuffle(&mut env.transactions);
        for transaction in &env.transactions {
            unwrap!(peer.parsec.vote_for(transaction.clone()));
        }
    }

    // Gossip to let all remaining peers reach consensus on all the blocks.
    utils::loop_with_max_iterations(100, || {
        env.network.send_random_syncs(&mut env.rng);
        for peer in &mut env.network.peers {
            peer.poll();
        }
        env.network
            .peers
            .iter()
            .all(|peer| peer.blocks.len() >= num_transactions)
    });

    assert!(env.network.blocks_all_in_sequence());
}

#[ignore]
#[test]
fn faulty_third_terminate_concurrently() {
    let num_peers = 10;
    let num_transactions = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(
        &PeerCount(num_peers),
        &TransactionCount(num_transactions),
        None,
    );

    // Have each peer vote for all transactions in random order.
    for peer in &mut env.network.peers {
        env.rng.shuffle(&mut env.transactions);
        for transaction in &env.transactions {
            unwrap!(peer.parsec.vote_for(transaction.clone()));
        }
    }

    // While gossiping, at a single random point remove all faulty peers in one go.
    utils::loop_with_max_iterations(100, || {
        env.network.send_random_syncs(&mut env.rng);
        for peer in &mut env.network.peers {
            peer.poll();
        }

        if env.network.peers.len() > num_peers - num_faulty
            && (env.rng.gen_weighted_bool(10)
                || env
                    .network
                    .peers
                    .iter()
                    .any(|peer| peer.blocks.len() >= num_transactions / 2))
        {
            env.rng.shuffle(&mut env.network.peers);
            env.network.peers.truncate(num_peers - num_faulty);
        }

        env.network
            .peers
            .iter()
            .all(|peer| peer.blocks.len() >= num_transactions)
    });

    assert!(env.network.blocks_all_in_sequence());
}

#[ignore]
#[test]
fn faulty_third_terminate_at_random_points() {
    let num_peers = 10;
    let num_transactions = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(
        &PeerCount(num_peers),
        &TransactionCount(num_transactions),
        None,
    );

    // Have each peer vote for all transactions in random order.
    for peer in &mut env.network.peers {
        env.rng.shuffle(&mut env.transactions);
        for transaction in &env.transactions {
            unwrap!(peer.parsec.vote_for(transaction.clone()));
        }
    }

    // While gossiping, at random points remove a single faulty peer, up to a maximum of
    // `num_faulty` peers removed in total.
    utils::loop_with_max_iterations(100, || {
        env.network.send_random_syncs(&mut env.rng);
        for peer in &mut env.network.peers {
            peer.poll();
        }

        if env.network.peers.len() > num_peers - num_faulty && env.rng.gen_weighted_bool(3) {
            env.rng.shuffle(&mut env.network.peers);
            let _ = env.network.peers.pop();
        }

        env.network
            .peers
            .iter()
            .all(|peer| peer.blocks.len() >= num_transactions)
    });

    assert!(env.network.blocks_all_in_sequence());
}
