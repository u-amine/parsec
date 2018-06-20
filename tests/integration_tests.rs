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
    box_pointers, missing_copy_implementations, missing_debug_implementations, unused,
    variant_size_differences
)]

#[macro_use]
extern crate lazy_static;
extern crate parsec;
extern crate rand;
extern crate rust_sodium;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate unwrap;

mod utils;

use self::utils::{init_rng, FullId, Network, Transaction};
use parsec::SecretId;
use std::collections::BTreeSet;

#[ignore]
#[test]
fn minimal_network() {
    let mut rng = init_rng(None);

    // 4 is the minimal network size for which the super majority is less than it.
    let num_peers = 4;
    let max_iterations = 100;

    let mut network = Network::new(num_peers);
    let id = FullId::new();
    let transaction = Transaction::InsertPeer(*id.public_id());

    for peer in network.peers.values_mut() {
        assert!(!peer.have_voted_for(&transaction));
        assert!(peer.vote_for(transaction.clone()).is_ok());
    }

    let mut consensued_peer = BTreeSet::new();
    let mut iterations = 0;
    loop {
        assert!(iterations < max_iterations);
        network.send_random_syncs(&mut rng);
        for (peer_id, peer) in &mut network.peers {
            if peer.poll().is_some() {
                let _ = consensued_peer.insert(*peer_id);
            }
        }
        if consensued_peer.len() == num_peers {
            break;
        }
        iterations += 1;
    }

    for peer in network.peers.values() {
        assert!(peer.have_voted_for(&transaction));
    }
}
