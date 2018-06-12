// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use id::SecretId;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use test_utils::{init_rng, FullId, Network, Transaction};

#[test]
fn minimal_network() {
    let mut rng = init_rng(None);

    // 4 is the minimal network size for which the super majority is less than it.
    let num_peers = 4;
    let max_iterations = 100;

    let mut network = Network::new(num_peers);
    let id = FullId::new();
    let transaction = Transaction::InsertPeer(*id.public_id());

    for peer in network.peers_mut().values_mut() {
        assert!(!peer.have_voted_for(&transaction));
        assert!(peer.vote_for(transaction.clone()).is_ok());
    }

    let mut consensued_peer = BTreeSet::new();
    let mut iterations = 0;
    loop {
        network.send_random_syncs(&mut rng);
        for (peer_id, peer) in network.peers_mut() {
            if peer.poll().is_ok() {
                let _ = consensued_peer.insert(*peer_id);
            }
        }
        if consensued_peer.len() == num_peers {
            break;
        }
        assert!(iterations < max_iterations);
        iterations += 1;
    }

    for peer in network.peers().values() {
        assert!(peer.have_voted_for(&transaction));
    }
}
