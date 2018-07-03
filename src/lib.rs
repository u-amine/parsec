// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! This is an implementation of PARSEC (Protocol for Asynchronous, Reliable, Secure and Efficient
//! Consensus).  For details of the protocol, see
//! [the RFC](https://github.com/maidsafe/rfcs/tree/master/text/0049-parsec/0049-parsec.md) and
//! [the whitepaper](http://docs.maidsafe.net/Whitepapers/pdf/PARSEC.pdf).

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

extern crate maidsafe_utilities;
#[macro_use]
extern crate quick_error;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate tiny_keccak;

mod block;
mod dump_network;
mod error;
mod gossip;
mod hash;
mod id;
mod meta_vote;
mod network_event;
mod parsec;
mod peer_manager;
mod round_hash;
mod vote;

#[doc(hidden)]
/// **NOT FOR PRODUCTION USE**: Mock types which trivially implement the required Parsec traits.
///
/// This can be used to swap proper cryptographic functionality for inexpensive (in some cases
/// no-op) replacements.  This is useful to allow tests to run quickly, but should not be used
/// outside of testing code.
pub mod mock;

pub use block::Block;
pub use error::Error;
pub use gossip::{Request, Response};
pub use id::{Proof, PublicId, SecretId};
pub use network_event::NetworkEvent;
pub use parsec::Parsec;
pub use vote::Vote;

/// This function will dump the graphs from all provided peers in dot format to a random folder in
/// the system's temp dir.  The location of this folder will be printed to stdout.  The function
/// will never panic, and hence is suitable for use in creating these files after a thread has
/// already panicked, e.g. in the case of a test failure.
#[cfg(feature = "dump-graphs")]
pub fn dump_graphs<T: NetworkEvent, S: SecretId>(peers: &[(&S::PublicId, &Parsec<T, S>)]) {
    use rand::Rng;
    use std::env;
    use std::fs::{self, File};
    use std::io::Write;

    let folder_name = rand::thread_rng()
        .gen_ascii_chars()
        .take(6)
        .collect::<String>();
    let dir = env::temp_dir().join("parsec_graphs").join(folder_name);
    if let Err(error) = fs::create_dir_all(&dir) {
        println!("Failed to create folder for dot files: {:?}", error);
    } else {
        println!("Writing dot files in {:?}", dir);
    }
    for (peer_id, parsec) in peers {
        let file_path = dir.join(format!("{:?}.dot", peer_id));
        if let Ok(mut file) = File::create(&file_path) {
            let _ = write!(file, "{:?}", parsec);
        } else {
            println!("Failed to create {:?}", file_path);
        }
    }
}
