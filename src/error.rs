// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

quick_error! {
    /// Parsec error variants.
    #[derive(Debug)]
    pub enum Error {
        /// Payload of a `Vote` doesn't match the payload of a `Block`.
        MismatchedPayload {
            display("The payload of the vote doesn't match the payload of targeted block.")
        }
        /// Failed to verify signature.
        SignatureFailure {
            display("The message or signature might be corrupted, or the signer is wrong.")
        }
        /// Serialisation Error.
        Serialisation(error: ::maidsafe_utilities::serialisation::SerialisationError) {
            display("Serialisation error: {}", error)
            from()
        }
        /// Peer is not known to our node.
        UnknownPeer {
            display("The peer_id is not known to our node's peer_list.")
        }
        /// Peer was known to our node, but is now removed.
        RemovedPeer {
            display("The peer_id has been removed from our node's peer_list.")
        }
        /// Our node has been removed from Parsec.
        SelfRemoved {
            display("Our node has been removed from Parsec.")
        }
        /// The given event is invalid or malformed.
        InvalidEvent {
            display("The given event is invalid or malformed.")
        }
        /// This event's self-parent or other-parent is unknown to our node.
        UnknownParent {
            display("This event's self-parent or other-parent is unknown to this node.")
        }
        /// Our node has already voted for this network event.
        DuplicateVote {
            display("Our node has already voted for this network event.")
        }
        /// Logic error.
        Logic {
            display("This a logic error and represents a flaw in the code.")
        }
    }
}
