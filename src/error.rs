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
        /// Payload does not match.
        MismatchedPayload {
            description("Payload doesn't match")
            display("The payload of the vote doesn't match the payload of targeted block.")
        }
        /// Failed in verify signature.
        SignatureFailure {
            description("Signature cannot be verified")
            display("The message or signature might be corrupted, or the signer is wrong.")
        }
        /// IO error.
        Io(error: ::std::io::Error) {
            description(error.description())
            display("I/O error: {}", error)
            from()
        }
        /// Serialisation Error.
        Serialisation(error: ::maidsafe_utilities::serialisation::SerialisationError) {
            description(error.description())
            display("Serialisation error: {}", error)
            from()
        }
    }
}
