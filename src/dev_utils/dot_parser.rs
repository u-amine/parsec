// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::Event;
use hash::Hash;
use hash::{HASH_LEN, HEX_DIGITS_PER_BYTE};
use meta_voting::{
    BoolSet, MetaElection, MetaElectionHandle, MetaElections, MetaEvent, MetaVote, Step,
};
use mock::{PeerId, Transaction};
use observation::Observation;
use peer_list::{PeerList, PeerState};
use pom::char_class::{alphanum, digit, hex_digit, space};
use pom::parser::*;
use pom::Result as PomResult;
use pom::{DataInput, Parser};
use round_hash::RoundHash;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread;

fn newline() -> Parser<u8, ()> {
    (seq(b"\n") | seq(b"\r\n")).discard()
}

fn next_line() -> Parser<u8, ()> {
    none_of(b"\r\n").repeat(0..) * newline()
}

fn spaces() -> Parser<u8, ()> {
    is_a(space).repeat(0..).discard()
}

fn comment_prefix() -> Parser<u8, ()> {
    seq(b"///") * spaces()
}

#[derive(Debug)]
struct ParsedFile {
    our_id: PeerId,
    peer_list: ParsedPeerList,
    graph: ParsedGraph,
    meta_elections: ParsedMetaElections,
}

fn parse_file() -> Parser<u8, ParsedFile> {
    (parse_our_id() + parse_peer_list() + parse_graph() + parse_meta_elections() - parse_end()).map(
        |(((our_id, peer_list), graph), meta_elections)| ParsedFile {
            our_id,
            peer_list,
            graph,
            meta_elections,
        },
    )
}

fn parse_peer_id() -> Parser<u8, PeerId> {
    is_a(alphanum)
        .repeat(1..)
        .collect()
        .convert(String::from_utf8)
        .map(|s| PeerId::new(&s))
}

fn parse_our_id() -> Parser<u8, PeerId> {
    comment_prefix() * seq(b"our_id: ") * parse_peer_id() - next_line()
}

#[derive(Debug)]
struct ParsedPeerList(BTreeMap<PeerId, ListDef>);

#[derive(Debug)]
struct ListDef {
    state: PeerState,
    peers: BTreeSet<PeerId>,
}

fn parse_peer_list() -> Parser<u8, ParsedPeerList> {
    let list_defs =
        comment_prefix() * seq(b"peer_list: {") * next_line() * parse_list_def().repeat(0..)
            - comment_prefix()
            - sym(b'}') * next_line();
    list_defs.map(|defs| ParsedPeerList(defs.into_iter().collect()))
}

fn parse_list_def() -> Parser<u8, (PeerId, ListDef)> {
    let list_def = comment_prefix() * parse_peer_id() - seq(b"; ") + parse_peer_state()
        - seq(b"; peers: ")
        + parse_peers()
        - next_line();
    list_def.map(|((id, state), peers)| (id, ListDef { state, peers }))
}

fn parse_peer_state() -> Parser<u8, PeerState> {
    let state = seq(b"PeerState(") * list(parse_single_state(), sym(b'|')) - sym(b')');
    state.map(|states| {
        states
            .into_iter()
            .fold(PeerState::inactive(), |s1, s2| s1 | s2)
    })
}

fn parse_single_state() -> Parser<u8, PeerState> {
    seq(b"VOTE").map(|_| PeerState::VOTE)
        | seq(b"SEND").map(|_| PeerState::SEND)
        | seq(b"RECV").map(|_| PeerState::RECV)
}

fn parse_peers() -> Parser<u8, BTreeSet<PeerId>> {
    (sym(b'{') * list(parse_peer_id(), seq(b", ")) - sym(b'}')).map(|v| v.into_iter().collect())
}

#[derive(Debug)]
struct ParsedGraph {
    graph: BTreeMap<String, ParsedEvent>,
    event_details: BTreeMap<String, EventDetails>,
}

#[derive(Debug)]
struct ParsedEvent {
    creator: PeerId,
    self_parent: Option<String>,
    other_parent: Option<String>,
}

const SKIP_DIGRAPH_INITIAL_PROPS: usize = 4;
const SKIP_STYLE_INVIS: usize = 3;

fn parse_graph() -> Parser<u8, ParsedGraph> {
    let subgraphs = seq(b"digraph GossipGraph")
        * next_line().repeat(SKIP_DIGRAPH_INITIAL_PROPS)
        * parse_subgraph().repeat(1..)
        - (none_of(b"}").repeat(0..) * one_of(b"}"))
        - next_line().repeat(SKIP_STYLE_INVIS)
        + parse_event_details()
        - seq(b"}")
        - next_line().repeat(2);
    subgraphs.map(|(graphs, details)| {
        let mut graph = BTreeMap::new();
        for subgraph in graphs {
            let mut self_parent = None;
            for event in subgraph.events {
                let other_parent = subgraph.other_parents.get(&event).cloned();
                let _ = graph.insert(
                    event.clone(),
                    ParsedEvent {
                        creator: subgraph.creator.clone(),
                        self_parent: self_parent.clone(),
                        other_parent,
                    },
                );
                self_parent = Some(event);
            }
        }
        ParsedGraph {
            graph,
            event_details: details,
        }
    })
}

#[derive(Debug)]
struct ParsedEdge {
    start: String,
    end: String,
}

#[derive(Debug)]
struct ParsedSubgraph {
    creator: PeerId,
    events: Vec<String>,
    other_parents: BTreeMap<String, String>,
}

const SKIP_AFTER_SUBGRAPH: usize = 3;

fn parse_subgraph() -> Parser<u8, ParsedSubgraph> {
    let id = next_line() * spaces() * seq(b"subgraph cluster_") * parse_peer_id()
        - next_line().repeat(SKIP_AFTER_SUBGRAPH);
    let data = id + parse_edge().repeat(0..) - spaces() - sym(b'}') - next_line()
        + parse_edge().repeat(0..)
        - next_line();
    // edges1 will contain the creator's line - we are only interested in the set of events at the
    // end of edges
    data.map(|((id, edges1), edges2)| ParsedSubgraph {
        creator: id,
        events: edges1.into_iter().map(|edge| edge.end).collect(),
        other_parents: edges2
            .into_iter()
            .map(|edge| (edge.end, edge.start))
            .collect(),
    })
}

fn parse_edge() -> Parser<u8, ParsedEdge> {
    (spaces() * sym(b'"') * parse_event_id() - seq(b"\" -> \"") + parse_event_id() - next_line())
        .map(|(id1, id2)| ParsedEdge {
            start: id1,
            end: id2,
        })
}

fn parse_event_id() -> Parser<u8, String> {
    is_a(|c| alphanum(c) || c == b'_')
        .repeat(1..)
        .convert(String::from_utf8)
}

fn parse_event_details() -> Parser<u8, BTreeMap<String, EventDetails>> {
    seq(b"/// ===== details of events") * next_line() * parse_single_event_detail()
        .repeat(1..)
        .map(|details| details.into_iter().collect())
}

#[derive(Debug)]
struct EventDetails {
    cause: String,
    last_ancestors: BTreeMap<PeerId, u64>,
}

fn skip_brackets() -> Parser<u8, ()> {
    sym(b'[') * (none_of(b"[]").discard() | call(skip_brackets)).repeat(0..) * sym(b']').discard()
}

fn parse_single_event_detail() -> Parser<u8, (String, EventDetails)> {
    (spaces() * sym(b'"') * parse_event_id() - seq(b"\" ") - skip_brackets() - next_line()
        + parse_cause()
        + parse_last_ancestors()
        - next_line()).map(|((id, cause), last_ancestors)| {
        (
            id,
            EventDetails {
                cause,
                last_ancestors,
            },
        )
    })
}

fn parse_cause() -> Parser<u8, String> {
    (comment_prefix() * seq(b"cause: ") * none_of(b"\r\n").repeat(1..) - newline())
        .convert(String::from_utf8)
}

fn parse_last_ancestors() -> Parser<u8, BTreeMap<PeerId, u64>> {
    (comment_prefix() * seq(b"last_ancestors: {") * list(
        parse_peer_id() - seq(b": ") + is_a(digit)
            .repeat(1..)
            .convert(String::from_utf8)
            .convert(|s| u64::from_str(&s)),
        seq(b", "),
    ) - next_line()).map(|v| v.into_iter().collect())
}

#[derive(Debug)]
struct ParsedMetaElections {
    consensus_history: Vec<Hash>,
    meta_elections: BTreeMap<MetaElectionHandle, ParsedMetaElection>,
}

fn parse_meta_elections() -> Parser<u8, ParsedMetaElections> {
    (seq(b"/// ===== meta-elections =====")
     * next_line()
     * parse_consensus_history()
     + parse_meta_election().repeat(0..))
        .map(|(consensus_history, meta_elections)| ParsedMetaElections {
            consensus_history,
            meta_elections: meta_elections.into_iter().collect()
        })
}

fn parse_consensus_history() -> Parser<u8, Vec<Hash>> {
    let hash_line = comment_prefix() * parse_hash() - next_line();
    comment_prefix() * seq(b"consensus_history:") * next_line() * hash_line.repeat(0..)
}

fn parse_hash() -> Parser<u8, Hash> {
    is_a(hex_digit)
        .repeat(HEX_DIGITS_PER_BYTE)
        .convert(String::from_utf8)
        .convert(|s| u8::from_str_radix(&s, 16))
        .repeat(HASH_LEN)
        .map(|v| {
            let mut bytes = [0; HASH_LEN];
            for (i, byte) in v.into_iter().enumerate() {
                bytes[i] = byte;
            }
            Hash::from_bytes(bytes)
        })
}

#[derive(Debug)]
struct ParsedMetaElection {
    consensus_len: usize,
    round_hashes: BTreeMap<PeerId, Vec<RoundHash>>,
    interesting_events: BTreeMap<PeerId, Vec<String>>,
    all_voters: BTreeSet<PeerId>,
    undecided_voters: BTreeSet<PeerId>,
    payload: Option<Observation<Transaction, PeerId>>,
    meta_events: BTreeMap<String, MetaEvent<Transaction, PeerId>>,
}

fn parse_meta_election() -> Parser<u8, (MetaElectionHandle, ParsedMetaElection)> {
    next_line() * parse_meta_election_handle()
        + (parse_consensus_len()
            + parse_round_hashes()
            + parse_interesting_events()
            + parse_all_voters()
            + parse_undecided_voters()
            + parse_payload().opt()
            + parse_meta_events()).map(
            |(
                (
                    (
                        (((consensus_len, round_hashes), interesting_events), all_voters),
                        undecided_voters,
                    ),
                    payload,
                ),
                meta_events,
            )| {
                ParsedMetaElection {
                    consensus_len,
                    round_hashes,
                    interesting_events,
                    all_voters,
                    undecided_voters,
                    payload,
                    meta_events,
                }
            },
        )
}

fn parse_meta_election_handle() -> Parser<u8, MetaElectionHandle> {
    comment_prefix()
        * seq(b"MetaElectionHandle(")
        * (seq(b"CURRENT").map(|_| MetaElectionHandle::CURRENT) | is_a(digit)
            .repeat(1..)
            .convert(String::from_utf8)
            .convert(|s| usize::from_str(&s))
            .map(MetaElectionHandle))
        - sym(b')')
        - next_line()
}

fn parse_consensus_len() -> Parser<u8, usize> {
    comment_prefix() * seq(b"consensus_len: ") * parse_usize() - next_line()
}

fn parse_round_hashes() -> Parser<u8, BTreeMap<PeerId, Vec<RoundHash>>> {
    (comment_prefix()
        * seq(b"round_hashes: {")
        * next_line()
        * parse_round_hashes_for_peer().repeat(0..)
        - comment_prefix()
        - seq(b"}")
        - next_line()).map(|v| v.into_iter().collect())
}

fn parse_round_hashes_for_peer() -> Parser<u8, (PeerId, Vec<RoundHash>)> {
    (comment_prefix() * parse_peer_id() - seq(b" -> [") - next_line()
        + parse_single_round_hash().repeat(0..)
        - comment_prefix()
        - sym(b']')
        - next_line()).map(|(id, hashes)| {
        let round_hashes = hashes
            .into_iter()
            .map(|hash| RoundHash::new_with_round(&id, hash.1, hash.0))
            .collect();
        (id, round_hashes)
    })
}

fn parse_single_round_hash() -> Parser<u8, (usize, Hash)> {
    comment_prefix() * seq(b"RoundHash { round: ") * parse_usize() - seq(b", latest_block_hash: ")
        + parse_hash()
        - next_line()
}

fn parse_usize() -> Parser<u8, usize> {
    is_a(digit)
        .repeat(1..)
        .convert(String::from_utf8)
        .convert(|s| usize::from_str(&s))
}

fn parse_interesting_events() -> Parser<u8, BTreeMap<PeerId, Vec<String>>> {
    (comment_prefix()
        * seq(b"interesting_events: {")
        * next_line()
        * parse_interesting_events_for_peer().repeat(0..)
        - comment_prefix()
        - sym(b'}')
        - next_line()).map(|v| v.into_iter().collect())
}

fn parse_interesting_events_for_peer() -> Parser<u8, (PeerId, Vec<String>)> {
    comment_prefix() * parse_peer_id() - seq(b" -> [")
        + list(sym(b'"') * parse_event_id() - sym(b'"'), seq(b", "))
        - seq(b"]")
        - next_line()
}

fn parse_all_voters() -> Parser<u8, BTreeSet<PeerId>> {
    comment_prefix() * seq(b"all_voters: ") * parse_peers() - next_line()
}

fn parse_undecided_voters() -> Parser<u8, BTreeSet<PeerId>> {
    comment_prefix() * seq(b"undecided_voters: ") * parse_peers() - next_line()
}

fn parse_payload() -> Parser<u8, Observation<Transaction, PeerId>> {
    comment_prefix() * seq(b"payload: ") * parse_observation() - next_line()
}

fn parse_observation() -> Parser<u8, Observation<Transaction, PeerId>> {
    parse_genesis() | parse_add() | parse_remove() | parse_opaque()
}

fn parse_genesis() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"Genesis(") * parse_peers() - seq(b")")).map(Observation::Genesis)
}

fn parse_add() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"Add(") * parse_peer_id() - seq(b")")).map(Observation::Add)
}

fn parse_remove() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"Remove(") * parse_peer_id() - seq(b")")).map(Observation::Remove)
}

fn parse_opaque() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"OpaquePayload(") * parse_transaction() - seq(b")"))
        .map(|s| Transaction::new(&s))
        .map(Observation::OpaquePayload)
}

fn parse_transaction() -> Parser<u8, String> {
    is_a(alphanum).repeat(1..).convert(String::from_utf8)
}

fn parse_meta_events() -> Parser<u8, BTreeMap<String, MetaEvent<Transaction, PeerId>>> {
    (comment_prefix()
        * seq(b"meta_events: {")
        * next_line()
        * parse_single_meta_event().repeat(1..)
        - comment_prefix()
        - sym(b'}')
        - next_line()).map(|v| v.into_iter().collect())
}

fn parse_single_meta_event() -> Parser<u8, (String, MetaEvent<Transaction, PeerId>)> {
    comment_prefix() * parse_event_id() - seq(b" -> {") - next_line() + parse_meta_event_content()
        - comment_prefix()
        - sym(b'}')
        - next_line()
}

fn parse_meta_event_content() -> Parser<u8, MetaEvent<Transaction, PeerId>> {
    (parse_observees() + parse_interesting_content() + parse_meta_votes().opt()).map(
        |((observees, interesting_content), meta_votes)| MetaEvent {
            observees,
            interesting_content,
            meta_votes: meta_votes.unwrap_or_else(BTreeMap::new),
        },
    )
}

fn parse_observees() -> Parser<u8, BTreeSet<PeerId>> {
    comment_prefix() * seq(b"observees: ") * parse_peers() - next_line()
}

fn parse_interesting_content() -> Parser<u8, Vec<Observation<Transaction, PeerId>>> {
    comment_prefix() * seq(b"interesting_content: [") * list(parse_observation(), seq(b", "))
        - next_line()
}

fn parse_meta_votes() -> Parser<u8, BTreeMap<PeerId, Vec<MetaVote>>> {
    (comment_prefix()
        * seq(b"meta_votes: {")
        * next_line()
        * next_line()
        * parse_peer_meta_votes().repeat(0..)
        - comment_prefix()
        - sym(b'}')
        - next_line()).map(|v| v.into_iter().collect())
}

fn parse_peer_meta_votes() -> Parser<u8, (PeerId, Vec<MetaVote>)> {
    let peer_line = comment_prefix() * is_a(alphanum).map(char::from) - seq(b": ")
        + parse_meta_vote()
        - next_line();
    let next_line = comment_prefix() * parse_meta_vote() - next_line();
    (peer_line + next_line.repeat(0..)).map(|((peer_initial, first_mv), other_mvs)| {
        let mut mvs = vec![first_mv];
        mvs.extend(other_mvs);
        (PeerId::from_initial(peer_initial), mvs)
    })
}

fn parse_meta_vote() -> Parser<u8, MetaVote> {
    (parse_usize() - sym(b'/') + parse_usize() - spaces() + parse_bool_set() - spaces()
        + parse_bool_set()
        - spaces()
        + parse_opt_bool()
        - spaces()
        + parse_opt_bool()).map(|(((((round, step), est), bin), aux), dec)| MetaVote {
        round,
        step: match step {
            0 => Step::ForcedTrue,
            1 => Step::ForcedFalse,
            2 => Step::GenuineFlip,
            _ => unreachable!(),
        },
        estimates: est,
        bin_values: bin,
        aux_value: aux,
        decision: dec,
    })
}

fn parse_bool_set() -> Parser<u8, BoolSet> {
    sym(b'-').map(|_| BoolSet::Empty)
        | sym(b'f').map(|_| BoolSet::Single(false))
        | sym(b't').map(|_| BoolSet::Single(true))
        | sym(b'b').map(|_| BoolSet::Both)
}

fn parse_opt_bool() -> Parser<u8, Option<bool>> {
    sym(b'-').map(|_| None) | sym(b'f').map(|_| Some(false)) | sym(b't').map(|_| Some(true))
}

fn parse_end() -> Parser<u8, ()> {
    one_of(b" \r\n").repeat(0..) * end()
}

/// The event graph and associated info that were parsed from the dumped dot file.
pub(crate) struct ParsedContents {
    pub our_id: PeerId,
    pub events: BTreeMap<Hash, Event<Transaction, PeerId>>,
    pub meta_elections: MetaElections<Transaction, PeerId>,
    pub peer_list: PeerList<PeerId>,
}

impl ParsedContents {
    /// Create empty `ParsedContents`.
    pub fn new(our_id: PeerId) -> Self {
        let peer_list = PeerList::new(our_id.clone());
        let meta_elections = MetaElections::new(BTreeSet::new());

        ParsedContents {
            our_id,
            events: BTreeMap::new(),
            meta_elections,
            peer_list,
        }
    }

    /// Remove and return the latest (newest) event from the `ParsedContents`, if any.
    pub fn remove_latest_event(&mut self) -> Option<Event<Transaction, PeerId>> {
        let hash = *self
            .events
            .values()
            .max_by_key(|event| event.topological_index())
            .map(|event| event.hash())?;
        let event = self.events.remove(&hash)?;

        self.peer_list.remove_event(&event);

        Some(event)
    }

    /// Insert event into the `ParsedContents`. Note this does not perform any validations whatsoever,
    /// so this is useful for simulating all kinds of invalid or malicious situations.
    pub fn add_event(&mut self, event: Event<Transaction, PeerId>) {
        unwrap!(self.peer_list.add_event(&event));

        let hash = *event.hash();
        let _ = self.events.insert(hash, event);
    }
}

/// Read a dumped dot file and return with parsed event graph and associated info.
pub(crate) fn parse_dot_file(full_path: &Path) -> io::Result<ParsedContents> {
    let result = unwrap!(read(File::open(full_path)?));
    Ok(convert_into_parsed_contents(result))
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This put the test
/// name as part of the path automatically.
pub(crate) fn parse_test_dot_file(filename: &str) -> ParsedContents {
    parse_dot_file_with_test_name(
        filename,
        &unwrap!(thread::current().name()).replace("::", "_"),
    )
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This reads and
/// parses the dot file as per `parse_dot_file()` above, with test name being part of the path.
pub(crate) fn parse_dot_file_with_test_name(filename: &str, test_name: &str) -> ParsedContents {
    let mut dot_path = PathBuf::from("input_graphs");
    dot_path.push(test_name);
    dot_path.push(filename);
    assert!(
        dot_path.exists(),
        "\nDot file {} doesn't exist.",
        dot_path.display()
    );

    unwrap!(
        parse_dot_file(&dot_path),
        "Failed to parse {}",
        dot_path.display()
    )
}

fn read(mut file: File) -> PomResult<ParsedFile> {
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return Err(::pom::Error::Custom {
            message: "file not found".to_string(),
            position: 0,
            inner: None,
        });
    }

    let mut input = DataInput::new(contents.as_bytes());
    parse_file().parse(&mut input)
}

fn convert_into_parsed_contents(result: ParsedFile) -> ParsedContents {
    let ParsedFile {
        our_id,
        peer_list,
        mut graph,
        meta_elections,
    } = result;

    let mut parsed_contents = ParsedContents::new(our_id.clone());
    let mut event_hashes =
        create_events(&mut graph.graph, &graph.event_details, &mut parsed_contents);

    let peer_states = peer_list
        .0
        .iter()
        .map(|(id, list)| (id.clone(), list.state))
        .collect();
    let peer_list = PeerList::new_from_dot_input(our_id, &parsed_contents.events, &peer_states);

    parsed_contents.peer_list = peer_list;
    parsed_contents.meta_elections = convert_to_meta_elections(meta_elections, &mut event_hashes);
    parsed_contents
}

fn convert_to_meta_elections(
    meta_elections: ParsedMetaElections,
    event_hashes: &mut BTreeMap<String, Hash>,
) -> MetaElections<Transaction, PeerId> {
    let meta_elections_map = meta_elections
        .meta_elections
        .into_iter()
        .map(|(handle, election)| {
            (
                handle,
                convert_to_meta_election(&handle, election, event_hashes),
            )
        }).collect();
    MetaElections::from_map_and_history(meta_elections_map, meta_elections.consensus_history)
}

fn convert_to_meta_election(
    handle: &MetaElectionHandle,
    meta_election: ParsedMetaElection,
    event_hashes: &mut BTreeMap<String, Hash>,
) -> MetaElection<Transaction, PeerId> {
    MetaElection {
        meta_events: meta_election
            .meta_events
            .into_iter()
            .map(|(ev_id, mev)| {
                (
                    *event_hashes
                        .entry(ev_id.clone())
                        .or_insert_with(|| Hash::from(ev_id.as_bytes())),
                    mev,
                )
            }).collect(),
        round_hashes: meta_election.round_hashes,
        all_voters: meta_election.all_voters,
        undecided_voters: meta_election.undecided_voters,
        interesting_events: meta_election
            .interesting_events
            .into_iter()
            .map(|(peer_id, events)| {
                (
                    peer_id,
                    events
                        .into_iter()
                        .map(|ev_id| {
                            *unwrap!(
                                event_hashes.get(&ev_id),
                                "Missing {:?} from meta_events section of meta election {:?}.  \
                                This meta-event must be defined here as it's an Interesting Event.",
                                ev_id,
                                handle
                            )
                        }).collect(),
                )
            }).collect(),
        consensus_len: meta_election.consensus_len,
        payload: meta_election.payload,
    }
}

fn create_events(
    graph: &mut BTreeMap<String, ParsedEvent>,
    details: &BTreeMap<String, EventDetails>,
    parsed_contents: &mut ParsedContents,
) -> BTreeMap<String, Hash> {
    let mut event_hashes = BTreeMap::new();
    while !graph.is_empty() {
        let (ev_id, next_parsed_event) = next_topological_event(graph, &event_hashes);
        let next_event_details = unwrap!(details.get(&ev_id));
        let next_event = Event::new_from_dot_input(
            &next_parsed_event.creator,
            &next_event_details.cause,
            next_parsed_event
                .self_parent
                .and_then(|ref id| event_hashes.get(id).cloned()),
            next_parsed_event
                .other_parent
                .and_then(|ref id| event_hashes.get(id).cloned()),
            parsed_contents.events.len(),
            unwrap!(u64::from_str(unwrap!(ev_id.split('_').nth(1)))),
            next_event_details.last_ancestors.clone(),
        );
        let _ = event_hashes.insert(ev_id, *next_event.hash());
        let _ = parsed_contents
            .events
            .insert(*next_event.hash(), next_event);
    }
    event_hashes
}

fn next_topological_event(
    graph: &mut BTreeMap<String, ParsedEvent>,
    hashes: &BTreeMap<String, Hash>,
) -> (String, ParsedEvent) {
    let next_key = unwrap!(
        graph
            .iter()
            .filter(|&(_, ref event)| event
                .self_parent
                .as_ref()
                .map(|ev_id| hashes.contains_key(ev_id))
                .unwrap_or(true)
                && event
                    .other_parent
                    .as_ref()
                    .map(|ev_id| hashes.contains_key(ev_id))
                    .unwrap_or(true)).map(|(key, _)| key)
            .next()
    ).clone();
    let ev = unwrap!(graph.remove(&next_key));
    (next_key, ev)
}

#[cfg(all(test, feature = "dump-graphs"))]
mod tests {
    use super::*;
    use dev_utils::{Environment, RngChoice, Schedule, ScheduleOptions};
    use dump_graph::DIR;
    use maidsafe_utilities::serialisation::deserialise;
    use meta_voting::MetaElections;
    use mock::{PeerId, Transaction};
    use std::fs;

    type SerialisedGraph = (
        BTreeMap<Hash, Event<Transaction, PeerId>>,
        MetaElections<Transaction, PeerId>,
    );

    // Alter the seed here to reproduce failures
    static SEED: RngChoice = RngChoice::SeededRandom;

    #[test]
    fn dot_parser() {
        let mut env = Environment::new(SEED);
        let schedule = Schedule::new(
            &mut env,
            &ScheduleOptions {
                genesis_size: 4,
                opaque_to_add: 5,
                gossip_prob: 0.8,
                ..Default::default()
            },
        );

        let result = env.network.execute_schedule(schedule);
        assert!(result.is_ok(), "{:?}", result);

        let mut num_of_files = 0u8;
        let entries = DIR.with(|dir| unwrap!(fs::read_dir(dir)));
        for entry in entries {
            let entry = unwrap!(entry);

            if !unwrap!(entry.file_name().to_str()).contains(".core") {
                continue;
            }
            num_of_files += 1;
            let mut core_file = unwrap!(File::open(entry.path()));
            let mut core_info = Vec::new();
            assert_ne!(unwrap!(core_file.read_to_end(&mut core_info)), 0);

            let (mut gossip_graph, meta_elections): SerialisedGraph =
                unwrap!(deserialise(&core_info));

            let mut dot_file_path = entry.path();
            assert!(dot_file_path.set_extension("dot"));
            let parsed_result = unwrap!(parse_dot_file(&dot_file_path));

            assert_eq!(gossip_graph, parsed_result.events);
            assert_eq!(meta_elections, parsed_result.meta_elections);
        }
        assert_ne!(num_of_files, 0u8);
    }
}
