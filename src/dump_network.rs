// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::Event;
use hash::Hash;
use id::SecretId;
use meta_vote::MetaVote;
use network_event::NetworkEvent;
use std::cmp;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

fn first_char<D: Debug>(id: &D) -> Option<char> {
    format!("{:?}", id).chars().next()
}

fn write_self_parents<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    node: &S::PublicId,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    events: &[&Event<T, S::PublicId>],
    positions: &BTreeMap<Hash, u64>,
) -> fmt::Result {
    writeln!(f, "    {:?} [style=invis]", node)?;
    for event in events {
        if let Some(self_parent) = event.self_parent() {
            let parent = if let Some(parent) = gossip_graph.get(self_parent) {
                parent
            } else {
                continue;
            };
            let event_pos = *positions.get(event.hash()).unwrap_or(&0);
            let self_parent_pos = *positions.get(parent.hash()).unwrap_or(&0);
            let minlen = if event_pos > self_parent_pos {
                event_pos - self_parent_pos
            } else {
                1
            };
            writeln!(
                f,
                "    \"{:?}\" -> \"{:?}\" [minlen={}]",
                self_parent,
                event.hash(),
                minlen
            )?
        } else {
            writeln!(f, "    {:?} -> \"{:?}\" [style=invis]", node, event.hash())?
        }
    }
    writeln!(f)
}

fn write_subgraph<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    node: &S::PublicId,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    events: &[&Event<T, S::PublicId>],
    positions: &BTreeMap<Hash, u64>,
) -> fmt::Result {
    writeln!(f, "    style=invis")?;
    writeln!(f, "  subgraph cluster_{:?} {{", node)?;
    writeln!(f, "    label={:?}", node)?;
    write_self_parents::<T, S>(f, node, gossip_graph, events, positions)?;
    writeln!(f)?;
    writeln!(f, "  }}")
}

fn write_other_parents<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    events: &[&Event<T, S::PublicId>],
) -> fmt::Result {
    // Write the communications between events
    for event in events {
        if let Some(other_event) = event.other_parent() {
            writeln!(
                f,
                "  \"{:?}\" -> \"{:?}\" [constraint=false]",
                other_event,
                event.hash()
            )?;
        }
    }
    writeln!(f)
}

fn write_nodes<S: SecretId>(f: &mut Formatter, nodes: &[S::PublicId]) -> fmt::Result {
    writeln!(f, "  {{")?;
    writeln!(f, "    rank=same")?;
    for node in nodes {
        writeln!(f, "    {:?} [style=filled, color=white]", node)?;
    }
    writeln!(f, "  }}")?;

    // Order the nodes alphabetically
    let mut peers: Vec<&S::PublicId> = nodes.iter().collect();
    peers.sort_by(|lhs, rhs| first_char(lhs).cmp(&first_char(rhs)));

    write!(f, "  ")?;
    let mut index = 0;
    for peer in &peers {
        write!(f, "{:?}", peer)?;
        if index < peers.len() - 1 {
            write!(f, " -> ")?;
            index += 1;
        }
    }
    writeln!(f, " [style=invis]")
}

fn write_evaluates<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    meta_votes: &BTreeMap<Hash, BTreeMap<S::PublicId, Vec<MetaVote>>>,
    initial_events: &[Hash],
) -> fmt::Result {
    for (event_hash, event) in gossip_graph.iter() {
        if let Some(event_meta_votes) = meta_votes.get(event_hash) {
            writeln!(f, " \"{:?}\" [shape=rectangle]", event.hash())?;
            if event_meta_votes.len() == initial_events.len() {
                write!(f, " \"{:?}\" ", event.hash())?;
                write!(
                    f,
                    " [label=\"{}_{}",
                    first_char(event.creator()).unwrap_or('E'),
                    event.index.unwrap_or(0)
                )?;

                let mut peer_ids: Vec<&S::PublicId> = event_meta_votes.keys().collect();
                peer_ids.sort_by(|lhs, rhs| first_char(lhs).cmp(&first_char(rhs)));

                for peer in &peer_ids {
                    if let Some(votes) = event_meta_votes.get(peer) {
                        if votes.is_empty() {
                            write!(f, "\n{}: []", first_char(peer).unwrap_or('E'))?;
                        } else {
                            write!(f, "\n{}: [ ", first_char(peer).unwrap_or('E'))?;
                            for i in 0..votes.len() {
                                if i == votes.len() - 1 {
                                    write!(f, "{:?}]", votes[i])?;
                                } else {
                                    writeln!(f, "{:?}", votes[i])?;
                                }
                            }
                        }
                    }
                }

                writeln!(f, "\"]")?;
                continue;
            }
        }
        writeln!(
            f,
            " \"{:?}\" [label=\"{}_{}\"]",
            event.hash(),
            first_char(event.creator()).unwrap_or('E'),
            event.index.unwrap_or(0)
        )?;
    }

    writeln!(f)
}

fn parent_pos(
    index: Option<u64>,
    parent_hash: Option<&Hash>,
    positions: &BTreeMap<Hash, u64>,
) -> Option<u64> {
    if let Some(parent_hash) = parent_hash {
        if let Some(parent_pos) = positions.get(parent_hash) {
            Some(*parent_pos)
        } else {
            None
        }
    } else {
        Some(index.unwrap_or(0))
    }
}

fn update_pos<T: NetworkEvent, S: SecretId>(
    positions: &mut BTreeMap<Hash, u64>,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
) {
    while positions.len() < gossip_graph.len() {
        for (hash, event) in gossip_graph.iter() {
            if !positions.contains_key(hash) {
                let self_parent_pos = if let Some(position) =
                    parent_pos(event.index, event.self_parent(), &positions)
                {
                    position
                } else {
                    continue;
                };
                let other_parent_pos = if let Some(position) =
                    parent_pos(event.index, event.other_parent(), &positions)
                {
                    position
                } else {
                    continue;
                };
                let _ = positions.insert(*hash, cmp::max(self_parent_pos, other_parent_pos) + 1);
                break;
            }
        }
    }
}

fn write_gossip_graph_dot<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    meta_votes: &BTreeMap<Hash, BTreeMap<S::PublicId, Vec<MetaVote>>>,
    initial_events: &[Hash],
) -> fmt::Result {
    let mut nodes = Vec::new();
    for initial in initial_events {
        let initial_event = if let Some(initial_event) = gossip_graph.get(initial) {
            initial_event
        } else {
            continue;
        };
        nodes.push(initial_event.creator().clone());
    }

    let mut positions: BTreeMap<Hash, u64> = BTreeMap::new();
    update_pos::<T, S>(&mut positions, gossip_graph);

    writeln!(f, "digraph GossipGraph {{")?;
    writeln!(f, "  splines=false")?;
    writeln!(f, "  rankdir=BT")?;

    for node in &nodes {
        let mut events: Vec<&Event<T, S::PublicId>> = gossip_graph
            .values()
            .filter_map(|event| {
                if event.creator() == node {
                    Some(event)
                } else {
                    None
                }
            })
            .collect();
        events.sort_by_key(|event| event.index.unwrap_or(0));
        write_subgraph::<T, S>(f, node, gossip_graph, &events, &positions)?;
        write_other_parents::<T, S>(f, &events)?;
    }

    write_evaluates::<T, S>(f, gossip_graph, meta_votes, initial_events)?;

    write_nodes::<S>(f, &nodes)?;
    writeln!(f, "}}")
}

/// Output a graphviz of the gossip graph.
pub(crate) fn dump_gossip_graph<T: NetworkEvent, S: SecretId>(
    f: &mut Formatter,
    gossip_graph: &BTreeMap<Hash, Event<T, S::PublicId>>,
    meta_votes: &BTreeMap<Hash, BTreeMap<S::PublicId, Vec<MetaVote>>>,
) -> fmt::Result {
    let initial_events: Vec<Hash> = gossip_graph
        .iter()
        .filter_map(|(hash, event)| {
            if event.index.unwrap_or(0) == 0 {
                Some(*hash)
            } else {
                None
            }
        })
        .collect();
    write_gossip_graph_dot::<T, S>(f, gossip_graph, meta_votes, &initial_events)
}
