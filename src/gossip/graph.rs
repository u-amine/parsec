// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Gossip graph

use super::{event::Event, event_hash::EventHash};
use id::PublicId;
use network_event::NetworkEvent;
use std::collections::BTreeMap;

#[serde(bound = "")]
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
pub(crate) struct Graph<T: NetworkEvent, P: PublicId> {
    events: BTreeMap<EventHash, Event<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> Default for Graph<T, P> {
    fn default() -> Self {
        Self {
            events: BTreeMap::new(),
        }
    }
}

impl<T: NetworkEvent, P: PublicId> Graph<T, P> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, event: Event<T, P>) -> EventHash {
        let hash = *event.hash();
        let _ = self.events.insert(hash, event);
        hash
    }

    pub fn get(&self, hash: &EventHash) -> Option<&Event<T, P>> {
        self.events.get(hash)
    }

    pub fn contains(&self, hash: &EventHash) -> bool {
        self.events.contains_key(hash)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[cfg(any(feature = "testing", feature = "dump-graphs"))]
    pub fn iter(&self) -> impl Iterator<Item = (&EventHash, &Event<T, P>)> {
        self.events.iter()
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn hashes(&self) -> impl Iterator<Item = &EventHash> {
        self.events.keys()
    }

    pub fn events(&self) -> impl Iterator<Item = &Event<T, P>> {
        self.events.values()
    }

    pub fn sorted_events_from(&self, start: usize) -> Vec<&Event<T, P>> {
        let mut events: Vec<_> = self
            .events
            .values()
            .filter(|event| event.topological_index() >= start)
            .collect();
        events.sort_by_key(|event| event.topological_index());
        events
    }

    /// Returns an iterator over events sorted topologically starting at the given topological
    /// index.
    pub fn sorted_hashes_from(&self, start: usize) -> Vec<EventHash> {
        let mut hashes: Vec<_> = self
            .events
            .values()
            .filter(|event| event.topological_index() >= start)
            .map(|event| (event.hash(), event.topological_index()))
            .collect();
        hashes.sort_by_key(|&(_, index)| index);
        hashes.into_iter().map(|(hash, _)| *hash).collect()
    }

    /// Iterator over all ancestors of the given event (including itself) in reverse topological order.
    pub fn ancestors<'a>(&'a self, event: &'a Event<T, P>) -> Ancestors<'a, T, P> {
        let mut queue = BTreeMap::new();
        let _ = queue.insert(event.topological_index(), event);

        Ancestors {
            graph: self,
            queue,
            visited: vec![false; event.topological_index() + 1],
        }
    }
}

#[cfg(test)]
impl<T: NetworkEvent, P: PublicId> Graph<T, P> {
    /// Remove the topologically last event.
    pub fn remove_last(&mut self) -> Option<Event<T, P>> {
        let hash = *self
            .events
            .values()
            .max_by_key(|event| event.topological_index())
            .map(|event| event.hash())?;
        self.events.remove(&hash)
    }
}

impl<T: NetworkEvent, P: PublicId> Into<BTreeMap<EventHash, Event<T, P>>> for Graph<T, P> {
    fn into(self) -> BTreeMap<EventHash, Event<T, P>> {
        self.events
    }
}

pub(crate) struct Ancestors<'a, T: NetworkEvent + 'a, P: PublicId + 'a> {
    graph: &'a Graph<T, P>,
    queue: BTreeMap<usize, &'a Event<T, P>>,
    visited: Vec<bool>, // TODO: replace with bitset, for space efficiency
}

impl<'a, T: NetworkEvent, P: PublicId> Iterator for Ancestors<'a, T, P> {
    type Item = &'a Event<T, P>;

    fn next(&mut self) -> Option<Self::Item> {
        // This is a modified breadth-first search: Instead of using a simple queue to track the
        // events to visit next, we use a priority queue (implemented as a BTreeMap keyed by
        // `topological_index`) so the events are visited in reverse topological order (children
        // before parents). We also keep track of the events we already visited, to avoid returning
        // single event more than once.

        loop {
            let index = *self.queue.keys().rev().next()?;
            let event = self.queue.remove(&index)?;

            if self.visited[index] {
                continue;
            }
            self.visited[index] = true;

            if let Some(parent) = event.self_parent().and_then(|hash| self.graph.get(hash)) {
                let _ = self.queue.insert(parent.topological_index(), parent);
            }

            if let Some(parent) = event.other_parent().and_then(|hash| self.graph.get(hash)) {
                let _ = self.queue.insert(parent.topological_index(), parent);
            }

            return Some(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::find_event_by_short_name;
    use dev_utils::parse_test_dot_file;

    #[test]
    fn ancestors_iterator() {
        // Generated with RNG seed: [174994228, 1445633118, 3041276290, 90293447].
        let contents = parse_test_dot_file("carol.dot");
        let graph = contents.events;

        let event = unwrap!(find_event_by_short_name(graph.events(), "B_4"));

        let expected = vec![
            "B_4", "B_3", "D_2", "D_1", "D_0", "B_2", "B_1", "B_0", "A_1", "A_0",
        ];

        let mut actual_names = Vec::new();
        let mut actual_indices = Vec::new();

        for event in graph.ancestors(event) {
            actual_names.push(event.short_name());
            actual_indices.push(event.topological_index());
        }

        assert_eq!(actual_names, expected);

        // Assert the events are yielded in reverse topological order.
        let mut sorted_indices = actual_indices.clone();
        sorted_indices.sort_by(|a, b| b.cmp(a));

        assert_eq!(actual_indices, sorted_indices);
    }
}
