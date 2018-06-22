// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::iter;

fn new_set_with_value(value: bool) -> BTreeSet<bool> {
    let mut set = BTreeSet::new();
    let _ = set.insert(value);
    set
}

#[derive(Clone, PartialEq, PartialOrd)]
pub(crate) enum Step {
    ForcedTrue,
    ForcedFalse,
    GenuineFlip,
}

impl Default for Step {
    fn default() -> Step {
        Step::ForcedTrue
    }
}

impl Debug for Step {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let step = match self {
            Step::ForcedTrue => 0,
            Step::ForcedFalse => 1,
            Step::GenuineFlip => 2,
        };
        write!(f, "{}", step)
    }
}

// This holds the state of a (binary) meta vote about which we're trying to achieve consensus.
#[derive(Clone, Default)]
pub(crate) struct MetaVote {
    pub round: usize,
    pub step: Step,
    pub estimates: BTreeSet<bool>,
    pub bin_values: BTreeSet<bool>,
    pub aux_value: Option<bool>,
    pub decision: Option<bool>,
}

fn write_bool(f: &mut Formatter, a_bool: bool) -> fmt::Result {
    if a_bool {
        write!(f, "t")
    } else {
        write!(f, "f")
    }
}

fn write_multiple_bool_values(
    f: &mut Formatter,
    field: &str,
    input: &BTreeSet<bool>,
) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    let values: Vec<&bool> = input.iter().collect();
    if values.len() == 1 {
        write_bool(f, *values[0])?;
    } else if values.len() == 2 {
        write_bool(f, *values[0])?;
        write!(f, ", ")?;
        write_bool(f, *values[1])?;
    }
    write!(f, "}} ")
}

fn write_optional_single_bool_value(
    f: &mut Formatter,
    field: &str,
    value: Option<bool>,
) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    if let Some(vote) = value {
        write_bool(f, vote)?;
    }
    write!(f, "}} ")
}

impl Debug for MetaVote {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{{ {}/{:?}, ", self.round, self.step)?;

        write_multiple_bool_values(f, "est", &self.estimates)?;
        write_multiple_bool_values(f, "bin", &self.bin_values)?;
        write_optional_single_bool_value(f, "aux", self.aux_value)?;
        write_optional_single_bool_value(f, "dec", self.decision)?;

        write!(f, "}}")
    }
}

impl MetaVote {
    pub fn new(initial_estimate: bool, others: &[Vec<MetaVote>], total_peers: usize) -> Vec<Self> {
        let mut initial = Self::default();
        initial.estimates = new_set_with_value(initial_estimate);
        Self::next(&[initial], others, &BTreeMap::new(), total_peers)
    }

    pub fn next(
        parent: &[MetaVote],
        others: &[Vec<MetaVote>],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
    ) -> Vec<Self> {
        let mut next = parent
            .iter()
            .map(|meta_vote| {
                let counts = MetaVoteCounts::new(meta_vote, others, total_peers);
                Self::update_meta_vote(meta_vote, &counts, &coin_tosses)
            })
            .collect::<Vec<_>>();
        while let Some(next_meta_vote) =
            Self::next_meta_vote(next.last(), others, &coin_tosses, total_peers)
        {
            next.push(next_meta_vote);
        }
        next
    }

    fn update_meta_vote(
        meta_vote: &MetaVote,
        counts: &MetaVoteCounts,
        coin_tosses: &BTreeMap<usize, bool>,
    ) -> MetaVote {
        let coin_toss = coin_tosses.get(&meta_vote.round);
        MetaVote {
            round: meta_vote.round,
            step: meta_vote.step.clone(),
            estimates: Self::calculate_new_estimates(&meta_vote, &counts, coin_toss),
            bin_values: Self::calculate_new_bin_values(&meta_vote, &counts),
            aux_value: Self::calculate_new_auxiliary_value(&meta_vote),
            decision: Self::calculate_new_decision(&meta_vote, &counts),
        }
    }

    fn next_meta_vote(
        parent: Option<&MetaVote>,
        others: &[Vec<MetaVote>],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
    ) -> Option<MetaVote> {
        parent.and_then(|parent| {
            let counts = MetaVoteCounts::new(parent, others, total_peers);
            if counts.is_super_majority(counts.aux_values_set()) {
                let coin_toss = coin_tosses.get(&parent.round);
                let mut next = parent.clone();
                Self::increase_step(&mut next, &counts, coin_toss.cloned());
                Some(next)
            } else {
                None
            }
        })
    }

    fn calculate_new_estimates(
        meta_vote: &MetaVote,
        counts: &MetaVoteCounts,
        coin_toss: Option<&bool>,
    ) -> BTreeSet<bool> {
        if let Some(decision) = meta_vote.decision {
            new_set_with_value(decision)
        } else if meta_vote.estimates.is_empty() {
            if let Some(toss) = coin_toss {
                new_set_with_value(*toss)
            } else {
                BTreeSet::new()
            }
        } else {
            let mut new_estimates = meta_vote.estimates.clone();
            if counts.at_least_one_third(counts.estimates_true) {
                let _ = new_estimates.insert(true);
            }
            if counts.at_least_one_third(counts.estimates_false) {
                let _ = new_estimates.insert(false);
            }
            new_estimates
        }
    }

    fn calculate_new_bin_values(meta_vote: &MetaVote, counts: &MetaVoteCounts) -> BTreeSet<bool> {
        if let Some(decision) = meta_vote.decision {
            new_set_with_value(decision)
        } else {
            let mut new_bin_values = meta_vote.bin_values.clone();
            if counts.is_super_majority(counts.estimates_true) {
                let _ = new_bin_values.insert(true);
            }
            if counts.is_super_majority(counts.estimates_false) {
                let _ = new_bin_values.insert(false);
            }
            new_bin_values
        }
    }

    fn calculate_new_auxiliary_value(meta_vote: &MetaVote) -> Option<bool> {
        if let Some(decision) = meta_vote.decision {
            Some(decision)
        } else if meta_vote.aux_value.is_none() && meta_vote.bin_values.is_empty() {
            if meta_vote.bin_values.len() == 1 {
                Some(meta_vote.bin_values.contains(&true))
            } else if meta_vote.bin_values.len() == 2 {
                Some(true)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn calculate_new_decision(meta_vote: &MetaVote, counts: &MetaVoteCounts) -> Option<bool> {
        if meta_vote.decision.is_none() {
            match meta_vote.step {
                Step::ForcedTrue => if meta_vote.bin_values.contains(&true)
                    && counts.is_super_majority(counts.aux_values_true)
                {
                    Some(true)
                } else {
                    None
                },
                Step::ForcedFalse => if meta_vote.bin_values.contains(&false)
                    && counts.is_super_majority(counts.aux_values_false)
                {
                    Some(false)
                } else {
                    None
                },
                Step::GenuineFlip => None,
            }
        } else {
            None
        }
    }

    fn increase_step(
        new_meta_vote: &mut MetaVote,
        counts: &MetaVoteCounts,
        coin_toss: Option<bool>,
    ) {
        new_meta_vote.bin_values.clear();
        new_meta_vote.aux_value = None;

        // Set the estimates as per the concrete coin toss rules.
        match new_meta_vote.step {
            Step::ForcedTrue => {
                if counts.is_super_majority(counts.aux_values_false) {
                    new_meta_vote.estimates = new_set_with_value(false);
                } else if !counts.is_super_majority(counts.aux_values_true) {
                    new_meta_vote.estimates = new_set_with_value(true);
                }
                new_meta_vote.step = Step::ForcedFalse;
            }
            Step::ForcedFalse => {
                if counts.is_super_majority(counts.aux_values_true) {
                    new_meta_vote.estimates = new_set_with_value(true);
                } else if !counts.is_super_majority(counts.aux_values_false) {
                    new_meta_vote.estimates = new_set_with_value(false);
                }
                new_meta_vote.step = Step::GenuineFlip;
            }
            Step::GenuineFlip => {
                if counts.is_super_majority(counts.aux_values_true) {
                    new_meta_vote.estimates = new_set_with_value(true);
                } else if counts.is_super_majority(counts.aux_values_false) {
                    new_meta_vote.estimates = new_set_with_value(false);
                } else if let Some(coin_toss_result) = coin_toss {
                    new_meta_vote.estimates = new_set_with_value(coin_toss_result);
                } else {
                    // Clear the estimates to indicate we're waiting for further events to be
                    // gossiped to try and get the coin toss result.
                    new_meta_vote.estimates.clear();
                }
                new_meta_vote.step = Step::ForcedTrue;
                new_meta_vote.round += 1;
            }
        }
    }
}

// This is used to collect the meta votes of other events relating to a single (binary) meta vote at
// a given round and step.
#[derive(Default)]
struct MetaVoteCounts {
    estimates_true: usize,
    estimates_false: usize,
    bin_values_true: usize,
    bin_values_false: usize,
    aux_values_true: usize,
    aux_values_false: usize,
    total_peers: usize,
}

impl MetaVoteCounts {
    // Construct a `MetaVoteCounts` by collecting details from all meta votes which are for the
    // given `parent`'s `round` and `step`.  These results will include info from our own `parent`
    // meta vote.
    fn new(parent: &MetaVote, others: &[Vec<MetaVote>], total_peers: usize) -> Self {
        let mut counts = MetaVoteCounts::default();
        counts.total_peers = total_peers;
        for vote in others
            .iter()
            .filter_map(|other| {
                other
                    .iter()
                    .filter(|vote| vote.round == parent.round && vote.step == parent.step)
                    .last()
            })
            .chain(iter::once(parent))
        {
            if vote.estimates.contains(&true) {
                counts.estimates_true += 1;
            }
            if vote.estimates.contains(&false) {
                counts.estimates_false += 1;
            }
            if vote.bin_values.contains(&true) {
                counts.bin_values_true += 1;
            }
            if vote.bin_values.contains(&false) {
                counts.bin_values_false += 1;
            }
            match vote.aux_value {
                Some(true) => counts.aux_values_true += 1,
                Some(false) => counts.aux_values_false += 1,
                None => (),
            }
        }
        counts
    }

    fn aux_values_set(&self) -> usize {
        self.aux_values_true + self.aux_values_false
    }

    fn is_super_majority(&self, count: usize) -> bool {
        3 * count > 2 * self.total_peers
    }

    fn at_least_one_third(&self, count: usize) -> bool {
        3 * count >= self.total_peers
    }
}
