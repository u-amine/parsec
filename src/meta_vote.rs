// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeSet;
use std::iter;

fn new_set_with_value(value: bool) -> BTreeSet<bool> {
    let mut set = BTreeSet::new();
    let _ = set.insert(value);
    set
}

#[derive(Clone, PartialEq)]
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

impl MetaVote {
    pub fn new(initial_estimate: bool, others: &[MetaVote], total_peers: usize) -> Self {
        let mut initial = Self::default();
        initial.estimates = new_set_with_value(initial_estimate);
        Self::next(&initial, others, None, total_peers)
    }

    pub fn next(
        parent: &MetaVote,
        others: &[MetaVote],
        coin_toss: Option<bool>,
        total_peers: usize,
    ) -> Self {
        let mut new_meta_vote = parent.clone();

        // If `estimates` is empty, we've been waiting for the result of a coin toss.
        if new_meta_vote.estimates.is_empty() {
            if let Some(coin_toss_result) = coin_toss {
                new_meta_vote.estimates = new_set_with_value(coin_toss_result);
            }
        }

        // Collect the meta vote counts for the current round and step.
        let mut counts = MetaVoteCounts::new(parent, others, total_peers);

        if counts.is_super_majority(counts.aux_values_set()) {
            // We're going to the next step.
            Self::increase_step(&mut new_meta_vote, &counts, coin_toss);
            // Calculate the counts again
            counts = MetaVoteCounts::new(parent, others, total_peers);
        }
        new_meta_vote.estimates = Self::calculate_new_estimates(&new_meta_vote, &parent, &counts);
        new_meta_vote.bin_values = Self::calculate_new_bin_values(&new_meta_vote, &parent, &counts);
        new_meta_vote.aux_value = Self::calculate_new_auxiliary_value(&new_meta_vote, parent);
        new_meta_vote.decision = Self::calculate_new_decision(&new_meta_vote, parent, &counts);

        new_meta_vote
    }

    fn calculate_new_estimates(
        new_meta_vote: &MetaVote,
        parent: &MetaVote,
        counts: &MetaVoteCounts,
    ) -> BTreeSet<bool> {
        if let Some(decision) = parent.decision {
            new_set_with_value(decision)
        } else {
            let mut new_estimates = new_meta_vote.estimates.clone();
            if counts.at_least_one_third(counts.estimates_true) {
                let _ = new_estimates.insert(true);
            }
            if counts.at_least_one_third(counts.estimates_false) {
                let _ = new_estimates.insert(false);
            }
            new_estimates
        }
    }

    fn calculate_new_bin_values(
        new_meta_vote: &MetaVote,
        parent: &MetaVote,
        counts: &MetaVoteCounts,
    ) -> BTreeSet<bool> {
        if let Some(decision) = parent.decision {
            new_set_with_value(decision)
        } else {
            let mut new_bin_values = new_meta_vote.bin_values.clone();
            if counts.is_super_majority(counts.estimates_true) {
                let _ = new_bin_values.insert(true);
            }
            if counts.is_super_majority(counts.estimates_false) {
                let _ = new_bin_values.insert(false);
            }
            new_bin_values
        }
    }

    fn calculate_new_auxiliary_value(new_meta_vote: &MetaVote, parent: &MetaVote) -> Option<bool> {
        if let Some(decision) = parent.decision {
            Some(decision)
        } else if parent.aux_value.is_none() && parent.bin_values.is_empty() {
            if new_meta_vote.bin_values.len() == 1 {
                Some(new_meta_vote.bin_values.contains(&true))
            } else if new_meta_vote.bin_values.len() == 2 {
                Some(true)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn calculate_new_decision(
        new_meta_vote: &MetaVote,
        parent: &MetaVote,
        counts: &MetaVoteCounts,
    ) -> Option<bool> {
        if new_meta_vote.decision.is_none() {
            match parent.step {
                Step::ForcedTrue => if new_meta_vote.bin_values.contains(&true)
                    && counts.is_super_majority(counts.aux_values_true)
                {
                    Some(true)
                } else {
                    None
                },
                Step::ForcedFalse => if new_meta_vote.bin_values.contains(&false)
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
    fn new(parent: &MetaVote, others: &[MetaVote], total_peers: usize) -> Self {
        let mut counts = MetaVoteCounts::default();
        counts.total_peers = total_peers;

        for vote in others.iter().chain(iter::once(parent)) {
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
