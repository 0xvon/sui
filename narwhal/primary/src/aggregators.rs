// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use config::{Committee, Stake};
use crypto::{PublicKey, Signature};
use fastcrypto::traits::EncodeDecodeBase64;
use std::collections::HashSet;
use tracing::debug;
use types::{
    ensure,
    error::{DagError, DagResult},
    Certificate, Header, Vote, HeaderDigest,
};

/// Aggregates votes for a particular header into a certificate.
pub struct VotesAggregator {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl VotesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        vote: Vote,
        committee: &Committee,
        header: &Header,
    ) -> DagResult<Option<Certificate>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author.clone()),
            DagError::AuthorityReuse(author.encode_base64())
        );

        self.votes.push((author.clone(), vote.signature));
        self.weight += committee.stake(&author);
        debug!("MASADEBUG {:?}.3.5: vote weight count: {:?}/{:?} for header {:?}", vote.round, self.weight, committee.quorum_threshold(), header.id);

        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(Certificate::new(
                committee,
                header.clone(),
                self.votes.clone(),
            )?));
        }
        Ok(None)
    }
}

/// Aggregate certificates and check if we reach a quorum.
pub struct CertificatesAggregator {
    weight: Stake,
    certificates: Vec<Certificate>,
    used: HashSet<HeaderDigest>,
}

impl CertificatesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            certificates: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        certificate: Certificate,
        committee: &Committee,
    ) -> Option<Vec<Certificate>> {
        let round = certificate.round();
        let origin = certificate.origin();
        let header_digest = certificate.header.id;

        // Ensure it is the first time this authority votes.
        if !self.used.insert(header_digest.clone()) {
            return None;
        }

        self.certificates.push(certificate);
        self.weight += committee.stake(&origin);

        let weight = self.certificates.len();

        debug!(
            "MASADEBUG {:?}.3.6: certificate weight count: {:?}/{:?}",
            round, weight, committee.quorum_threshold()
        );
        if weight >= committee.quorum_threshold() as usize {
            // Note that we do not reset the weight here. If this function is called again and
            // the proposer didn't yet advance round, we can add extra certificates as parents.
            // This is required when running Bullshark as consensus and does not harm when running
            // Tusk or an external consensus protocol.
            return Some(self.certificates.drain(..).collect());
        }
        None
    }
}
