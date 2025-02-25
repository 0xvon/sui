// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    aggregators::{CertificatesAggregator, VotesAggregator},
    metrics::PrimaryMetrics,
    primary::PrimaryMessage,
    synchronizer::Synchronizer,
};
use async_recursion::async_recursion;
use config::{Committee, Epoch, SharedWorkerCache};
use crypto::{PublicKey, Signature};
use fastcrypto::{Hash as _, SignatureService};
use itertools::Itertools;
use network::{CancelOnDropHandler, P2pNetwork, ReliableNetwork};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};
use storage::CertificateStore;
use store::Store;
use tokio::{sync::watch, task::JoinHandle};
use tracing::{debug, error, info, instrument, warn};
use types::{
    ensure,
    error::{DagError, DagError::StoreError, DagResult},
    metered_channel::{Receiver, Sender},
    Certificate, Header, HeaderDigest, ReconfigureNotification, Round, RoundVoteDigestPair, Vote,
};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The worker information cache.
    worker_cache: SharedWorkerCache,
    /// The persistent storage keyed to headers.
    header_store: Store<HeaderDigest, Header>,
    /// The persistent storage keyed to certificates.
    certificate_store: CertificateStore,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// Service to sign headers.
    signature_service: SignatureService<Signature>,
    /// Get a signal when the round changes
    rx_consensus_round_updates: watch::Receiver<u64>,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Watch channel to reconfigure the committee.
    rx_reconfigure: watch::Receiver<ReconfigureNotification>,
    /// Receiver for dag messages (headers, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<Header>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid a vote to the `Proposer` (along with their round).
    tx_proposer_vote: Sender<(Vote, Round, Epoch)>,

    /// The last garbage collected round.
    gc_round: Round,
    /// The highest certificates round received by this node.
    highest_received_round: Round,
    /// The highest certificates round processed by this node.
    highest_processed_round: Round,
    /// The set of headers we are currently processing.
    processing: HashMap<Round, HashSet<HeaderDigest>>,
    /// The store to persist the last voted round per authority, used to ensure idempotence.
    vote_digest_store: Store<PublicKey, RoundVoteDigestPair>,
    /// Aggregates votes into a certificate.
    votes_aggregators: HashMap<HeaderDigest, VotesAggregator>,
    /// Aggregates certificates to use as parents for new headers.
    certificates_aggregators: HashMap<Round, Box<CertificatesAggregator>>,
    /// A network sender to send the batches to the other workers.
    network: P2pNetwork,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelOnDropHandler<anyhow::Result<anemo::Response<()>>>>>,
    /// Metrics handler
    metrics: Arc<PrimaryMetrics>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        worker_cache: SharedWorkerCache,
        header_store: Store<HeaderDigest, Header>,
        certificate_store: CertificateStore,
        vote_digest_store: Store<PublicKey, RoundVoteDigestPair>,
        synchronizer: Synchronizer,
        signature_service: SignatureService<Signature>,
        rx_consensus_round_updates: watch::Receiver<u64>,
        gc_depth: Round,
        rx_committee: watch::Receiver<ReconfigureNotification>,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        tx_consensus: Sender<Certificate>,
        tx_proposer_vote: Sender<(Vote, Round, Epoch)>,
        metrics: Arc<PrimaryMetrics>,
        primary_network: P2pNetwork,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                worker_cache,
                header_store,
                certificate_store,
                synchronizer,
                signature_service,
                rx_consensus_round_updates,
                gc_depth,
                rx_reconfigure: rx_committee,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                tx_consensus,
                tx_proposer_vote,
                gc_round: 0,
                highest_received_round: 0,
                highest_processed_round: 0,
                processing: HashMap::with_capacity(2 * gc_depth as usize),
                vote_digest_store,
                votes_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: primary_network,
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                metrics,
            }
            .recover()
            .await
            .run()
            .await;
        })
    }

    #[instrument(level = "info", skip_all)]
    pub async fn recover(mut self) -> Self {
        info!("Starting certificate recovery. Message processing will begin after completion.");

        let last_round_certificates = self
            .certificate_store
            .last_round()
            .expect("Failed recovering certificates in primary core");

        for certificate in last_round_certificates {
            self.append_certificate_in_aggregator(certificate)
                .await
                .expect("Failed appending recovered certificates to aggregator in primary core");
        }
        self
    }

    // process own header
    #[instrument(level = "debug", skip_all, fields(header_digest = ?header.digest()))]
    async fn process_own_header(&mut self, header: Header) -> DagResult<()> {
        if header.epoch < self.committee.epoch() {
            debug!("Proposer outdated");
            return Ok(());
        }

        // Update the committee now if the proposer already did so.
        self.try_update_committee().await;

        // Broadcast the new header in a reliable manner.
        let peers = self
            .committee
            .others_primaries(&self.name)
            .into_iter()
            .map(|(_, _, network_key)| network_key)
            .collect();

        let message = PrimaryMessage::Header(header.clone());
        let handlers = self.network.broadcast(peers, &message).await;
        self.cancel_handlers
            .entry(header.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Process the header.
        self.process_header(&header).await
    }

    #[async_recursion]
    #[instrument(level = "debug", skip_all, fields(header_digest = ?header.digest()))]
    async fn process_header(&mut self, header: &Header) -> DagResult<()> {
        debug!(
            "MASADEBUG {:?}.1: Processing header {:?}",
            header.round, header
        );

        let header_source = if self.name.eq(&header.author) {
            "own"
        } else {
            "other"
        };

        // Indicate that we are processing this header.
        let inserted = self
            .processing
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.id);

        if inserted {
            // Only increase the metric when the header has been seen for the first
            // time. Edge case is headers received past gc_round so we might have already
            // processed them, but not big issue for now.
            self.metrics
                .unique_headers_received
                .with_label_values(&[&header.epoch.to_string(), header_source])
                .inc();
        }

        // If the following condition is valid, it means we already garbage collected the parents. There is thus
        // no points in trying to synchronize them or vote for the header. We just need to gather the payload.
        if self.gc_round >= header.round {
            if self.synchronizer.missing_payload(header).await? {
                self.metrics
                    .headers_suspended
                    .with_label_values(&[&header.epoch.to_string(), "missing_payload"])
                    .inc();
                debug!("Downloading the payload of {header}");
            }
            return Ok(());
        }

        // Check the parent votes. Ensure the parents form a quorum and are all from the previous round.
        // let mut stake = 0;
        // for x in &header.prev_votes {
        //     ensure!(
        //         x.round() + 1 == header.round,
        //         DagError::MalformedHeader(header.id)
        //     );
        //     stake += self.committee.stake(&x.origin());
        // }
        // ensure!(
        //     stake >= self.committee.quorum_threshold(),
        //     DagError::HeaderRequiresQuorum(header.id)
        // );

        let _vote = self.process_prev_votes(header).await;
        info!("process_prev_votes finished");

        // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
        // reschedule processing of this header once we have it.
        if self.synchronizer.missing_payload(header).await? {
            self.metrics
                .headers_suspended
                .with_label_values(&[&header.epoch.to_string(), "missing_payload"])
                .inc();
            debug!("Processing of {header} suspended: missing payload");
            return Ok(());
        }

        // Store the header.
        self.header_store.write(header.id, header.clone()).await;

        self.metrics
            .headers_processed
            .with_label_values(&[&header.epoch.to_string(), header_source])
            .inc();

        // Check if we can vote for this header.
        // Send the vote when:
        // 1. when there is no existing vote for this publicKey & round
        //    (for this publicKey the last voted round in the votes store < header.round)
        // 2. when there is a vote for this publicKey & round,
        //    (for this publicKey the last voted round in the votes store = header.round)
        //    and the hash also corresponding to the vote we already sent matches the hash of
        //    the vote we create for this header we received
        // Taking the inverse of these two, the only time we don't want to vote is when:
        // there is a digest for the publicKey & round, and it does not match the digest of the
        // vote we create for this header.
        // Also when the header round is less than the latest round we have already voted for,
        // then it is useless to vote, so we don't.

        let result = self
            .vote_digest_store
            .read(header.author.clone())
            .await
            .map_err(StoreError)?;

        if let Some(round_digest_pair) = result {
            debug!("MASADEBUG: pair found");
            if header.round < round_digest_pair.round {
                return Ok(());
            }
            if header.round == round_digest_pair.round {
                // check the hash first
                let temp_vote = Vote::new(header, &self.name, &mut self.signature_service).await;
                if temp_vote.digest() != round_digest_pair.vote_digest {
                    // we already sent a vote for a different header to the authority for this round
                    // don't equivocate by sending a different vote for the same round
                    warn!(
                        "Authority {} submitted duplicate header for votes at round {}",
                        header.author, header.round
                    );
                    self.metrics
                        .votes_dropped_equivocation_protection
                        .with_label_values(&[&header.epoch.to_string(), header_source])
                        .inc();
                    return Ok(());
                }
            }
        }

        self.create_vote(header).await
    }

    #[instrument(level = "debug", skip_all)]
    async fn process_prev_votes(&mut self, header: &Header) -> DagResult<()> {
        // MASATODO
        debug!(
            "MASADEBUG {:?}.2: Processing {:?} prev votes started at header {}",
            header.round,
            header.prev_votes.len(),
            header.id
        );
        for vote in header.prev_votes.iter() {
            if let Err(e) = self.sanitize_vote(&vote).await {
                error!("Failed to sanitize vote: {}", e.to_string());
            }
            if let Err(e) = self.process_vote(vote.clone()).await {
                error!("Failed to process vote: {}", e.to_string());
            }
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    async fn create_vote(&mut self, header: &Header) -> DagResult<()> {
        // Make a vote and send it to proposer
        let vote = Vote::new(header, &self.name, &mut self.signature_service).await;
        debug!(
            "MASADEBUG {:?}.3: Created vote {vote:?} for {header} at round",
            header.round
        );
        let vote_digest = vote.digest();

        // Update the vote digest store with the vote we just sent.
        // We don't need to store the vote itself, since it can be reconstructed using the headers
        // that are stored in the header store. This strategy can be used to re-deliver votes to
        // ensure progress / liveness.
        self.vote_digest_store
            .write(
                header.author.clone(),
                RoundVoteDigestPair {
                    round: header.round,
                    vote_digest,
                },
            )
            .await;

        self.tx_proposer_vote
            .send((vote, header.round, header.epoch))
            .await
            .map_err(|_| DagError::ShuttingDown)?;

        Ok(())
    }

    #[async_recursion]
    #[instrument(level = "debug", skip_all, fields(vote_digest = ?vote.digest()))]
    async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
        debug!(
            "MASADEBUG {:?}.5: Processing Vote {:?} for header {:?}",
            vote.round + 1, vote, vote.id
        );
    
        if let Some(header) = self.header_store.read(vote.id).await? {
            // Add it to the votes' aggregator and try to make a new certificate.
            if let Some(certificate) = self
                .votes_aggregators
                .entry(vote.id)
                .or_insert_with(|| VotesAggregator::new())
                .append(vote.clone(), &self.committee, &header)?
            {
                debug!(
                    "MASADEBUG {:?}.6: Assembled certificate {:?} for header {}",
                    certificate.round() + 1,
                    certificate, vote.id,
                );

                self.metrics
                    .certificates_created
                    .with_label_values(&[&certificate.epoch().to_string()])
                    .inc();

                // Process the new certificate.
                match self.process_certificate(certificate).await {
                    Ok(()) => (),
                    result @ Err(DagError::ShuttingDown) => result?,
                    _ => panic!("Failed to process valid certificate"),
                }
            }
        }
        Ok(())
    }

    #[async_recursion]
    #[instrument(level = "debug", skip_all, fields(certificate_digest = ?certificate.digest()))]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!(
            "MASADEBUG {:?}.5: Processing Certificate {:?}",
            certificate.round() + 1,
            certificate
        );

        let certificate_source = if self.name.eq(&certificate.header.author) {
            "own"
        } else {
            "other"
        };
        self.highest_received_round = self.highest_received_round.max(certificate.round());
        self.metrics
            .highest_received_round
            .with_label_values(&[&certificate.epoch().to_string(), certificate_source])
            .set(self.highest_received_round as i64);

        // Ensure we have all the ancestors of this certificate yet (if we didn't already garbage collect them).
        // If we don't, the synchronizer will gather them and trigger re-processing of this certificate.
        if certificate.round() > self.gc_round + 1
            && !self.synchronizer.deliver_certificate(&certificate).await?
        {
            debug!(
                "Processing of {:?} suspended: missing ancestors",
                certificate
            );
            self.metrics
                .certificates_suspended
                .with_label_values(&[&certificate.epoch().to_string(), "missing_parents"])
                .inc();
            return Ok(());
        }

        // Store the certificate.
        self.certificate_store.write(certificate.clone())?;

        // Update metrics for processed certificates.
        self.highest_processed_round = self.highest_processed_round.max(certificate.round());
        self.metrics
            .highest_processed_round
            .with_label_values(&[&certificate.epoch().to_string(), certificate_source])
            .set(self.highest_processed_round as i64);
        self.metrics
            .certificates_processed
            .with_label_values(&[&certificate.epoch().to_string(), certificate_source])
            .inc();
        // Append the certificate to the aggregator of the
        // corresponding round.
        self.append_certificate_in_aggregator(certificate.clone())
            .await?;

        // Send it to the consensus layer.
        let id = certificate.header.id;
        if let Err(e) = self.tx_consensus.send(certificate).await {
            warn!(
                "Failed to deliver certificate {} to the consensus: {}",
                id, e
            );
        }
        Ok(())
    }

    async fn append_certificate_in_aggregator(
        &mut self,
        certificate: Certificate,
    ) -> DagResult<()> {
        // Check if we have enough certificates to enter a new dag round and propose a header.
        if let Some(parents) = self
            .certificates_aggregators
            .entry(certificate.round())
            .or_insert_with(|| Box::new(CertificatesAggregator::new()))
            .append(certificate.clone(), &self.committee)
        {
            debug!("Parents created: {:?}", parents.len());
            // Store header with parents
            let processing_headers = self.processing
                .entry(certificate.round() + 1)
                .or_default()
                .drain()
                .collect_vec();
            for digest in processing_headers {
                if let Some(header) = self.header_store.read(digest).await? {
                    let new_header = header.insert_parents(parents.clone());
                    self.header_store.write(digest.clone(), new_header).await
                }
            }

            let before = self.cancel_handlers.len();
            if certificate.round() > 0 {
                self.cancel_handlers
                    .retain(|k, _| *k >= certificate.round() - 1);
            }
            debug!(
                "Pruned {} messages from obsolete rounds.",
                before.saturating_sub(self.cancel_handlers.len())
            );
        }

        Ok(())
    }

    async fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        if header.epoch > self.committee.epoch() {
            self.try_update_committee().await;
        }
        ensure!(
            self.committee.epoch() == header.epoch,
            DagError::InvalidEpoch {
                expected: self.committee.epoch(),
                received: header.epoch
            }
        );
        ensure!(
            self.gc_round < header.round,
            DagError::TooOld(header.id.into(), header.round, self.gc_round)
        );

        // Verify the header's signature.
        header.verify(&self.committee, self.worker_cache.clone())?;

        // TODO [issue #672]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    async fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        if vote.epoch > self.committee.epoch() {
            self.try_update_committee().await;
        }

        // Verify the vote.
        vote.verify(&self.committee).map_err(DagError::from)
    }

    /// If a new committee is available, update our internal state.
    async fn try_update_committee(&mut self) {
        if self
            .rx_reconfigure
            .has_changed()
            .expect("Reconfigure channel dropped")
        {
            let message = self.rx_reconfigure.borrow().clone();
            if let ReconfigureNotification::NewEpoch(new_committee) = message {
                self.change_epoch(new_committee).await;
                // Mark the value as seen.
                let _ = self.rx_reconfigure.borrow_and_update();
            }
        }
    }

    /// Update the committee and cleanup internal state.
    async fn change_epoch(&mut self, committee: Committee) {
        // Cleanup internal state.
        let keys = self.vote_digest_store.iter(None).await.into_keys();
        if let Err(e) = self.vote_digest_store.remove_all(keys).await {
            error!("Error in change epoch when clearing vote store {}", e);
        }
        self.processing.clear();
        self.votes_aggregators.clear();
        self.certificates_aggregators.clear();
        self.cancel_handlers.clear();

        // Update the committee
        self.committee = committee;

        // Cleanup the synchronizer
        self.synchronizer.update_genesis(&self.committee);
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        info!("Core on node {} has started successfully.", self.name);
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header) => {
                            match self.sanitize_header(&header).await {
                                Ok(()) => self.process_header(&header).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header(&header).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,

                // Check whether the committee changed.
                result = self.rx_reconfigure.changed() => {
                    result.expect("Committee channel dropped");
                    let message = self.rx_reconfigure.borrow().clone();
                    match message {
                        ReconfigureNotification::NewEpoch(new_committee) => {
                            self.change_epoch(new_committee).await;
                        },
                        ReconfigureNotification::UpdateCommittee(new_committee) => {
                            // Update the committee.
                            self.committee = new_committee;
                        },
                        ReconfigureNotification::Shutdown => return
                    }
                    tracing::debug!("Committee updated to {}", self.committee);
                    Ok(())
                }

                // Check whether the consensus round has changed, to clean up structures
                Ok(()) = self.rx_consensus_round_updates.changed() => {
                    let round = *self.rx_consensus_round_updates.borrow();
                    if round > self.gc_depth {
                        let now = Instant::now();

                        let gc_round = round - self.gc_depth;
                        self.processing.retain(|k, _| k > &gc_round);
                        self.votes_aggregators.clear();
                        self.certificates_aggregators.retain(|k, _| k > &gc_round);
                        self.cancel_handlers.retain(|k, _| k > &gc_round);
                        self.gc_round = gc_round;

                        self.metrics
                            .gc_core_latency
                            .with_label_values(&[&self.committee.epoch.to_string()])
                            .observe(now.elapsed().as_secs_f64());
                    }

                    Ok(())
                }

            };
            match result {
                Ok(()) => (),
                Err(e @ DagError::ShuttingDown) => debug!("{e}"),
                Err(DagError::StoreError(e)) => {
                    error!("{e}");
                    panic!("Storage failure: killing node.");
                }
                Err(e @ DagError::TooOld(..) | e @ DagError::InvalidEpoch { .. }) => debug!("{e}"),
                Err(e) => warn!("{e}"),
            }

            self.metrics
                .core_cancel_handlers_total
                .with_label_values(&[&self.committee.epoch.to_string()])
                .set(self.cancel_handlers.len() as i64);
        }
    }
}
