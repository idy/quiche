// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! Experimental QUIC-aware CONNECT-UDP forwarding support.
//!
//! The wire contract is pinned to `draft-ietf-masque-quic-proxy-09`. This
//! module owns negotiation, Capsules, CID mappings and packet transforms, but
//! deliberately performs no socket or HTTP stream I/O.

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use crate::h3::Header;
use crate::h3::NameValue;
use crate::BufFactory;
use crate::Connection;
use crate::PathEvent;

mod capsule;
mod mapping;
mod negotiation;
mod packet;
mod transform;

#[cfg(test)]
mod tests;

use capsule::Capsule;
use capsule::Decoder;
use mapping::Mapping;

/// The Internet-Draft revision implemented by this module.
pub const DRAFT_VERSION: &str = "draft-ietf-masque-quic-proxy-09";

/// The HTTP/3 DATAGRAM stream error code.
pub const H3_DATAGRAM_ERROR: u64 = 0x33;

const H3_NO_ERROR: u64 = 0x100;
const MAX_PENDING_ACTIONS: usize = 128;
const MAX_PENDING_CONTROL_BYTES: usize = 64 * 1024;
const MAX_ACTIVE_MAPPINGS_HARD: usize = 1024;
const MAX_VCID_LEN: usize = 20;

/// A result returned by the QUIC-aware proxying API.
pub type Result<T> = std::result::Result<T, Error>;

/// An error returned by the QUIC-aware proxying API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// No output or action is currently available.
    Done,
    /// The output buffer cannot hold the next complete Capsule.
    BufferTooShort,
    /// A local configuration value is invalid.
    InvalidConfig,
    /// The association identifier is not known.
    UnknownAssociation,
    /// An application-assigned identifier is already present.
    DuplicateIdentifier,
    /// The operation is not valid in the current state.
    InvalidState,
    /// A configured resource bound was reached.
    Capacity,
    /// A cryptographic operation failed.
    Crypto,
    /// The peer violated the draft wire or state contract.
    ProtocolViolation,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// A packet transform negotiated for forwarded mode.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PacketTransform {
    /// Replace only the Destination Connection ID.
    Identity,
    /// Apply the draft design-team AES transform after CID replacement.
    ScrambleDt,
}

impl PacketTransform {
    fn wire_name(self) -> &'static str {
        match self {
            PacketTransform::Identity => "identity",
            PacketTransform::ScrambleDt => "scramble-dt",
        }
    }

    fn from_wire_name(value: &str) -> Option<Self> {
        match value {
            "identity" => Some(PacketTransform::Identity),
            "scramble-dt" => Some(PacketTransform::ScrambleDt),
            _ => None,
        }
    }
}

/// The ECN codepoint associated with an application-owned UDP datagram.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// Not ECN-capable transport.
    NotEct,
    /// ECN-capable transport codepoint zero.
    Ect0,
    /// ECN-capable transport codepoint one.
    Ect1,
    /// Congestion experienced.
    Ce,
}

/// The reason a packet was deliberately dropped.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DropReason {
    /// No active CID mapping matched the packet.
    UnknownCid,
    /// The CID conflicts with another mapping.
    ConflictingCid,
    /// The mapping has not completed its acknowledgement gate.
    PrematureMapping,
    /// The packet is empty or otherwise structurally invalid.
    InvalidPacket,
    /// The selected output path has not been validated.
    UnvalidatedPath,
    /// The transform cannot process this packet shape.
    UnsupportedTransformInput,
}

/// The independently negotiated forwarding and port-sharing modes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedMode {
    forwarding: Option<PacketTransform>,
    port_sharing: bool,
}

impl NegotiatedMode {
    fn new(forwarding: Option<PacketTransform>, port_sharing: bool) -> Self {
        Self {
            forwarding,
            port_sharing,
        }
    }

    /// Returns the selected forwarding transform, if forwarded mode is active.
    pub fn forwarding(&self) -> Option<PacketTransform> {
        self.forwarding
    }

    /// Returns whether target-facing port sharing was accepted.
    pub fn port_sharing(&self) -> bool {
        self.port_sharing
    }
}

/// Configuration shared by client or proxy endpoint state.
pub struct ForwardingConfig {
    transforms: Vec<PacketTransform>,
    port_sharing: bool,
    max_active_mappings: usize,
    registration_timeout: Duration,
    outer_keepalive_interval: Option<Duration>,
    preserve_ecn: bool,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            transforms: vec![
                PacketTransform::ScrambleDt,
                PacketTransform::Identity,
            ],
            port_sharing: false,
            max_active_mappings: 64,
            registration_timeout: Duration::from_secs(10),
            outer_keepalive_interval: None,
            preserve_ecn: true,
        }
    }
}

impl ForwardingConfig {
    /// Replaces the ordered transform preference list.
    pub fn set_transforms(
        &mut self, transforms: &[PacketTransform],
    ) -> Result<()> {
        let mut unique = Vec::new();
        for transform in transforms {
            if unique.contains(transform) {
                return Err(Error::InvalidConfig);
            }
            unique.push(*transform);
        }
        self.transforms = unique;
        Ok(())
    }

    /// Enables or disables target-facing port sharing.
    pub fn set_port_sharing(&mut self, enabled: bool) {
        self.port_sharing = enabled;
    }

    /// Sets the maximum active CID mappings per association.
    pub fn set_max_active_mappings(&mut self, value: usize) -> Result<()> {
        if value == 0 || value > MAX_ACTIVE_MAPPINGS_HARD {
            return Err(Error::InvalidConfig);
        }
        self.max_active_mappings = value;
        Ok(())
    }

    /// Sets the registration-exhaustion timeout.
    pub fn set_registration_timeout(&mut self, value: Duration) -> Result<()> {
        if !(Duration::from_secs(1)..=Duration::from_secs(300)).contains(&value) {
            return Err(Error::InvalidConfig);
        }
        self.registration_timeout = value;
        Ok(())
    }

    /// Sets the outer QUIC keepalive interval.
    pub fn set_outer_keepalive_interval(
        &mut self, value: Option<Duration>,
    ) -> Result<()> {
        if value == Some(Duration::ZERO) {
            return Err(Error::InvalidConfig);
        }
        self.outer_keepalive_interval = value;
        Ok(())
    }

    /// Enables or disables preservation of observed ECN codepoints.
    pub fn set_preserve_ecn(&mut self, enabled: bool) {
        self.preserve_ecn = enabled;
    }
}

/// A parsed request-side QUIC-aware proxying offer.
pub struct ForwardingOffer {
    forwarding: bool,
    transforms: Vec<PacketTransform>,
    port_sharing: bool,
    scramble_key: Option<[u8; 32]>,
}

impl ForwardingOffer {
    /// Parses an offer from CONNECT-UDP request headers.
    pub fn from_request_headers<T: NameValue>(
        headers: &[T],
    ) -> Result<Option<Self>> {
        negotiation::parse_request_headers(headers)
    }
}

/// An opaque application-assigned outer QUIC connection identifier.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct OuterConnectionId(u64);

impl OuterConnectionId {
    /// Creates an identifier from an application value.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the application value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// An opaque application-assigned CONNECT-UDP association identifier.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct AssociationId(u64);

impl AssociationId {
    /// Creates an identifier from an application value.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the application value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// An application-owned UDP path.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct ForwardingPath {
    /// The local socket address.
    pub local: SocketAddr,
    /// The peer socket address.
    pub peer: SocketAddr,
}

/// The disposition of one application-owned UDP datagram.
pub enum PacketAction {
    /// Pass the packet to the identified outer QUIC connection.
    OuterQuic {
        /// The outer connection.
        connection: OuterConnectionId,
    },
    /// Carry the packet in CONNECT-UDP Context ID zero.
    Tunnel {
        /// The CONNECT-UDP association.
        association: AssociationId,
    },
    /// Send the rewritten packet as a raw UDP datagram.
    SendRaw {
        /// The CONNECT-UDP association.
        association: AssociationId,
        /// The approved output path.
        path: ForwardingPath,
        /// The ECN codepoint to apply.
        ecn: EcnCodepoint,
    },
    /// Deliver the restored packet to the inner QUIC connection.
    DeliverInner {
        /// The CONNECT-UDP association.
        association: AssociationId,
    },
    /// Tunnel a target stateless reset in Context ID zero.
    TunnelStatelessReset {
        /// The CONNECT-UDP association.
        association: AssociationId,
    },
    /// Drop the packet without closing either QUIC connection.
    Drop(DropReason),
}

/// A protocol action that the embedding application must execute.
pub enum SessionAction {
    /// Encoded control bytes are ready for the request stream.
    WriteControl {
        /// The CONNECT-UDP association.
        association: AssociationId,
    },
    /// Reset the CONNECT-UDP request stream.
    ResetStream {
        /// The CONNECT-UDP association.
        association: AssociationId,
        /// The HTTP/3 application error code.
        code: u64,
    },
    /// Generate an ack-eliciting outer QUIC packet.
    KeepAliveRequired {
        /// The outer QUIC connection.
        connection: OuterConnectionId,
    },
    /// CID forwarding readiness or path ownership changed.
    MappingChanged {
        /// The CONNECT-UDP association.
        association: AssociationId,
    },
}

#[derive(Clone)]
struct Association {
    outer: OuterConnectionId,
    target_path: Option<ForwardingPath>,
    mode: NegotiatedMode,
    negotiated: bool,
    decoder: Decoder,
    control: VecDeque<ControlItem>,
    control_bytes: usize,
    tunnel_capacity: Option<usize>,
    source_ids: HashMap<Vec<u8>, Option<[u8; 16]>>,
    destination_ids: HashMap<Vec<u8>, Option<[u8; 16]>>,
    client_mappings: Vec<Mapping>,
    target_mappings: Vec<Mapping>,
    pending_client: HashSet<Vec<u8>>,
    pending_target: HashSet<Vec<u8>>,
    registrations: u64,
    max_registrations: u64,
    exhausted_since: Option<Instant>,
    send_key: Option<[u8; 32]>,
    receive_key: Option<[u8; 32]>,
}

#[derive(Clone)]
struct ControlItem {
    encoded: Vec<u8>,
    max_connection_ids: bool,
}

impl Association {
    fn new(
        outer: OuterConnectionId, target_path: Option<ForwardingPath>,
    ) -> Self {
        Self {
            outer,
            target_path,
            mode: NegotiatedMode::new(None, false),
            negotiated: false,
            decoder: Decoder::default(),
            control: VecDeque::new(),
            control_bytes: 0,
            tunnel_capacity: None,
            source_ids: HashMap::new(),
            destination_ids: HashMap::new(),
            client_mappings: Vec::new(),
            target_mappings: Vec::new(),
            pending_client: HashSet::new(),
            pending_target: HashSet::new(),
            registrations: 0,
            max_registrations: 2,
            exhausted_since: None,
            send_key: None,
            receive_key: None,
        }
    }

    fn queue(&mut self, capsule: Capsule) -> Result<bool> {
        let max_connection_ids = matches!(&capsule, Capsule::MaxConnectionIds(_));
        let encoded = capsule.encode()?;
        if self.control_bytes + encoded.len() > MAX_PENDING_CONTROL_BYTES {
            return Err(Error::Capacity);
        }
        let was_empty = self.control.is_empty();
        self.control_bytes += encoded.len();
        self.control.push_back(ControlItem {
            encoded,
            max_connection_ids,
        });
        Ok(was_empty)
    }

    fn poll_control(&mut self, out: &mut [u8]) -> Result<usize> {
        let Some(item) = self.control.front() else {
            return Err(Error::Done);
        };
        if out.len() < item.encoded.len() {
            return Err(Error::BufferTooShort);
        }
        let len = item.encoded.len();
        out[..len].copy_from_slice(&item.encoded);
        self.control.pop_front();
        self.control_bytes -= len;
        Ok(len)
    }

    fn register(&mut self, capsule: Capsule, client: bool) -> Result<bool> {
        if self.registrations >= self.max_registrations {
            self.exhausted_since.get_or_insert_with(Instant::now);
            return Err(Error::Capacity);
        }
        let pending_cid = match (&capsule, client) {
            (Capsule::RegisterClient { cid, .. }, true) |
            (Capsule::RegisterTarget { cid, .. }, false) => Some(cid.clone()),
            _ => None,
        };
        let write_control = self.queue(capsule)?;
        self.registrations += 1;
        if let Some(cid) = pending_cid {
            if client {
                self.pending_client.insert(cid);
            } else {
                self.pending_target.insert(cid);
            }
        }
        Ok(write_control)
    }

    fn forwarding_ready(&self) -> bool {
        self.mode.forwarding().is_some() &&
            self.client_mappings
                .iter()
                .any(|mapping| mapping.acknowledged) &&
            self.target_mappings
                .iter()
                .any(|mapping| mapping.acknowledged)
    }

    fn extension_active(&self) -> bool {
        self.mode.forwarding().is_some() || self.mode.port_sharing()
    }

    fn disable_extension(&mut self) {
        self.control.clear();
        self.control_bytes = 0;
        self.source_ids.clear();
        self.destination_ids.clear();
        self.client_mappings.clear();
        self.target_mappings.clear();
        self.pending_client.clear();
        self.pending_target.clear();
        self.exhausted_since = None;
        self.send_key = None;
        self.receive_key = None;
    }
}

/// Client-side QUIC-aware CONNECT-UDP state.
pub struct ClientEndpoint {
    config: ForwardingConfig,
    outer: OuterConnectionId,
    path: ForwardingPath,
    outer_cids: HashSet<Vec<u8>>,
    associations: HashMap<AssociationId, Association>,
    actions: VecDeque<SessionAction>,
    last_keepalive: Instant,
}

impl ClientEndpoint {
    /// Creates client endpoint state for one outer QUIC connection.
    pub fn new(
        config: ForwardingConfig, outer: OuterConnectionId, path: ForwardingPath,
    ) -> Result<Self> {
        if config.max_active_mappings == 0 {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            config,
            outer,
            path,
            outer_cids: HashSet::new(),
            associations: HashMap::new(),
            actions: VecDeque::new(),
            last_keepalive: Instant::now(),
        })
    }

    /// Adds a CONNECT-UDP association.
    pub fn open_association(&mut self, id: AssociationId) -> Result<()> {
        if self.associations.contains_key(&id) {
            return Err(Error::DuplicateIdentifier);
        }
        let mut association = Association::new(self.outer, None);
        if self
            .config
            .transforms
            .contains(&PacketTransform::ScrambleDt)
        {
            association.send_key = Some(random_key());
        }
        self.associations.insert(id, association);
        Ok(())
    }

    /// Records the maximum CONNECT-UDP payload capacity.
    pub fn set_tunnel_payload_capacity(
        &mut self, id: AssociationId, bytes: usize,
    ) -> Result<()> {
        if bytes < 1200 {
            return Err(Error::InvalidConfig);
        }
        self.association_mut(id)?.tunnel_capacity = Some(bytes);
        Ok(())
    }

    /// Appends extension request headers.
    pub fn append_request_headers(
        &self, id: AssociationId, headers: &mut Vec<Header>,
    ) -> Result<()> {
        let association = self.association(id)?;
        negotiation::append_request_headers(
            &self.config,
            association.send_key.as_ref(),
            headers,
        )
    }

    /// Consumes extension response headers.
    pub fn on_response_headers<T: NameValue>(
        &mut self, id: AssociationId, headers: &[T],
    ) -> Result<NegotiatedMode> {
        self.association(id)?;
        let parsed = negotiation::parse_response_headers(
            headers,
            &self.config.transforms,
            self.config.port_sharing,
        );
        let (mode, receive_key) = match parsed {
            Ok(value) => value,
            Err(Error::ProtocolViolation) => {
                self.push_action(SessionAction::ResetStream {
                    association: id,
                    code: H3_DATAGRAM_ERROR,
                })?;
                return Err(Error::ProtocolViolation);
            },
            Err(error) => return Err(error),
        };
        let association = self.association_mut(id)?;
        association.mode = mode;
        association.negotiated = true;
        association.receive_key = receive_key;
        if !association.extension_active() {
            association.disable_extension();
            self.actions
                .retain(|action| action_association(action) != Some(id));
        }
        Ok(mode)
    }

    /// Feeds request-stream DATA bytes into the Capsule decoder.
    pub fn receive_control(
        &mut self, id: AssociationId, input: &[u8],
    ) -> Result<usize> {
        let capsules = match self.association_mut(id)?.decoder.receive(input) {
            Ok(capsules) => capsules,
            Err(Error::ProtocolViolation) => {
                self.push_action(SessionAction::ResetStream {
                    association: id,
                    code: H3_DATAGRAM_ERROR,
                })?;
                return Err(Error::ProtocolViolation);
            },
            Err(error) => return Err(error),
        };
        let mut association = self
            .associations
            .remove(&id)
            .ok_or(Error::UnknownAssociation)?;
        let handled = capsules.into_iter().try_for_each(|capsule| {
            self.handle_client_capsule(id, &mut association, capsule)
        });
        self.associations.insert(id, association);
        if let Err(error) = handled {
            if matches!(error, Error::ProtocolViolation | Error::Capacity) {
                self.push_action(SessionAction::ResetStream {
                    association: id,
                    code: H3_DATAGRAM_ERROR,
                })?;
                return Err(Error::ProtocolViolation);
            }
            return Err(error);
        }
        Ok(input.len())
    }

    /// Validates the Capsule decoder when the request stream reaches FIN.
    pub fn finish_control(&mut self, id: AssociationId) -> Result<()> {
        if self.association(id)?.decoder.finish().is_err() {
            self.push_action(SessionAction::ResetStream {
                association: id,
                code: H3_DATAGRAM_ERROR,
            })?;
            return Err(Error::ProtocolViolation);
        }
        Ok(())
    }

    /// Drains the next complete encoded Capsule.
    pub fn poll_control(
        &mut self, id: AssociationId, out: &mut [u8],
    ) -> Result<usize> {
        self.association_mut(id)?.poll_control(out)
    }

    /// Returns the next application action.
    pub fn poll_action(&mut self) -> Option<SessionAction> {
        self.actions.pop_front()
    }

    /// Synchronizes the complete outer source CID snapshot.
    pub fn sync_outer_connection_ids<F: BufFactory>(
        &mut self, connection: &Connection<F>,
    ) -> Result<()> {
        self.outer_cids = connection
            .source_ids_metadata()
            .map(|metadata| metadata.connection_id().as_ref().to_vec())
            .collect();
        Ok(())
    }

    /// Synchronizes inner source and destination CID snapshots.
    pub fn sync_inner_connection_ids<F: BufFactory>(
        &mut self, id: AssociationId, connection: &Connection<F>,
    ) -> Result<()> {
        let association = self.association(id)?;
        if association.negotiated && !association.extension_active() {
            return Ok(());
        }

        let sources = connection
            .source_ids_metadata()
            .map(|metadata| {
                (
                    metadata.connection_id().as_ref().to_vec(),
                    metadata.reset_token().map(u128::to_be_bytes),
                )
            })
            .collect::<HashMap<_, _>>();
        let destinations = connection
            .destination_ids_metadata()
            .map(|metadata| {
                (
                    metadata.connection_id().as_ref().to_vec(),
                    metadata.reset_token().map(u128::to_be_bytes),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut association = self.association(id)?.clone();
        let was_ready = association.forwarding_ready();
        let result = sync_snapshots(&mut association, &sources, &destinations);
        let write_control = result.as_ref().is_ok_and(|changed| *changed);
        let is_ready = association.forwarding_ready();
        result?;
        let previous_actions = self.actions.len();
        if write_control {
            self.push_action(SessionAction::WriteControl { association: id })?;
        }
        if was_ready != is_ready {
            if let Err(error) = self
                .push_action(SessionAction::MappingChanged { association: id })
            {
                self.actions.truncate(previous_actions);
                return Err(error);
            }
        }
        self.associations.insert(id, association);
        Ok(())
    }

    /// Returns whether inner output is blocked on a client CID acknowledgement.
    pub fn inner_send_blocked(&self, id: AssociationId) -> Result<bool> {
        let association = self.association(id)?;
        Ok(!association.pending_client.is_empty() ||
            association.exhausted_since.is_some())
    }

    /// Updates client state from an outer QUIC path event.
    pub fn on_outer_path_event(&mut self, event: &PathEvent) -> Result<()> {
        match event {
            PathEvent::Validated(local, peer) |
            PathEvent::PeerMigrated(local, peer) => {
                let migrated =
                    self.path.local != *local || self.path.peer != *peer;
                self.path = ForwardingPath {
                    local: *local,
                    peer: *peer,
                };
                if migrated {
                    let ids =
                        self.associations.keys().copied().collect::<Vec<_>>();
                    for id in ids {
                        let association = self.association_mut(id)?;
                        association.client_mappings.clear();
                        association.target_mappings.clear();
                        association.pending_client.clear();
                        association.pending_target.clear();
                        association.source_ids.clear();
                        association.destination_ids.clear();
                        association.exhausted_since = None;
                        association.control.clear();
                        association.control_bytes = 0;
                        self.actions.retain(|action| {
                            !matches!(
                                action,
                                SessionAction::WriteControl { association }
                                    if *association == id
                            )
                        });
                        self.push_action(SessionAction::MappingChanged {
                            association: id,
                        })?;
                    }
                }
            },
            _ => (),
        }
        Ok(())
    }

    /// Updates client state from an inner QUIC path event.
    pub fn on_inner_path_event(
        &mut self, id: AssociationId, event: &PathEvent,
    ) -> Result<()> {
        self.association(id)?;
        if matches!(event, PathEvent::PeerMigrated(..) | PathEvent::Closed(..)) {
            self.push_action(SessionAction::MappingChanged { association: id })?;
        }
        Ok(())
    }

    /// Returns the next session timer duration.
    pub fn timeout(&self) -> Option<Duration> {
        endpoint_timeout(
            &self.config,
            self.last_keepalive,
            self.associations.values(),
        )
    }

    /// Processes expired registration and keepalive timers.
    pub fn on_timeout(&mut self) {
        let now = Instant::now();
        let expired = self
            .associations
            .iter()
            .filter_map(|(id, association)| {
                association
                    .exhausted_since
                    .filter(|started| {
                        now.duration_since(*started) >=
                            self.config.registration_timeout
                    })
                    .map(|_| *id)
            })
            .collect::<Vec<_>>();
        for id in expired {
            let reset_pending = self.actions.iter().any(|action| {
                matches!(
                    action,
                    SessionAction::ResetStream { association, .. }
                        if *association == id
                )
            });
            if reset_pending ||
                self.push_action(SessionAction::ResetStream {
                    association: id,
                    code: H3_NO_ERROR,
                })
                .is_ok()
            {
                if let Ok(association) = self.association_mut(id) {
                    association.exhausted_since = None;
                }
            }
        }
        if let Some(interval) = self.config.outer_keepalive_interval {
            if now.duration_since(self.last_keepalive) >= interval {
                let keepalive_pending = self.actions.iter().any(|action| {
                    matches!(
                        action,
                        SessionAction::KeepAliveRequired { connection }
                            if *connection == self.outer
                    )
                });
                if keepalive_pending ||
                    self.push_action(SessionAction::KeepAliveRequired {
                        connection: self.outer,
                    })
                    .is_ok()
                {
                    self.last_keepalive = now;
                }
            }
        }
    }

    /// Closes one association and removes all of its state.
    pub fn close_association(&mut self, id: AssociationId) {
        self.associations.remove(&id);
        self.actions
            .retain(|action| action_association(action) != Some(id));
    }

    /// Closes all client endpoint state.
    pub fn close(&mut self) {
        self.associations.clear();
        self.actions.clear();
        self.outer_cids.clear();
    }

    /// Routes an inner packet toward the proxy.
    pub fn route_inner_to_proxy(
        &mut self, id: AssociationId, ecn: EcnCodepoint, packet: &mut Vec<u8>,
    ) -> Result<PacketAction> {
        if packet.is_empty() {
            return Ok(PacketAction::Drop(DropReason::InvalidPacket));
        }
        let association = self.association(id)?;
        if association.tunnel_capacity.is_none() {
            return Err(Error::InvalidState);
        }
        if packet::is_long(packet)? || association.mode.forwarding().is_none() {
            return Ok(PacketAction::Tunnel { association: id });
        }
        let Some(mapping) = association.target_mappings.iter().find(|mapping| {
            mapping.acknowledged &&
                mapping::packet_cid_matches(packet, &mapping.cid)
        }) else {
            return Ok(PacketAction::Tunnel { association: id });
        };
        if let Err(error) = packet::rewrite(
            packet,
            mapping.cid.len(),
            &mapping.vcid,
            association.mode.forwarding(),
            association.send_key.as_ref(),
            false,
        ) {
            return match error {
                Error::ProtocolViolation =>
                    Ok(PacketAction::Drop(DropReason::UnsupportedTransformInput)),
                error => Err(error),
            };
        }
        Ok(PacketAction::SendRaw {
            association: id,
            path: self.path,
            ecn: self.output_ecn(ecn),
        })
    }

    /// Routes a packet received on the client-proxy UDP path.
    pub fn route_from_network(
        &mut self, path: ForwardingPath, _ecn: EcnCodepoint, packet: &mut Vec<u8>,
    ) -> Result<PacketAction> {
        if packet.is_empty() {
            return Ok(PacketAction::Drop(DropReason::InvalidPacket));
        }
        if packet::is_long(packet)? {
            return Ok(PacketAction::OuterQuic {
                connection: self.outer,
            });
        }
        let outer_match = self
            .outer_cids
            .iter()
            .any(|cid| mapping::packet_cid_matches(packet, cid));
        if path != self.path {
            if outer_match {
                return Ok(PacketAction::OuterQuic {
                    connection: self.outer,
                });
            }
            return Ok(PacketAction::Drop(DropReason::UnvalidatedPath));
        }
        let mut matched = None;
        for (id, association) in &self.associations {
            if association.mode.forwarding().is_none() {
                continue;
            }
            if let Some(mapping) =
                association.client_mappings.iter().find(|mapping| {
                    mapping.acknowledged &&
                        mapping::packet_cid_matches(packet, &mapping.vcid)
                })
            {
                if matched.is_some() {
                    return Ok(PacketAction::Drop(DropReason::ConflictingCid));
                }
                matched = Some((*id, association, mapping));
            }
        }
        if outer_match && matched.is_some() {
            return Ok(PacketAction::Drop(DropReason::ConflictingCid));
        }
        if outer_match {
            return Ok(PacketAction::OuterQuic {
                connection: self.outer,
            });
        }
        if let Some((id, association, mapping)) = matched {
            if let Err(error) = packet::rewrite(
                packet,
                mapping.vcid.len(),
                &mapping.cid,
                association.mode.forwarding(),
                association.receive_key.as_ref(),
                true,
            ) {
                return match error {
                    Error::ProtocolViolation => Ok(PacketAction::Drop(
                        DropReason::UnsupportedTransformInput,
                    )),
                    error => Err(error),
                };
            }
            return Ok(PacketAction::DeliverInner { association: id });
        }
        Ok(PacketAction::Drop(DropReason::UnknownCid))
    }

    fn handle_client_capsule(
        &mut self, id: AssociationId, association: &mut Association,
        capsule: Capsule,
    ) -> Result<()> {
        let was_ready = association.forwarding_ready();
        match capsule {
            Capsule::AckClient { cid, vcid } => {
                if !association.pending_client.remove(&cid) ||
                    match association.mode.forwarding() {
                        Some(_) =>
                            vcid.len() < cid.len() || vcid.len() > MAX_VCID_LEN,
                        None => !vcid.is_empty(),
                    }
                {
                    return Err(Error::ProtocolViolation);
                }
                let reset_token =
                    association.source_ids.get(&cid).copied().flatten();
                association
                    .client_mappings
                    .retain(|mapping| mapping.cid != cid);
                association.client_mappings.push(Mapping {
                    cid: cid.clone(),
                    vcid: vcid.clone(),
                    reset_token,
                    acknowledged: true,
                });
                if association.mode.forwarding().is_some() {
                    let notify = association.queue(Capsule::AckClientVcid {
                        cid,
                        vcid,
                        reset_token,
                    })?;
                    if notify {
                        self.push_action(SessionAction::WriteControl {
                            association: id,
                        })?;
                    }
                }
            },

            Capsule::AckTarget {
                cid,
                vcid,
                reset_token,
            } => {
                if !association.pending_target.remove(&cid) ||
                    match association.mode.forwarding() {
                        Some(_) => vcid.len() > MAX_VCID_LEN,
                        None => !vcid.is_empty() || reset_token.is_some(),
                    }
                {
                    return Err(Error::ProtocolViolation);
                }
                association
                    .target_mappings
                    .retain(|mapping| mapping.cid != cid);
                association.target_mappings.push(Mapping {
                    cid,
                    vcid,
                    reset_token,
                    acknowledged: true,
                });
            },

            Capsule::RejectClient { reason, cid } => {
                if reason > capsule::CONFLICT_REASON ||
                    !association.pending_client.remove(&cid)
                {
                    return Err(Error::ProtocolViolation);
                }
                self.push_action(SessionAction::ResetStream {
                    association: id,
                    code: H3_DATAGRAM_ERROR,
                })?;
            },

            Capsule::RejectTarget { reason, cid } => {
                if reason > capsule::CONFLICT_REASON ||
                    !association.pending_target.remove(&cid)
                {
                    return Err(Error::ProtocolViolation);
                }
                self.push_action(SessionAction::ResetStream {
                    association: id,
                    code: H3_DATAGRAM_ERROR,
                })?;
            },

            Capsule::MaxConnectionIds(value) => {
                if value < 3 || value <= association.max_registrations {
                    return Err(Error::ProtocolViolation);
                }
                association.max_registrations = value;
                association.exhausted_since = None;
            },

            _ => return Err(Error::ProtocolViolation),
        }
        if was_ready != association.forwarding_ready() {
            self.push_action(SessionAction::MappingChanged { association: id })?;
        }
        Ok(())
    }

    fn association(&self, id: AssociationId) -> Result<&Association> {
        self.associations.get(&id).ok_or(Error::UnknownAssociation)
    }

    fn association_mut(&mut self, id: AssociationId) -> Result<&mut Association> {
        self.associations
            .get_mut(&id)
            .ok_or(Error::UnknownAssociation)
    }

    fn push_action(&mut self, action: SessionAction) -> Result<()> {
        push_bounded_action(&mut self.actions, action)
    }

    fn output_ecn(&self, ecn: EcnCodepoint) -> EcnCodepoint {
        if self.config.preserve_ecn {
            ecn
        } else {
            EcnCodepoint::NotEct
        }
    }
}

struct OuterState {
    path: ForwardingPath,
    validated: bool,
    cids: HashSet<Vec<u8>>,
}

/// Proxy-side state shared across outer QUIC connections and associations.
pub struct ProxyEndpoint {
    config: ForwardingConfig,
    outers: HashMap<OuterConnectionId, OuterState>,
    associations: HashMap<AssociationId, Association>,
    actions: VecDeque<SessionAction>,
    last_keepalive: Instant,
}

impl ProxyEndpoint {
    /// Creates proxy endpoint state.
    pub fn new(config: ForwardingConfig) -> Result<Self> {
        if config.max_active_mappings == 0 {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            config,
            outers: HashMap::new(),
            associations: HashMap::new(),
            actions: VecDeque::new(),
            last_keepalive: Instant::now(),
        })
    }

    /// Attaches an outer QUIC connection and its validated path.
    pub fn attach_outer(
        &mut self, id: OuterConnectionId, path: ForwardingPath,
    ) -> Result<()> {
        if self.outers.contains_key(&id) {
            return Err(Error::DuplicateIdentifier);
        }
        self.outers.insert(id, OuterState {
            path,
            validated: true,
            cids: HashSet::new(),
        });
        Ok(())
    }

    /// Accepts a parsed request offer and appends extension response headers.
    pub fn accept(
        &mut self, id: AssociationId, outer: OuterConnectionId,
        target_path: ForwardingPath, proxy_status_identity: &str,
        offer: ForwardingOffer, response_headers: &mut Vec<Header>,
    ) -> Result<NegotiatedMode> {
        if self.associations.contains_key(&id) {
            return Err(Error::DuplicateIdentifier);
        }
        if !self.outers.contains_key(&outer) {
            return Err(Error::InvalidState);
        }
        let transform = offer
            .transforms
            .iter()
            .copied()
            .find(|transform| {
                self.config.transforms.contains(transform) &&
                    (*transform != PacketTransform::ScrambleDt ||
                        offer.scramble_key.is_some())
            })
            .filter(|_| offer.forwarding);
        let mode = NegotiatedMode::new(
            transform,
            self.config.port_sharing && offer.port_sharing,
        );
        if (mode.forwarding().is_some() || mode.port_sharing()) &&
            self.actions.len() >= MAX_PENDING_ACTIONS
        {
            return Err(Error::Capacity);
        }
        let send_key =
            (transform == Some(PacketTransform::ScrambleDt)).then(random_key);
        negotiation::append_response_headers(
            mode,
            send_key.as_ref(),
            proxy_status_identity,
            target_path,
            response_headers,
        )?;

        let mut association = Association::new(outer, Some(target_path));
        association.mode = mode;
        association.negotiated = true;
        association.send_key = send_key;
        association.receive_key = offer.scramble_key;
        if !association.extension_active() {
            association.disable_extension();
        }
        let notify = if association.extension_active() {
            let notify = association.queue(Capsule::MaxConnectionIds(
                MAX_ACTIVE_MAPPINGS_HARD as u64,
            ))?;
            association.max_registrations = MAX_ACTIVE_MAPPINGS_HARD as u64;
            notify
        } else {
            false
        };
        self.associations.insert(id, association);
        if notify {
            self.push_action(SessionAction::WriteControl { association: id })?;
        }
        Ok(mode)
    }

    /// Records the maximum CONNECT-UDP payload capacity.
    pub fn set_tunnel_payload_capacity(
        &mut self, id: AssociationId, bytes: usize,
    ) -> Result<()> {
        if bytes < 1200 {
            return Err(Error::InvalidConfig);
        }
        self.association_mut(id)?.tunnel_capacity = Some(bytes);
        Ok(())
    }

    /// Feeds request-stream DATA bytes into the Capsule decoder.
    pub fn receive_control(
        &mut self, id: AssociationId, input: &[u8],
    ) -> Result<usize> {
        let capsules = match self.association_mut(id)?.decoder.receive(input) {
            Ok(capsules) => capsules,
            Err(Error::ProtocolViolation) => {
                self.push_action(SessionAction::ResetStream {
                    association: id,
                    code: H3_DATAGRAM_ERROR,
                })?;
                return Err(Error::ProtocolViolation);
            },
            Err(error) => return Err(error),
        };
        let mut association = self
            .associations
            .remove(&id)
            .ok_or(Error::UnknownAssociation)?;
        let handled = capsules.into_iter().try_for_each(|capsule| {
            self.handle_proxy_capsule(id, &mut association, capsule)
        });
        self.associations.insert(id, association);
        if let Err(error) = handled {
            if matches!(error, Error::ProtocolViolation | Error::Capacity) {
                self.push_action(SessionAction::ResetStream {
                    association: id,
                    code: H3_DATAGRAM_ERROR,
                })?;
                return Err(Error::ProtocolViolation);
            }
            return Err(error);
        }
        Ok(input.len())
    }

    /// Validates the Capsule decoder when the request stream reaches FIN.
    pub fn finish_control(&mut self, id: AssociationId) -> Result<()> {
        if self.association_mut(id)?.decoder.finish().is_err() {
            self.push_action(SessionAction::ResetStream {
                association: id,
                code: H3_DATAGRAM_ERROR,
            })?;
            return Err(Error::ProtocolViolation);
        }
        Ok(())
    }

    /// Drains the next complete encoded Capsule.
    pub fn poll_control(
        &mut self, id: AssociationId, out: &mut [u8],
    ) -> Result<usize> {
        self.association_mut(id)?.poll_control(out)
    }

    /// Returns the next application action.
    pub fn poll_action(&mut self) -> Option<SessionAction> {
        self.actions.pop_front()
    }

    /// Synchronizes the source CIDs of an outer QUIC connection.
    pub fn sync_outer_connection_ids<F: BufFactory>(
        &mut self, id: OuterConnectionId, connection: &Connection<F>,
    ) -> Result<()> {
        let outer = self.outers.get_mut(&id).ok_or(Error::InvalidState)?;
        outer.cids = connection
            .source_ids_metadata()
            .map(|metadata| metadata.connection_id().as_ref().to_vec())
            .collect();
        Ok(())
    }

    /// Updates proxy state from an outer QUIC path event.
    pub fn on_outer_path_event(
        &mut self, id: OuterConnectionId, event: &PathEvent,
    ) -> Result<()> {
        let outer = self.outers.get_mut(&id).ok_or(Error::InvalidState)?;
        match event {
            PathEvent::New(local, peer) => {
                outer.path = ForwardingPath {
                    local: *local,
                    peer: *peer,
                };
                outer.validated = false;
            },
            PathEvent::Validated(local, peer) => {
                outer.path = ForwardingPath {
                    local: *local,
                    peer: *peer,
                };
                outer.validated = true;
            },
            PathEvent::PeerMigrated(local, peer) => {
                outer.path = ForwardingPath {
                    local: *local,
                    peer: *peer,
                };
                outer.validated = true;
                let ids = self
                    .associations
                    .iter()
                    .filter_map(|(association, state)| {
                        (state.outer == id).then_some(*association)
                    })
                    .collect::<Vec<_>>();
                for association_id in ids {
                    let association = self.association_mut(association_id)?;
                    association.client_mappings.clear();
                    association.target_mappings.clear();
                    association.control.retain(|item| item.max_connection_ids);
                    association.control_bytes = association
                        .control
                        .iter()
                        .map(|item| item.encoded.len())
                        .sum();
                    let write_control = !association.control.is_empty();
                    self.actions.retain(|action| {
                        !matches!(
                        action,
                        SessionAction::WriteControl { association }
                            if *association == association_id
                        )
                    });
                    if write_control {
                        self.push_action(SessionAction::WriteControl {
                            association: association_id,
                        })?;
                    }
                    self.push_action(SessionAction::MappingChanged {
                        association: association_id,
                    })?;
                }
            },
            PathEvent::FailedValidation(..) | PathEvent::Closed(..) => {
                outer.validated = false;
            },
            PathEvent::ReusedSourceConnectionId(..) => (),
        }
        Ok(())
    }

    /// Returns the next session timer duration.
    pub fn timeout(&self) -> Option<Duration> {
        endpoint_timeout(
            &self.config,
            self.last_keepalive,
            self.associations.values(),
        )
    }

    /// Processes expired registration and keepalive timers.
    pub fn on_timeout(&mut self) {
        let now = Instant::now();
        if let Some(interval) = self.config.outer_keepalive_interval {
            if now.duration_since(self.last_keepalive) >= interval {
                let ids = self.outers.keys().copied().collect::<Vec<_>>();
                let mut queued_all = true;
                for connection in ids {
                    let keepalive_pending = self.actions.iter().any(|action| {
                        matches!(
                            action,
                            SessionAction::KeepAliveRequired {
                                connection: pending,
                            } if *pending == connection
                        )
                    });
                    if !keepalive_pending &&
                        self.push_action(SessionAction::KeepAliveRequired {
                            connection,
                        })
                        .is_err()
                    {
                        queued_all = false;
                    }
                }
                if queued_all {
                    self.last_keepalive = now;
                }
            }
        }
    }

    /// Closes one association and removes all of its maps and secrets.
    pub fn close_association(&mut self, id: AssociationId) {
        self.associations.remove(&id);
        self.actions
            .retain(|action| action_association(action) != Some(id));
    }

    /// Detaches an outer connection and all of its associations.
    pub fn detach_outer(&mut self, id: OuterConnectionId) {
        self.outers.remove(&id);
        let associations = self
            .associations
            .iter()
            .filter_map(|(association, state)| {
                (state.outer == id).then_some(*association)
            })
            .collect::<Vec<_>>();
        for association in associations {
            self.close_association(association);
        }
        self.actions.retain(|action| {
            !matches!(
                action,
                SessionAction::KeepAliveRequired { connection }
                    if *connection == id
            )
        });
    }

    /// Closes all proxy endpoint state.
    pub fn close(&mut self) {
        self.associations.clear();
        self.outers.clear();
        self.actions.clear();
    }

    /// Routes a datagram received from a client-facing socket.
    pub fn route_from_client(
        &mut self, path: ForwardingPath, ecn: EcnCodepoint, packet: &mut Vec<u8>,
    ) -> Result<PacketAction> {
        if packet.is_empty() {
            return Ok(PacketAction::Drop(DropReason::InvalidPacket));
        }
        let long_dcid = match packet::long_dcid(packet) {
            Ok(dcid) => dcid,
            Err(_) => return Ok(PacketAction::Drop(DropReason::InvalidPacket)),
        };
        if let Some(dcid) = long_dcid {
            let mut matched = self.outers.iter().filter_map(|(id, outer)| {
                (outer.path == path &&
                    outer.cids.iter().any(|cid| cid.as_slice() == dcid))
                .then_some(*id)
            });
            let Some(connection) = matched.next() else {
                return Ok(PacketAction::Drop(DropReason::UnknownCid));
            };
            if matched.next().is_some() {
                return Ok(PacketAction::Drop(DropReason::ConflictingCid));
            }
            return Ok(PacketAction::OuterQuic { connection });
        }

        let mut outer_match = None;
        for (outer_id, outer) in &self.outers {
            if outer.path == path &&
                outer
                    .cids
                    .iter()
                    .any(|cid| mapping::packet_cid_matches(packet, cid))
            {
                if outer_match.is_some() {
                    return Ok(PacketAction::Drop(DropReason::ConflictingCid));
                }
                outer_match = Some(*outer_id);
            }
        }

        let mut forwarded_match = None;
        for (id, association) in &self.associations {
            let outer = self
                .outers
                .get(&association.outer)
                .ok_or(Error::InvalidState)?;
            if outer.path != path || association.mode.forwarding().is_none() {
                continue;
            }
            if let Some(mapping) =
                association.target_mappings.iter().find(|mapping| {
                    mapping.acknowledged &&
                        mapping::packet_cid_matches(packet, &mapping.vcid)
                })
            {
                if forwarded_match.is_some() {
                    return Ok(PacketAction::Drop(DropReason::ConflictingCid));
                }
                forwarded_match = Some((*id, association, mapping));
            }
        }
        if outer_match.is_some() && forwarded_match.is_some() {
            return Ok(PacketAction::Drop(DropReason::ConflictingCid));
        }
        if let Some(connection) = outer_match {
            return Ok(PacketAction::OuterQuic { connection });
        }
        if let Some((id, association, mapping)) = forwarded_match {
            let target_path =
                association.target_path.ok_or(Error::InvalidState)?;
            if let Err(error) = packet::rewrite(
                packet,
                mapping.vcid.len(),
                &mapping.cid,
                association.mode.forwarding(),
                association.receive_key.as_ref(),
                true,
            ) {
                return match error {
                    Error::ProtocolViolation => Ok(PacketAction::Drop(
                        DropReason::UnsupportedTransformInput,
                    )),
                    error => Err(error),
                };
            }
            return Ok(PacketAction::SendRaw {
                association: id,
                path: target_path,
                ecn: self.output_ecn(ecn),
            });
        }
        Ok(PacketAction::Drop(DropReason::UnknownCid))
    }

    /// Routes a datagram received from a target-facing socket.
    pub fn route_from_target(
        &mut self, path: ForwardingPath, ecn: EcnCodepoint, packet: &mut Vec<u8>,
    ) -> Result<PacketAction> {
        if packet.is_empty() {
            return Ok(PacketAction::Drop(DropReason::InvalidPacket));
        }

        let mut ordinary = self.associations.iter().filter_map(|(id, state)| {
            (state.target_path == Some(path) &&
                state.negotiated &&
                !state.extension_active())
            .then_some((*id, state))
        });
        if let Some((id, association)) = ordinary.next() {
            if ordinary.next().is_some() {
                return Ok(PacketAction::Drop(DropReason::ConflictingCid));
            }
            if association.tunnel_capacity.is_none() {
                return Err(Error::InvalidState);
            }
            return Ok(PacketAction::Tunnel { association: id });
        }

        let long_dcid = match packet::long_dcid(packet) {
            Ok(dcid) => dcid,
            Err(_) => return Ok(PacketAction::Drop(DropReason::InvalidPacket)),
        };
        if let Some(dcid) = long_dcid {
            for (id, association) in &self.associations {
                if association.target_path == Some(path) &&
                    association
                        .client_mappings
                        .iter()
                        .any(|mapping| mapping.cid == dcid)
                {
                    if association.tunnel_capacity.is_none() {
                        return Err(Error::InvalidState);
                    }
                    return Ok(PacketAction::Tunnel { association: *id });
                }
            }
            return Ok(PacketAction::Drop(DropReason::UnknownCid));
        }
        for (id, association) in &self.associations {
            if association.target_path != Some(path) {
                continue;
            }
            if association.tunnel_capacity.is_none() {
                return Err(Error::InvalidState);
            }
            if association.mode.forwarding().is_none() {
                if association.client_mappings.iter().any(|mapping| {
                    mapping.acknowledged &&
                        mapping::packet_cid_matches(packet, &mapping.cid)
                }) {
                    return Ok(PacketAction::Tunnel { association: *id });
                }
                continue;
            }
            if association.target_mappings.iter().any(|mapping| {
                mapping::stateless_reset_matches(
                    packet,
                    mapping.reset_token.as_ref(),
                )
            }) {
                return Ok(PacketAction::TunnelStatelessReset {
                    association: *id,
                });
            }
            if let Some(mapping) = association
                .client_mappings
                .iter()
                .find(|mapping| mapping::packet_cid_matches(packet, &mapping.cid))
            {
                if !mapping.acknowledged {
                    return Ok(PacketAction::Tunnel { association: *id });
                }
                let outer = self
                    .outers
                    .get(&association.outer)
                    .ok_or(Error::InvalidState)?;
                if !outer.validated {
                    return Ok(PacketAction::Drop(DropReason::UnvalidatedPath));
                }
                if let Err(error) = packet::rewrite(
                    packet,
                    mapping.cid.len(),
                    &mapping.vcid,
                    association.mode.forwarding(),
                    association.send_key.as_ref(),
                    false,
                ) {
                    return match error {
                        Error::ProtocolViolation => Ok(PacketAction::Drop(
                            DropReason::UnsupportedTransformInput,
                        )),
                        error => Err(error),
                    };
                }
                return Ok(PacketAction::SendRaw {
                    association: *id,
                    path: outer.path,
                    ecn: self.output_ecn(ecn),
                });
            }
        }
        Ok(PacketAction::Drop(DropReason::UnknownCid))
    }

    fn handle_proxy_capsule(
        &mut self, id: AssociationId, association: &mut Association,
        capsule: Capsule,
    ) -> Result<()> {
        match capsule {
            Capsule::RegisterClient { reason, cid } => {
                let previous_vcid_len = association
                    .client_mappings
                    .iter()
                    .find(|mapping| mapping.cid == cid)
                    .map(|mapping| mapping.vcid.len());
                if reason > capsule::CONFLICT_REASON ||
                    (reason != capsule::DEFAULT_REASON &&
                        previous_vcid_len.is_none()) ||
                    (reason != capsule::DEFAULT_REASON &&
                        association.mode.forwarding().is_none())
                {
                    return Err(Error::ProtocolViolation);
                }
                if association.registrations >= association.max_registrations {
                    return Err(Error::ProtocolViolation);
                }
                association.registrations += 1;
                if cid.len() < 8 {
                    self.queue_proxy_capsule(
                        id,
                        association,
                        Capsule::RejectClient {
                            reason: capsule::TOO_SHORT_REASON,
                            cid,
                        },
                    )?;
                    return Ok(());
                }
                let conflict = self.client_cid_conflicts(id, association, &cid);
                let replaces_existing = previous_vcid_len.is_some();
                if conflict ||
                    (!replaces_existing &&
                        association.client_mappings.len() >=
                            self.config.max_active_mappings)
                {
                    self.queue_proxy_capsule(
                        id,
                        association,
                        Capsule::RejectClient {
                            reason: capsule::CONFLICT_REASON,
                            cid,
                        },
                    )?;
                    return Ok(());
                }
                let vcid = if association.mode.forwarding().is_some() {
                    let min_len = if reason == capsule::TOO_SHORT_REASON {
                        previous_vcid_len
                            .map(|length| length.saturating_add(1))
                            .unwrap_or(cid.len())
                    } else {
                        cid.len()
                    };
                    let generated = mapping::generate_vcid_at_least(
                        &cid,
                        min_len,
                        |candidate| self.vcid_conflicts(association, candidate),
                    );
                    match generated {
                        Ok(vcid) => vcid,
                        Err(Error::Capacity) => {
                            self.queue_proxy_capsule(
                                id,
                                association,
                                Capsule::RejectClient {
                                    reason: if min_len > MAX_VCID_LEN {
                                        capsule::TOO_SHORT_REASON
                                    } else {
                                        capsule::CONFLICT_REASON
                                    },
                                    cid,
                                },
                            )?;
                            return Ok(());
                        },
                        Err(error) => return Err(error),
                    }
                } else {
                    Vec::new()
                };
                association
                    .client_mappings
                    .retain(|mapping| mapping.cid != cid);
                association.client_mappings.push(Mapping {
                    cid: cid.clone(),
                    vcid: vcid.clone(),
                    reset_token: None,
                    acknowledged: association.mode.forwarding().is_none(),
                });
                self.queue_proxy_capsule(id, association, Capsule::AckClient {
                    cid,
                    vcid,
                })?;
            },

            Capsule::RegisterTarget {
                reason,
                cid,
                reset_token,
            } => {
                if reason != capsule::DEFAULT_REASON ||
                    association.registrations >= association.max_registrations
                {
                    return Err(Error::ProtocolViolation);
                }
                association.registrations += 1;
                let replaces_existing = association
                    .target_mappings
                    .iter()
                    .any(|mapping| mapping.cid == cid);
                if !replaces_existing &&
                    association.target_mappings.len() >=
                        self.config.max_active_mappings
                {
                    self.queue_proxy_capsule(
                        id,
                        association,
                        Capsule::RejectTarget {
                            reason: capsule::CONFLICT_REASON,
                            cid,
                        },
                    )?;
                    return Ok(());
                }
                let vcid = if association.mode.forwarding().is_some() {
                    let generated = mapping::generate_vcid(&cid, |candidate| {
                        self.vcid_conflicts(association, candidate)
                    });
                    match generated {
                        Ok(vcid) => vcid,
                        Err(Error::Capacity) => {
                            self.queue_proxy_capsule(
                                id,
                                association,
                                Capsule::RejectTarget {
                                    reason: capsule::CONFLICT_REASON,
                                    cid,
                                },
                            )?;
                            return Ok(());
                        },
                        Err(error) => return Err(error),
                    }
                } else {
                    Vec::new()
                };
                association
                    .target_mappings
                    .retain(|mapping| mapping.cid != cid);
                association.target_mappings.push(Mapping {
                    cid: cid.clone(),
                    vcid: vcid.clone(),
                    reset_token,
                    acknowledged: true,
                });
                self.queue_proxy_capsule(id, association, Capsule::AckTarget {
                    cid,
                    vcid,
                    reset_token: None,
                })?;
            },

            Capsule::AckClientVcid {
                cid,
                vcid,
                reset_token,
            } => {
                let Some(mapping) = association
                    .client_mappings
                    .iter_mut()
                    .find(|mapping| mapping.cid == cid && mapping.vcid == vcid)
                else {
                    return Err(Error::ProtocolViolation);
                };
                if mapping.acknowledged {
                    return Err(Error::ProtocolViolation);
                }
                mapping.acknowledged = true;
                mapping.reset_token = reset_token;
                self.push_action(SessionAction::MappingChanged {
                    association: id,
                })?;
            },

            Capsule::CloseClient { reason, cid } => {
                if reason != capsule::DEFAULT_REASON {
                    return Err(Error::ProtocolViolation);
                }
                association
                    .client_mappings
                    .retain(|mapping| mapping.cid != cid);
            },

            Capsule::CloseTarget { reason, cid } => {
                if reason != capsule::DEFAULT_REASON {
                    return Err(Error::ProtocolViolation);
                }
                association
                    .target_mappings
                    .retain(|mapping| mapping.cid != cid);
            },

            _ => return Err(Error::ProtocolViolation),
        }
        Ok(())
    }

    fn client_cid_conflicts(
        &self, id: AssociationId, current: &Association, cid: &[u8],
    ) -> bool {
        let Some(path) = current.target_path else {
            return true;
        };
        self.outers.get(&current.outer).is_some_and(|outer| {
            outer
                .cids
                .iter()
                .any(|outer_cid| mapping::conflicts(outer_cid, cid))
        }) || self.associations.iter().any(|(other_id, association)| {
            *other_id != id &&
                association.target_path == Some(path) &&
                association
                    .client_mappings
                    .iter()
                    .any(|mapping| mapping::conflicts(&mapping.cid, cid))
        }) || current.client_mappings.iter().any(|mapping| {
            mapping.cid != cid && mapping::conflicts(&mapping.cid, cid)
        })
    }

    fn vcid_conflicts(&self, current: &Association, vcid: &[u8]) -> bool {
        self.outers.get(&current.outer).is_some_and(|state| {
            state.cids.iter().any(|cid| mapping::conflicts(cid, vcid))
        }) || self.associations.values().any(|association| {
            association.outer == current.outer &&
                association
                    .client_mappings
                    .iter()
                    .chain(&association.target_mappings)
                    .any(|mapping| mapping::conflicts(&mapping.vcid, vcid))
        }) || current
            .client_mappings
            .iter()
            .chain(&current.target_mappings)
            .any(|mapping| mapping::conflicts(&mapping.vcid, vcid))
    }

    fn queue_proxy_capsule(
        &mut self, id: AssociationId, association: &mut Association,
        capsule: Capsule,
    ) -> Result<()> {
        if association.queue(capsule)? {
            self.push_action(SessionAction::WriteControl { association: id })?;
        }
        Ok(())
    }

    fn association_mut(&mut self, id: AssociationId) -> Result<&mut Association> {
        self.associations
            .get_mut(&id)
            .ok_or(Error::UnknownAssociation)
    }

    fn push_action(&mut self, action: SessionAction) -> Result<()> {
        push_bounded_action(&mut self.actions, action)
    }

    fn output_ecn(&self, ecn: EcnCodepoint) -> EcnCodepoint {
        if self.config.preserve_ecn {
            ecn
        } else {
            EcnCodepoint::NotEct
        }
    }
}

fn sync_snapshots(
    association: &mut Association, sources: &HashMap<Vec<u8>, Option<[u8; 16]>>,
    destinations: &HashMap<Vec<u8>, Option<[u8; 16]>>,
) -> Result<bool> {
    let mut changed = false;
    let retired_sources = association
        .source_ids
        .keys()
        .filter(|cid| !sources.contains_key(*cid))
        .cloned()
        .collect::<Vec<_>>();
    let retired_destinations = association
        .destination_ids
        .keys()
        .filter(|cid| !destinations.contains_key(*cid))
        .cloned()
        .collect::<Vec<_>>();

    for cid in retired_sources {
        changed |= association.queue(Capsule::CloseClient {
            reason: capsule::DEFAULT_REASON,
            cid: cid.clone(),
        })?;
        association.source_ids.remove(&cid);
        association
            .client_mappings
            .retain(|mapping| mapping.cid != cid);
        association.pending_client.remove(&cid);
    }
    for cid in retired_destinations {
        changed |= association.queue(Capsule::CloseTarget {
            reason: capsule::DEFAULT_REASON,
            cid: cid.clone(),
        })?;
        association.destination_ids.remove(&cid);
        association
            .target_mappings
            .retain(|mapping| mapping.cid != cid);
        association.pending_target.remove(&cid);
    }

    let mut exhausted = false;
    for (cid, reset_token) in sources {
        if let Some(current) = association.source_ids.get_mut(cid) {
            *current = *reset_token;
            continue;
        }
        if association.registrations >= association.max_registrations {
            exhausted = true;
            continue;
        }
        changed |= association.register(
            Capsule::RegisterClient {
                reason: capsule::DEFAULT_REASON,
                cid: cid.clone(),
            },
            true,
        )?;
        association.source_ids.insert(cid.clone(), *reset_token);
    }
    for (cid, reset_token) in destinations {
        if let Some(current) = association.destination_ids.get_mut(cid) {
            *current = *reset_token;
            continue;
        }
        if association.registrations >= association.max_registrations {
            exhausted = true;
            continue;
        }
        changed |= association.register(
            Capsule::RegisterTarget {
                reason: capsule::DEFAULT_REASON,
                cid: cid.clone(),
                reset_token: *reset_token,
            },
            false,
        )?;
        association
            .destination_ids
            .insert(cid.clone(), *reset_token);
    }
    if exhausted {
        association.exhausted_since.get_or_insert_with(Instant::now);
    } else {
        association.exhausted_since = None;
    }
    Ok(changed)
}

fn endpoint_timeout<'a>(
    config: &ForwardingConfig, last_keepalive: Instant,
    associations: impl Iterator<Item = &'a Association>,
) -> Option<Duration> {
    let now = Instant::now();
    let registration = associations
        .filter_map(|association| association.exhausted_since)
        .map(|started| {
            config
                .registration_timeout
                .saturating_sub(now.duration_since(started))
        })
        .min();
    let keepalive = config.outer_keepalive_interval.map(|interval| {
        interval.saturating_sub(now.duration_since(last_keepalive))
    });
    match (registration, keepalive) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn random_key() -> [u8; 32] {
    let mut key = [0; 32];
    super::super::rand::rand_bytes(&mut key);
    key
}

fn action_association(action: &SessionAction) -> Option<AssociationId> {
    match action {
        SessionAction::WriteControl { association } |
        SessionAction::ResetStream { association, .. } |
        SessionAction::MappingChanged { association } => Some(*association),
        SessionAction::KeepAliveRequired { .. } => None,
    }
}

fn push_bounded_action(
    actions: &mut VecDeque<SessionAction>, action: SessionAction,
) -> Result<()> {
    match &action {
        SessionAction::ResetStream { association, code } => {
            if let Some(SessionAction::ResetStream {
                code: queued_code, ..
            }) = actions.iter_mut().find(|queued| {
                matches!(
                    queued,
                    SessionAction::ResetStream {
                        association: queued_association,
                        ..
                    } if queued_association == association
                )
            }) {
                if *code == H3_DATAGRAM_ERROR {
                    *queued_code = *code;
                }
                return Ok(());
            }
        },

        SessionAction::WriteControl { association } => {
            if actions.iter().any(|queued| {
                matches!(
                    queued,
                    SessionAction::WriteControl {
                        association: queued_association,
                    } if queued_association == association
                )
            }) {
                return Ok(());
            }
        },

        SessionAction::KeepAliveRequired { connection } => {
            if actions.iter().any(|queued| {
                matches!(
                    queued,
                    SessionAction::KeepAliveRequired {
                        connection: queued_connection,
                    } if queued_connection == connection
                )
            }) {
                return Ok(());
            }
        },

        SessionAction::MappingChanged { association } => {
            if actions.iter().any(|queued| {
                matches!(
                    queued,
                    SessionAction::MappingChanged {
                        association: queued_association,
                    } if queued_association == association
                )
            }) {
                return Ok(());
            }
        },
    }

    if actions.len() >= MAX_PENDING_ACTIONS {
        if matches!(action, SessionAction::ResetStream { .. }) {
            let Some(position) = actions.iter().position(|queued| {
                !matches!(queued, SessionAction::ResetStream { .. })
            }) else {
                return Err(Error::Capacity);
            };
            actions.remove(position);
        } else {
            return Err(Error::Capacity);
        }
    }
    actions.push_back(action);
    Ok(())
}
