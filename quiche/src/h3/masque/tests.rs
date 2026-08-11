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

use super::action_association;
use super::capsule::Capsule;
use super::capsule::Decoder;
use super::mapping::Mapping;
use super::transform;
use super::Association;
use super::AssociationId;
use super::ClientEndpoint;
use super::EcnCodepoint;
use super::Error;
use super::ForwardingConfig;
use super::ForwardingOffer;
use super::ForwardingPath;
use super::OuterConnectionId;
use super::PacketAction;
use super::PacketTransform;
use super::ProxyEndpoint;
use crate::h3::NameValue;
use crate::test_utils::Pipe;
use std::cell::Cell;
use std::time::Duration;
use std::time::Instant;

#[test]
fn capsule_fragmentation_round_trip() {
    let capsule = Capsule::AckTarget {
        cid: vec![1, 2, 3, 4],
        vcid: vec![5, 6, 7, 8],
        reset_token: Some([9; 16]),
    };
    let encoded = capsule.encode().unwrap();
    let mut decoder = Decoder::default();
    let mut decoded = Vec::new();
    for byte in encoded {
        decoded.extend(decoder.receive(&[byte]).unwrap());
    }
    assert_eq!(decoded, vec![capsule]);
    assert_eq!(decoder.finish(), Ok(()));
}

#[test]
fn partial_capsule_at_fin_resets_both_roles() {
    let outer = OuterConnectionId::from_u64(35);
    let association = AssociationId::from_u64(36);
    let partial = [0x80];

    let mut client =
        ClientEndpoint::new(ForwardingConfig::default(), outer, path(7900, 8000))
            .unwrap();
    client.open_association(association).unwrap();
    assert_eq!(client.receive_control(association, &partial), Ok(1));
    assert_eq!(
        client.finish_control(association),
        Err(Error::ProtocolViolation)
    );
    assert!(matches!(
        client.poll_action(),
        Some(super::SessionAction::ResetStream {
            association: value,
            code: super::H3_DATAGRAM_ERROR,
        }) if value == association
    ));

    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy
        .associations
        .insert(association, Association::new(outer, None));
    assert_eq!(proxy.receive_control(association, &partial), Ok(1));
    assert_eq!(
        proxy.finish_control(association),
        Err(Error::ProtocolViolation)
    );
    assert!(matches!(
        proxy.poll_action(),
        Some(super::SessionAction::ResetStream {
            association: value,
            code: super::H3_DATAGRAM_ERROR,
        }) if value == association
    ));
}

#[test]
fn every_capsule_codepoint_round_trips() {
    let capsules = vec![
        Capsule::RegisterClient {
            reason: 0,
            cid: Vec::new(),
        },
        Capsule::RegisterClient {
            reason: 2,
            cid: vec![1; 255],
        },
        Capsule::RegisterTarget {
            reason: 0,
            cid: vec![2; 20],
            reset_token: Some([3; 16]),
        },
        Capsule::AckClient {
            cid: vec![4; 8],
            vcid: vec![5; 20],
        },
        Capsule::AckClientVcid {
            cid: vec![6; 8],
            vcid: vec![7; 8],
            reset_token: None,
        },
        Capsule::AckTarget {
            cid: vec![8; 8],
            vcid: vec![9; 8],
            reset_token: Some([10; 16]),
        },
        Capsule::RejectClient {
            reason: 1,
            cid: vec![11; 8],
        },
        Capsule::RejectTarget {
            reason: 2,
            cid: vec![12; 8],
        },
        Capsule::CloseClient {
            reason: 0,
            cid: vec![13; 8],
        },
        Capsule::CloseTarget {
            reason: 0,
            cid: vec![14; 8],
        },
        Capsule::MaxConnectionIds(1024),
    ];
    let mut decoder = Decoder::default();
    for capsule in capsules {
        assert_eq!(
            decoder.receive(&capsule.encode().unwrap()),
            Ok(vec![capsule])
        );
    }
}

#[test]
fn unknown_capsule_is_streamed_without_allocation() {
    let mut encoded = vec![0x21, 0x80, 0x00, 0x40, 0x00];
    encoded.extend(std::iter::repeat_n(0xaa, 16_384));
    let mut decoder = Decoder::default();
    assert!(decoder.receive(&encoded).unwrap().is_empty());
    assert_eq!(decoder.finish(), Ok(()));
}

#[test]
fn scramble_matches_draft_vector_and_inverts() {
    let key: [u8; 32] =
        hex("f13a915f96fb8919d9d8655488ffea5778cac8cffbc27cd38c173bcbad955cff")
            .try_into()
            .unwrap();
    let mut packet = hex(
        "500123456789abcdef0123456789abcdef012345671ba3bed7043a21632023048def32f4f8f260c290490413d24ea6",
    );
    let original = packet.clone();
    transform::scramble(&mut packet, 20, &key, false).unwrap();
    assert_eq!(
        packet,
        hex(
            "320123456789abcdef0123456789abcdef012345678ebe6906e16ec5fc90a02c0109994c3fed03f9d5d88c5f408bb6",
        )
    );
    transform::scramble(&mut packet, 20, &key, true).unwrap();
    assert_eq!(packet, original);
}

#[test]
fn negotiate_and_forward_in_both_directions() {
    let outer = OuterConnectionId::from_u64(7);
    let association = AssociationId::from_u64(11);
    let client_path = path(4100, 4200);
    let proxy_path = path(4200, 4100);
    let target_path = path(4300, 4400);

    let mut client_config = ForwardingConfig::default();
    client_config.set_port_sharing(true);
    let mut proxy_config = ForwardingConfig::default();
    proxy_config.set_port_sharing(true);

    let mut client =
        ClientEndpoint::new(client_config, outer, client_path).unwrap();
    client.open_association(association).unwrap();
    client
        .set_tunnel_payload_capacity(association, 1200)
        .unwrap();

    let mut request_headers = Vec::new();
    client
        .append_request_headers(association, &mut request_headers)
        .unwrap();
    let offer = ForwardingOffer::from_request_headers(&request_headers)
        .unwrap()
        .unwrap();

    let mut proxy = ProxyEndpoint::new(proxy_config).unwrap();
    proxy.attach_outer(outer, proxy_path).unwrap();
    let mut response_headers = Vec::new();
    let proxy_mode = proxy
        .accept(
            association,
            outer,
            target_path,
            "proxy.example",
            offer,
            &mut response_headers,
        )
        .unwrap();
    proxy
        .set_tunnel_payload_capacity(association, 1200)
        .unwrap();
    assert_eq!(proxy_mode.forwarding(), Some(PacketTransform::ScrambleDt));
    assert!(proxy_mode.port_sharing());

    assert_eq!(header_value(&response_headers, b"capsule-protocol"), "?1");
    let forwarding = header_value(&response_headers, b"proxy-quic-forwarding");
    assert!(forwarding.contains("scramble-dt"));
    assert!(!forwarding.contains("\"scramble\""));
    let proxy_status = header_value(&response_headers, b"proxy-status");
    assert!(proxy_status.contains("proxy.example"));
    assert!(proxy_status.contains("127.0.0.1:4400"));

    let client_mode = client
        .on_response_headers(association, &response_headers)
        .unwrap();
    assert_eq!(client_mode, proxy_mode);

    let outer_pipe = Pipe::new("cubic").unwrap();
    client
        .sync_outer_connection_ids(&outer_pipe.client)
        .unwrap();
    proxy
        .sync_outer_connection_ids(outer, &outer_pipe.server)
        .unwrap();
    let mut outer_to_client =
        short_packet(outer_pipe.client.source_id().as_ref());
    assert!(matches!(
        client
            .route_from_network(
                client_path,
                EcnCodepoint::NotEct,
                &mut outer_to_client,
            )
            .unwrap(),
        PacketAction::OuterQuic { connection } if connection == outer
    ));
    let mut outer_to_proxy = short_packet(outer_pipe.server.source_id().as_ref());
    assert!(matches!(
        proxy
            .route_from_client(
                proxy_path,
                EcnCodepoint::NotEct,
                &mut outer_to_proxy,
            )
            .unwrap(),
        PacketAction::OuterQuic { connection } if connection == outer
    ));

    // Receive the proxy's increasing MAX_CONNECTION_IDS before registering
    // the complete initial source/destination CID snapshot.
    transfer_proxy_control(&mut proxy, &mut client, association);
    let pipe = Pipe::new("cubic").unwrap();
    let source_cid = pipe.client.source_id().as_ref().to_vec();
    let destination_cid = pipe.client.destination_id().as_ref().to_vec();
    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();
    assert!(client.inner_send_blocked(association).unwrap());

    transfer_client_control(&mut client, &mut proxy, association);
    transfer_proxy_control(&mut proxy, &mut client, association);
    transfer_client_control(&mut client, &mut proxy, association);
    assert!(!client.inner_send_blocked(association).unwrap());

    let mut long = vec![0xc0; 1200];
    assert!(matches!(
        client
            .route_inner_to_proxy(association, EcnCodepoint::Ect0, &mut long)
            .unwrap(),
        PacketAction::Tunnel { association: value } if value == association
    ));

    let mut client_to_target = short_packet(&destination_cid);
    let original = client_to_target.clone();
    assert!(matches!(
        client
            .route_inner_to_proxy(
                association,
                EcnCodepoint::Ect0,
                &mut client_to_target,
            )
            .unwrap(),
        PacketAction::SendRaw {
            association: value,
            path: value_path,
            ecn: EcnCodepoint::Ect0,
        } if value == association && value_path == client_path
    ));
    assert_ne!(client_to_target, original);
    assert!(matches!(
        proxy
            .route_from_client(
                proxy_path,
                EcnCodepoint::Ect0,
                &mut client_to_target,
            )
            .unwrap(),
        PacketAction::SendRaw {
            association: value,
            path: value_path,
            ecn: EcnCodepoint::Ect0,
        } if value == association && value_path == target_path
    ));
    assert_eq!(client_to_target, original);

    let mut target_to_client = short_packet(&source_cid);
    let original = target_to_client.clone();
    assert!(matches!(
        proxy
            .route_from_target(
                target_path,
                EcnCodepoint::Ce,
                &mut target_to_client,
            )
            .unwrap(),
        PacketAction::SendRaw {
            association: value,
            path: value_path,
            ecn: EcnCodepoint::Ce,
        } if value == association && value_path == proxy_path
    ));
    assert_ne!(target_to_client, original);
    assert!(matches!(
        client
            .route_from_network(
                client_path,
                EcnCodepoint::Ce,
                &mut target_to_client,
            )
            .unwrap(),
        PacketAction::DeliverInner { association: value }
            if value == association
    ));
    assert_eq!(target_to_client, original);

    let mut target_long = long_packet(&source_cid);
    assert!(matches!(
        proxy
            .route_from_target(
                target_path,
                EcnCodepoint::NotEct,
                &mut target_long,
            )
            .unwrap(),
        PacketAction::Tunnel { association: value } if value == association
    ));
}

#[test]
fn packet_rewrite_supports_shorter_and_longer_connection_ids() {
    for (old, new) in [
        (vec![1; 12], vec![2; 8]),
        (vec![1; 8], vec![2; 8]),
        (vec![1; 8], vec![2; 20]),
    ] {
        let mut packet = short_packet(&old);
        let original_tail = packet[1 + old.len()..].to_vec();
        super::packet::rewrite(
            &mut packet,
            old.len(),
            &new,
            Some(PacketTransform::Identity),
            None,
            false,
        )
        .unwrap();
        assert_eq!(&packet[1..1 + new.len()], new.as_slice());
        assert_eq!(&packet[1 + new.len()..], original_tail.as_slice());
    }

    let old = vec![3; 8];
    let new = vec![4; 12];
    let mut undersized = short_packet(&old);
    undersized.truncate(1 + old.len() + 15);
    let original = undersized.clone();
    assert_eq!(
        super::packet::rewrite(
            &mut undersized,
            old.len(),
            &new,
            Some(PacketTransform::ScrambleDt),
            Some(&[5; 32]),
            false,
        ),
        Err(Error::ProtocolViolation)
    );
    assert_eq!(undersized, original);

    let mut missing_key = short_packet(&old);
    let original = missing_key.clone();
    assert_eq!(
        super::packet::rewrite(
            &mut missing_key,
            old.len(),
            &new,
            Some(PacketTransform::ScrambleDt),
            None,
            false,
        ),
        Err(Error::InvalidState)
    );
    assert_eq!(missing_key, original);
}

#[test]
fn invalid_max_connection_ids_resets_the_request() {
    let association = AssociationId::from_u64(3);
    let mut client = ClientEndpoint::new(
        ForwardingConfig::default(),
        OuterConnectionId::from_u64(2),
        path(4500, 4600),
    )
    .unwrap();
    client.open_association(association).unwrap();

    let encoded = Capsule::MaxConnectionIds(2).encode().unwrap();
    assert_eq!(
        client.receive_control(association, &encoded),
        Err(Error::ProtocolViolation)
    );
    assert!(matches!(
        client.poll_action(),
        Some(super::SessionAction::ResetStream {
            association: value,
            code: super::H3_DATAGRAM_ERROR,
        }) if value == association
    ));
}

#[test]
fn capsule_batch_state_is_atomic_on_error() {
    let outer = OuterConnectionId::from_u64(43);
    let association = AssociationId::from_u64(44);
    let mut client =
        ClientEndpoint::new(ForwardingConfig::default(), outer, path(8700, 8800))
            .unwrap();
    client.open_association(association).unwrap();

    let mut client_batch = Capsule::MaxConnectionIds(4).encode().unwrap();
    client_batch.extend(Capsule::MaxConnectionIds(3).encode().unwrap());
    assert_eq!(
        client.receive_control(association, &client_batch),
        Err(Error::ProtocolViolation)
    );
    assert_eq!(
        client
            .associations
            .get(&association)
            .unwrap()
            .max_registrations,
        2
    );

    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy
        .associations
        .insert(association, Association::new(outer, None));
    let mut proxy_batch = Capsule::RegisterClient {
        reason: super::capsule::DEFAULT_REASON,
        cid: vec![0xa1; 8],
    }
    .encode()
    .unwrap();
    proxy_batch.extend(Capsule::MaxConnectionIds(3).encode().unwrap());
    assert_eq!(
        proxy.receive_control(association, &proxy_batch),
        Err(Error::ProtocolViolation)
    );
    let state = proxy.associations.get(&association).unwrap();
    assert!(state.client_mappings.is_empty());
    assert!(state.control.is_empty());
    assert_eq!(state.registration_requests, 0);
    assert!(matches!(
        proxy.poll_action(),
        Some(super::SessionAction::ResetStream {
            association: value,
            code: super::H3_DATAGRAM_ERROR,
        }) if value == association
    ));
    assert!(proxy.poll_action().is_none());
}

#[test]
fn registration_limit_counts_requests_cumulatively() {
    let outer = OuterConnectionId::from_u64(45);
    let association = AssociationId::from_u64(46);
    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    let mut state = Association::new(outer, None);
    state.max_registrations = 3;
    proxy.associations.insert(association, state);

    let rejected = Capsule::RegisterClient {
        reason: super::capsule::DEFAULT_REASON,
        cid: vec![0xa2; 7],
    }
    .encode()
    .unwrap();
    proxy.receive_control(association, &rejected).unwrap();

    let target_cid = vec![0xa3; 8];
    let target = Capsule::RegisterTarget {
        reason: super::capsule::DEFAULT_REASON,
        cid: target_cid.clone(),
        reset_token: None,
    }
    .encode()
    .unwrap();
    proxy.receive_control(association, &target).unwrap();
    let close = Capsule::CloseTarget {
        reason: super::capsule::DEFAULT_REASON,
        cid: target_cid,
    }
    .encode()
    .unwrap();
    proxy.receive_control(association, &close).unwrap();

    let final_allowed = Capsule::RegisterTarget {
        reason: super::capsule::DEFAULT_REASON,
        cid: vec![0xa4; 8],
        reset_token: None,
    }
    .encode()
    .unwrap();
    proxy.receive_control(association, &final_allowed).unwrap();
    let over_limit = Capsule::RegisterTarget {
        reason: super::capsule::DEFAULT_REASON,
        cid: vec![0xa5; 8],
        reset_token: None,
    }
    .encode()
    .unwrap();
    assert_eq!(
        proxy.receive_control(association, &over_limit),
        Err(Error::ProtocolViolation)
    );
    assert_eq!(
        proxy
            .associations
            .get(&association)
            .unwrap()
            .registration_requests,
        3
    );
}

#[test]
fn capsule_support_gates_both_negotiated_capabilities() {
    let mut disabled = ForwardingConfig::default();
    disabled.set_transforms(&[]).unwrap();
    let client = ClientEndpoint::new(
        disabled,
        OuterConnectionId::from_u64(24),
        path(6900, 7000),
    )
    .unwrap();
    let association = AssociationId::from_u64(25);
    let mut client = client;
    client.open_association(association).unwrap();
    let mut request = Vec::new();
    client
        .append_request_headers(association, &mut request)
        .unwrap();
    assert!(ForwardingOffer::from_request_headers(&request)
        .unwrap()
        .is_none());

    let response = vec![
        crate::h3::Header::new(
            b"proxy-quic-forwarding",
            b"?1;transform=\"identity\"",
        ),
        crate::h3::Header::new(b"proxy-quic-port-sharing", b"?1"),
    ];
    let mode = client.on_response_headers(association, &response).unwrap();
    assert_eq!(mode.forwarding(), None);
    assert!(!mode.port_sharing());

    let response = vec![
        crate::h3::Header::new(b"capsule-protocol", b"?1"),
        crate::h3::Header::new(b"proxy-quic-forwarding", b"?0"),
        crate::h3::Header::new(b"proxy-quic-port-sharing", b"?1"),
    ];
    let mode = client.on_response_headers(association, &response).unwrap();
    assert_eq!(mode.forwarding(), None);
    assert!(!mode.port_sharing());
}

#[test]
fn declined_extension_stops_all_cid_control() {
    let outer = OuterConnectionId::from_u64(31);
    let association = AssociationId::from_u64(32);
    let mut client_config = ForwardingConfig::default();
    client_config
        .set_transforms(&[PacketTransform::Identity])
        .unwrap();
    let mut client =
        ClientEndpoint::new(client_config, outer, path(7500, 7600)).unwrap();
    client.open_association(association).unwrap();

    let pipe = Pipe::new("cubic").unwrap();
    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();
    assert!(client
        .actions
        .iter()
        .any(|action| action_association(action) == Some(association)));

    let response = vec![
        crate::h3::Header::new(b"capsule-protocol", b"?1"),
        crate::h3::Header::new(b"proxy-quic-forwarding", b"?0"),
        crate::h3::Header::new(b"proxy-quic-port-sharing", b"?0"),
    ];
    let mode = client.on_response_headers(association, &response).unwrap();
    assert_eq!(mode.forwarding(), None);
    assert!(!mode.port_sharing());
    assert!(!client.inner_send_blocked(association).unwrap());
    assert!(!client
        .actions
        .iter()
        .any(|action| action_association(action) == Some(association)));

    let mut output = [0; 1024];
    assert_eq!(
        client.poll_control(association, &mut output),
        Err(Error::Done)
    );
    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();
    assert_eq!(
        client.poll_control(association, &mut output),
        Err(Error::Done)
    );

    let mut request = Vec::new();
    client
        .append_request_headers(association, &mut request)
        .unwrap();
    let offer = ForwardingOffer::from_request_headers(&request)
        .unwrap()
        .unwrap();
    let mut proxy_config = ForwardingConfig::default();
    proxy_config.set_transforms(&[]).unwrap();
    let mut proxy = ProxyEndpoint::new(proxy_config).unwrap();
    proxy.attach_outer(outer, path(7600, 7500)).unwrap();
    let mut response = Vec::new();
    let mode = proxy
        .accept(
            association,
            outer,
            path(7700, 7800),
            "proxy.example",
            offer,
            &mut response,
        )
        .unwrap();
    assert_eq!(mode.forwarding(), None);
    assert!(!mode.port_sharing());
    proxy
        .set_tunnel_payload_capacity(association, 1200)
        .unwrap();
    assert_eq!(
        proxy.poll_control(association, &mut output),
        Err(Error::Done)
    );
    assert!(proxy.poll_action().is_none());

    let mut ordinary_udp = vec![0xff, 0x01];
    assert!(matches!(
        proxy
            .route_from_target(
                path(7700, 7800),
                EcnCodepoint::NotEct,
                &mut ordinary_udp,
            )
            .unwrap(),
        PacketAction::Tunnel { association: value } if value == association
    ));
}

#[test]
fn port_sharing_without_forwarding_keeps_packets_tunnelled() {
    let outer = OuterConnectionId::from_u64(8);
    let association = AssociationId::from_u64(9);
    let client_path = path(5100, 5200);
    let proxy_path = path(5200, 5100);
    let target_path = path(5300, 5400);
    let mut client_config = ForwardingConfig::default();
    client_config.set_transforms(&[]).unwrap();
    client_config.set_port_sharing(true);
    let mut proxy_config = ForwardingConfig::default();
    proxy_config.set_port_sharing(true);

    let mut client =
        ClientEndpoint::new(client_config, outer, client_path).unwrap();
    client.open_association(association).unwrap();
    client
        .set_tunnel_payload_capacity(association, 1200)
        .unwrap();
    let mut request = Vec::new();
    client
        .append_request_headers(association, &mut request)
        .unwrap();
    let offer = ForwardingOffer::from_request_headers(&request)
        .unwrap()
        .unwrap();

    let mut proxy = ProxyEndpoint::new(proxy_config).unwrap();
    proxy.attach_outer(outer, proxy_path).unwrap();
    let mut response = Vec::new();
    let mode = proxy
        .accept(
            association,
            outer,
            target_path,
            "proxy.example",
            offer,
            &mut response,
        )
        .unwrap();
    proxy
        .set_tunnel_payload_capacity(association, 1200)
        .unwrap();
    assert_eq!(mode.forwarding(), None);
    assert!(mode.port_sharing());
    assert_eq!(
        client.on_response_headers(association, &response).unwrap(),
        mode
    );

    transfer_proxy_control(&mut proxy, &mut client, association);
    let pipe = Pipe::new("cubic").unwrap();
    let source_cid = pipe.client.source_id().as_ref().to_vec();
    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();
    transfer_client_control(&mut client, &mut proxy, association);
    transfer_proxy_control(&mut proxy, &mut client, association);

    let mut packet = short_packet(&source_cid);
    assert!(matches!(
        client
            .route_inner_to_proxy(
                association,
                EcnCodepoint::NotEct,
                &mut packet,
            )
            .unwrap(),
        PacketAction::Tunnel { association: value } if value == association
    ));
    assert!(matches!(
        proxy
            .route_from_target(
                target_path,
                EcnCodepoint::NotEct,
                &mut packet,
            )
            .unwrap(),
        PacketAction::Tunnel { association: value } if value == association
    ));
}

#[test]
fn malformed_known_capsule_queues_request_reset() {
    let association = AssociationId::from_u64(13);
    let mut client = ClientEndpoint::new(
        ForwardingConfig::default(),
        OuterConnectionId::from_u64(12),
        path(5500, 5600),
    )
    .unwrap();
    client.open_association(association).unwrap();

    let mut encoded = encode_varint(super::capsule::ACK_CLIENT_CID);
    encoded.extend(encode_varint(513));
    assert_eq!(
        client.receive_control(association, &encoded),
        Err(Error::ProtocolViolation)
    );
    assert!(matches!(
        client.poll_action(),
        Some(super::SessionAction::ResetStream {
            association: value,
            code: super::H3_DATAGRAM_ERROR,
        }) if value == association
    ));
}

#[test]
fn registration_exhaustion_retries_after_larger_limit() {
    let association = AssociationId::from_u64(15);
    let mut client = ClientEndpoint::new(
        ForwardingConfig::default(),
        OuterConnectionId::from_u64(14),
        path(5700, 5800),
    )
    .unwrap();
    client.open_association(association).unwrap();
    let mut pipe = Pipe::new("cubic").unwrap();
    pipe.handshake().unwrap();

    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();
    let mut output = [0; 1024];
    assert!(client.poll_control(association, &mut output).is_ok());
    assert!(client.poll_control(association, &mut output).is_ok());
    assert_eq!(
        client.poll_control(association, &mut output),
        Err(Error::Done)
    );

    let replacement = crate::ConnectionId::from_ref(&[0x6b; 16]);
    pipe.client
        .new_scid(&replacement, u128::from_be_bytes([0x7c; 16]), false)
        .unwrap();
    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();
    assert!(client.inner_send_blocked(association).unwrap());
    assert_eq!(
        client.poll_control(association, &mut output),
        Err(Error::Done)
    );

    let increased = Capsule::MaxConnectionIds(3).encode().unwrap();
    client.receive_control(association, &increased).unwrap();
    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();
    assert!(client.poll_control(association, &mut output).is_ok());
}

#[test]
fn ambiguous_outer_and_forwarded_cids_are_dropped() {
    let outer = OuterConnectionId::from_u64(16);
    let association = AssociationId::from_u64(17);
    let forwarding_path = path(5900, 6000);
    let mut client =
        ClientEndpoint::new(ForwardingConfig::default(), outer, forwarding_path)
            .unwrap();
    client.open_association(association).unwrap();
    let conflicting = vec![0x81; 8];
    client.outer_cids.insert(conflicting.clone());
    let state = client.associations.get_mut(&association).unwrap();
    state.mode =
        super::NegotiatedMode::new(Some(PacketTransform::Identity), false);
    state.client_mappings.push(Mapping {
        cid: vec![0x82; 8],
        vcid: conflicting.clone(),
        reset_token: None,
        acknowledged: true,
    });

    let mut packet = short_packet(&conflicting);
    assert!(matches!(
        client
            .route_from_network(
                forwarding_path,
                EcnCodepoint::NotEct,
                &mut packet,
            )
            .unwrap(),
        PacketAction::Drop(super::DropReason::ConflictingCid)
    ));
}

#[test]
fn long_header_demux_rejects_ambiguous_outer_connections() {
    let forwarding_path = path(6100, 6200);
    let alternate_path = path(6300, 6400);
    let first = OuterConnectionId::from_u64(18);
    let second = OuterConnectionId::from_u64(19);
    let cid = vec![0x83; 8];
    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy.attach_outer(first, forwarding_path).unwrap();
    proxy.attach_outer(second, alternate_path).unwrap();
    proxy
        .outers
        .get_mut(&first)
        .unwrap()
        .cids
        .insert(cid.clone());
    proxy
        .outers
        .get_mut(&second)
        .unwrap()
        .cids
        .insert(cid.clone());

    let mut packet = long_packet(&cid);
    assert!(matches!(
        proxy
            .route_from_client(
                forwarding_path,
                EcnCodepoint::NotEct,
                &mut packet,
            )
            .unwrap(),
        PacketAction::Drop(super::DropReason::ConflictingCid)
    ));
}

#[test]
fn known_outer_cids_reach_quic_from_a_new_path() {
    let outer = OuterConnectionId::from_u64(47);
    let association = AssociationId::from_u64(48);
    let old_path = path(8900, 9000);
    let new_path = path(9100, 9200);
    let outer_cid = vec![0xa6; 8];
    let forwarded_cid = vec![0xa7; 8];
    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy.attach_outer(outer, old_path).unwrap();
    proxy
        .outers
        .get_mut(&outer)
        .unwrap()
        .cids
        .insert(outer_cid.clone());

    for mut packet in [long_packet(&outer_cid), short_packet(&outer_cid)] {
        assert!(matches!(
            proxy
                .route_from_client(new_path, EcnCodepoint::NotEct, &mut packet)
                .unwrap(),
            PacketAction::OuterQuic { connection } if connection == outer
        ));
    }

    let mut state = Association::new(outer, Some(path(9300, 9400)));
    state.mode =
        super::NegotiatedMode::new(Some(PacketTransform::Identity), false);
    state.target_mappings.push(Mapping {
        cid: vec![0xa8; 8],
        vcid: forwarded_cid.clone(),
        reset_token: None,
        acknowledged: true,
    });
    proxy.associations.insert(association, state);
    let mut packet = short_packet(&forwarded_cid);
    assert!(matches!(
        proxy
            .route_from_client(new_path, EcnCodepoint::NotEct, &mut packet)
            .unwrap(),
        PacketAction::Drop(super::DropReason::UnknownCid)
    ));
}

#[test]
fn unacknowledged_target_packet_stays_tunnelled() {
    let outer = OuterConnectionId::from_u64(20);
    let association = AssociationId::from_u64(21);
    let proxy_path = path(6300, 6400);
    let target_path = path(6500, 6600);
    let cid = vec![0x84; 8];
    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy.attach_outer(outer, proxy_path).unwrap();
    let mut state = Association::new(outer, Some(target_path));
    state.mode =
        super::NegotiatedMode::new(Some(PacketTransform::Identity), false);
    state.tunnel_capacity = Some(1200);
    state.client_mappings.push(Mapping {
        cid: cid.clone(),
        vcid: vec![0x85; 8],
        reset_token: None,
        acknowledged: false,
    });
    proxy.associations.insert(association, state);

    let mut packet = short_packet(&cid);
    assert!(matches!(
        proxy
            .route_from_target(
                target_path,
                EcnCodepoint::NotEct,
                &mut packet,
            )
            .unwrap(),
        PacketAction::Tunnel { association: value } if value == association
    ));
}

#[test]
fn full_action_queue_prioritizes_registration_timeout_reset() {
    let association = AssociationId::from_u64(22);
    let mut config = ForwardingConfig::default();
    config
        .set_registration_timeout(Duration::from_secs(1))
        .unwrap();
    let mut client = ClientEndpoint::new(
        config,
        OuterConnectionId::from_u64(23),
        path(6700, 6800),
    )
    .unwrap();
    client.open_association(association).unwrap();
    client
        .associations
        .get_mut(&association)
        .unwrap()
        .exhausted_since = Some(Instant::now() - Duration::from_secs(2));
    for _ in 0..super::MAX_PENDING_ACTIONS {
        client
            .actions
            .push_back(super::SessionAction::MappingChanged { association });
    }

    client.on_timeout();
    assert!(client
        .associations
        .get(&association)
        .unwrap()
        .exhausted_since
        .is_none());
    assert_eq!(client.actions.len(), super::MAX_PENDING_ACTIONS);
    assert!(client.actions.iter().any(|action| {
        matches!(
            action,
            super::SessionAction::ResetStream {
                association: value,
                code: super::H3_NO_ERROR,
            } if *value == association
        )
    }));
}

#[test]
fn cid_snapshot_sync_is_atomic_when_actions_are_full() {
    let association = AssociationId::from_u64(41);
    let mut client = ClientEndpoint::new(
        ForwardingConfig::default(),
        OuterConnectionId::from_u64(42),
        path(8500, 8600),
    )
    .unwrap();
    client.open_association(association).unwrap();
    for value in 0..super::MAX_PENDING_ACTIONS as u64 {
        client
            .actions
            .push_back(super::SessionAction::KeepAliveRequired {
                connection: OuterConnectionId::from_u64(1000 + value),
            });
    }

    let pipe = Pipe::new("cubic").unwrap();
    assert_eq!(
        client.sync_inner_connection_ids(association, &pipe.client),
        Err(Error::Capacity)
    );
    let state = client.associations.get(&association).unwrap();
    assert!(state.source_ids.is_empty());
    assert!(state.destination_ids.is_empty());
    assert!(state.pending_client.is_empty());
    assert!(state.pending_target.is_empty());
    assert!(state.control.is_empty());
    assert_eq!(state.registration_requests, 0);
}

#[test]
fn active_migration_discards_stale_mapping_control() {
    let outer = OuterConnectionId::from_u64(26);
    let association = AssociationId::from_u64(27);
    let old_client_path = path(7100, 7200);
    let new_client_path = path(7300, 7400);
    let mut client =
        ClientEndpoint::new(ForwardingConfig::default(), outer, old_client_path)
            .unwrap();
    client.open_association(association).unwrap();
    let pipe = Pipe::new("cubic").unwrap();
    client
        .receive_control(
            association,
            &Capsule::MaxConnectionIds(4).encode().unwrap(),
        )
        .unwrap();
    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();

    client
        .on_outer_path_event(&crate::PathEvent::Validated(
            new_client_path.local,
            new_client_path.peer,
        ))
        .unwrap();
    assert_eq!(
        client
            .associations
            .get(&association)
            .unwrap()
            .registration_requests,
        2
    );
    let mut output = [0; 1024];
    assert_eq!(
        client.poll_control(association, &mut output),
        Err(Error::Done)
    );
    assert!(!client.actions.iter().any(|action| {
        matches!(
            action,
            super::SessionAction::WriteControl { association: value }
                if *value == association
        )
    }));

    client
        .sync_inner_connection_ids(association, &pipe.client)
        .unwrap();
    assert_eq!(
        client
            .associations
            .get(&association)
            .unwrap()
            .registration_requests,
        4
    );
    assert!(client.poll_control(association, &mut output).is_ok());
    assert!(client.poll_control(association, &mut output).is_ok());
    assert_eq!(
        client.poll_control(association, &mut output),
        Err(Error::Done)
    );
}

#[test]
fn configuration_and_control_resource_bounds_are_enforced() {
    let mut config = ForwardingConfig::default();
    assert_eq!(config.set_max_active_mappings(0), Err(Error::InvalidConfig));
    assert_eq!(
        config.set_max_active_mappings(super::MAX_ACTIVE_MAPPINGS_HARD + 1),
        Err(Error::InvalidConfig)
    );
    assert!(config
        .set_max_active_mappings(super::MAX_ACTIVE_MAPPINGS_HARD)
        .is_ok());
    assert_eq!(
        config.set_registration_timeout(Duration::from_millis(999)),
        Err(Error::InvalidConfig)
    );
    assert_eq!(
        config.set_registration_timeout(Duration::from_secs(301)),
        Err(Error::InvalidConfig)
    );
    assert_eq!(
        config.set_outer_keepalive_interval(Some(Duration::ZERO)),
        Err(Error::InvalidConfig)
    );

    let mut association = Association::new(OuterConnectionId::from_u64(28), None);
    let capsule = Capsule::RegisterClient {
        reason: 0,
        cid: vec![0x86; 255],
    };
    while association.queue(capsule.clone()).is_ok() {}
    assert!(association.control_bytes <= super::MAX_PENDING_CONTROL_BYTES);
    let items = association.control.len();
    let bytes = association.control_bytes;
    assert_eq!(association.queue(capsule), Err(Error::Capacity));
    assert_eq!(association.control.len(), items);
    assert_eq!(association.control_bytes, bytes);

    let mut output = [0; 1024];
    assert_eq!(
        association.poll_control(&mut output[..1]),
        Err(Error::BufferTooShort)
    );
    assert!(association.poll_control(&mut output).is_ok());
}

#[test]
fn cid_conflicts_and_collision_retry_limit_are_bounded() {
    assert!(super::mapping::conflicts(&[], &[1, 2]));
    assert!(super::mapping::conflicts(&[1, 2], &[1, 2, 3]));
    assert!(super::mapping::conflicts(&[1, 2, 3], &[1, 2]));
    assert!(!super::mapping::conflicts(&[1, 2], &[1, 3]));

    let attempts = Cell::new(0);
    assert_eq!(
        super::mapping::generate_vcid(&[1; 8], |_| {
            attempts.set(attempts.get() + 1);
            true
        }),
        Err(Error::Capacity)
    );
    assert_eq!(attempts.get(), 16);
}

#[test]
fn client_cid_reregistration_reasons_are_stateful() {
    let outer = OuterConnectionId::from_u64(37);
    let association = AssociationId::from_u64(38);
    let target_path = path(8100, 8200);
    let cid = vec![0x91; 8];

    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy.attach_outer(outer, path(8200, 8100)).unwrap();
    let mut state = Association::new(outer, Some(target_path));
    state.mode =
        super::NegotiatedMode::new(Some(PacketTransform::Identity), false);
    state.negotiated = true;
    proxy.associations.insert(association, state);
    let invalid = Capsule::RegisterClient {
        reason: super::capsule::TOO_SHORT_REASON,
        cid: cid.clone(),
    }
    .encode()
    .unwrap();
    assert_eq!(
        proxy.receive_control(association, &invalid),
        Err(Error::ProtocolViolation)
    );

    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy.attach_outer(outer, path(8200, 8100)).unwrap();
    let mut state = Association::new(outer, Some(target_path));
    state.mode =
        super::NegotiatedMode::new(Some(PacketTransform::Identity), false);
    state.negotiated = true;
    state.client_mappings.push(Mapping {
        cid: cid.clone(),
        vcid: vec![0x92; 8],
        reset_token: None,
        acknowledged: true,
    });
    proxy.associations.insert(association, state);
    let retry = Capsule::RegisterClient {
        reason: super::capsule::TOO_SHORT_REASON,
        cid: cid.clone(),
    }
    .encode()
    .unwrap();
    proxy.receive_control(association, &retry).unwrap();

    let mut encoded = [0; 1024];
    let written = proxy.poll_control(association, &mut encoded).unwrap();
    let mut decoder = Decoder::default();
    let decoded = decoder.receive(&encoded[..written]).unwrap();
    assert!(matches!(
        decoded.as_slice(),
        [Capsule::AckClient { cid: value, vcid }]
            if value == &cid && vcid.len() > 8
    ));
}

#[test]
fn tunnel_only_mode_rejects_forwarding_ack_fields() {
    let outer = OuterConnectionId::from_u64(39);
    let association = AssociationId::from_u64(40);
    let cid = vec![0x93; 8];
    let mut client =
        ClientEndpoint::new(ForwardingConfig::default(), outer, path(8300, 8400))
            .unwrap();
    client.open_association(association).unwrap();
    let state = client.associations.get_mut(&association).unwrap();
    state.mode = super::NegotiatedMode::new(None, true);
    state.negotiated = true;
    state.pending_target.insert(cid.clone());

    let invalid = Capsule::AckTarget {
        cid,
        vcid: vec![0x94; 8],
        reset_token: Some([0x95; 16]),
    }
    .encode()
    .unwrap();
    assert_eq!(
        client.receive_control(association, &invalid),
        Err(Error::ProtocolViolation)
    );
    assert!(client.actions.iter().any(|action| {
        matches!(
            action,
            super::SessionAction::ResetStream {
                association: value,
                code: super::H3_DATAGRAM_ERROR,
            } if *value == association
        )
    }));
}

#[test]
fn wrong_role_capsule_resets_proxy_request() {
    let association = AssociationId::from_u64(29);
    let outer = OuterConnectionId::from_u64(30);
    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy
        .associations
        .insert(association, Association::new(outer, None));
    for _ in 0..super::MAX_PENDING_ACTIONS {
        proxy
            .actions
            .push_back(super::SessionAction::MappingChanged { association });
    }
    let wrong_role = Capsule::AckTarget {
        cid: vec![1; 8],
        vcid: vec![2; 8],
        reset_token: None,
    }
    .encode()
    .unwrap();
    assert_eq!(
        proxy.receive_control(association, &wrong_role),
        Err(Error::ProtocolViolation)
    );
    assert_eq!(proxy.actions.len(), super::MAX_PENDING_ACTIONS);
    assert!(proxy.actions.iter().any(|action| {
        matches!(
            action,
            super::SessionAction::ResetStream {
                association: value,
                code: super::H3_DATAGRAM_ERROR,
            } if *value == association
        )
    }));
}

#[test]
fn stateless_reset_and_ecn_actions_follow_policy() {
    let outer = OuterConnectionId::from_u64(31);
    let association = AssociationId::from_u64(32);
    let proxy_path = path(7500, 7600);
    let target_path = path(7700, 7800);
    let reset_token = [0x87; 16];
    let mut proxy = ProxyEndpoint::new(ForwardingConfig::default()).unwrap();
    proxy.attach_outer(outer, proxy_path).unwrap();
    let mut proxy_state = Association::new(outer, Some(target_path));
    proxy_state.mode =
        super::NegotiatedMode::new(Some(PacketTransform::Identity), false);
    proxy_state.tunnel_capacity = Some(1200);
    proxy_state.target_mappings.push(Mapping {
        cid: vec![0x88; 8],
        vcid: vec![0x89; 8],
        reset_token: Some(reset_token),
        acknowledged: true,
    });
    proxy.associations.insert(association, proxy_state);
    let mut reset = vec![0x40; 21];
    reset[5..].copy_from_slice(&reset_token);
    assert!(matches!(
        proxy
            .route_from_target(target_path, EcnCodepoint::Ce, &mut reset)
            .unwrap(),
        PacketAction::TunnelStatelessReset { association: value }
            if value == association
    ));

    let mut config = ForwardingConfig::default();
    config.set_preserve_ecn(false);
    let mut client = ClientEndpoint::new(config, outer, proxy_path).unwrap();
    client.open_association(association).unwrap();
    let client_state = client.associations.get_mut(&association).unwrap();
    client_state.mode =
        super::NegotiatedMode::new(Some(PacketTransform::Identity), false);
    client_state.tunnel_capacity = Some(1200);
    client_state.target_mappings.push(Mapping {
        cid: vec![0x8a; 8],
        vcid: vec![0x8b; 8],
        reset_token: None,
        acknowledged: true,
    });
    let mut packet = short_packet(&[0x8a; 8]);
    assert!(matches!(
        client
            .route_inner_to_proxy(association, EcnCodepoint::Ce, &mut packet)
            .unwrap(),
        PacketAction::SendRaw {
            ecn: EcnCodepoint::NotEct,
            ..
        }
    ));
}

fn transfer_client_control(
    client: &mut ClientEndpoint, proxy: &mut ProxyEndpoint,
    association: AssociationId,
) {
    let mut output = [0; 1024];
    loop {
        match client.poll_control(association, &mut output) {
            Ok(written) => {
                proxy
                    .receive_control(association, &output[..written])
                    .unwrap();
            },
            Err(Error::Done) => break,
            Err(error) => panic!("unexpected client control error: {error}"),
        }
    }
}

fn transfer_proxy_control(
    proxy: &mut ProxyEndpoint, client: &mut ClientEndpoint,
    association: AssociationId,
) {
    let mut output = [0; 1024];
    loop {
        match proxy.poll_control(association, &mut output) {
            Ok(written) => {
                client
                    .receive_control(association, &output[..written])
                    .unwrap();
            },
            Err(Error::Done) => break,
            Err(error) => panic!("unexpected proxy control error: {error}"),
        }
    }
}

fn header_value<'a>(headers: &'a [crate::h3::Header], name: &[u8]) -> &'a str {
    let value = headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .unwrap()
        .value();
    std::str::from_utf8(value).unwrap()
}

fn path(local: u16, peer: u16) -> ForwardingPath {
    ForwardingPath {
        local: format!("127.0.0.1:{local}").parse().unwrap(),
        peer: format!("127.0.0.1:{peer}").parse().unwrap(),
    }
}

fn short_packet(cid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x40];
    packet.extend_from_slice(cid);
    packet.extend_from_slice(&[0xa5; 32]);
    packet
}

fn long_packet(dcid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xc0, 0, 0, 0, 1, dcid.len() as u8];
    packet.extend_from_slice(dcid);
    packet.push(0);
    packet.resize(1200, 0xa5);
    packet
}

fn encode_varint(value: u64) -> Vec<u8> {
    let mut encoded = vec![0; octets::varint_len(value)];
    octets::OctetsMut::with_slice(&mut encoded)
        .put_varint(value)
        .unwrap();
    encoded
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
