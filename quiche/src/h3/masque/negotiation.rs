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

use sfv::BareItem;
use sfv::Item;
use sfv::Parameters;
use sfv::Parser;
use sfv::SerializeValue;

use super::Error;
use super::ForwardingConfig;
use super::ForwardingOffer;
use super::ForwardingPath;
use super::NegotiatedMode;
use super::PacketTransform;
use super::Result;
use crate::h3::Header;
use crate::h3::NameValue;

const CAPSULE_PROTOCOL: &[u8] = b"capsule-protocol";
const FORWARDING: &[u8] = b"proxy-quic-forwarding";
const PORT_SHARING: &[u8] = b"proxy-quic-port-sharing";
const PROXY_STATUS: &[u8] = b"proxy-status";

pub(super) fn append_request_headers(
    config: &ForwardingConfig, send_key: Option<&[u8; 32]>,
    headers: &mut Vec<Header>,
) -> Result<()> {
    headers.push(Header::new(CAPSULE_PROTOCOL, b"?1"));

    let forwarding = !config.transforms.is_empty();
    let mut params = Parameters::new();
    if forwarding {
        let transforms = config
            .transforms
            .iter()
            .map(|transform| transform.wire_name())
            .collect::<Vec<_>>()
            .join(",");
        params.insert("accept-transform".into(), BareItem::String(transforms));

        if config.transforms.contains(&PacketTransform::ScrambleDt) {
            let key = send_key.ok_or(Error::InvalidState)?;
            params.insert("scramble-key".into(), BareItem::ByteSeq(key.to_vec()));
        }
    }

    let forwarding = Item::with_params(BareItem::Boolean(forwarding), params)
        .serialize_value()
        .map_err(|_| Error::InvalidConfig)?;
    headers.push(Header::new(FORWARDING, forwarding.as_bytes()));

    let port_sharing = Item::new(BareItem::Boolean(config.port_sharing))
        .serialize_value()
        .map_err(|_| Error::InvalidConfig)?;
    headers.push(Header::new(PORT_SHARING, port_sharing.as_bytes()));
    Ok(())
}

pub(super) fn parse_request_headers<T: NameValue>(
    headers: &[T],
) -> Result<Option<ForwardingOffer>> {
    if item_boolean(headers, CAPSULE_PROTOCOL)? != Some(true) {
        return Ok(None);
    }

    let port_sharing = item_boolean(headers, PORT_SHARING)?.unwrap_or(false);
    let Some(item) = find_item(headers, FORWARDING)? else {
        return if port_sharing {
            Ok(Some(ForwardingOffer {
                forwarding: false,
                transforms: Vec::new(),
                port_sharing,
                scramble_key: None,
            }))
        } else {
            Ok(None)
        };
    };

    let forwarding = item.bare_item.as_bool().ok_or(Error::ProtocolViolation)?;
    let transforms = if forwarding {
        match item
            .params
            .get("accept-transform")
            .and_then(BareItem::as_str)
        {
            Some(value) => parse_transforms(value),
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    let forwarding = forwarding && !transforms.is_empty();
    let scramble_key = item
        .params
        .get("scramble-key")
        .and_then(BareItem::as_byte_seq)
        .and_then(|value| value.as_slice().try_into().ok());

    if !forwarding && !port_sharing {
        return Ok(None);
    }

    Ok(Some(ForwardingOffer {
        forwarding,
        transforms,
        port_sharing,
        scramble_key,
    }))
}

pub(super) fn append_response_headers(
    mode: NegotiatedMode, send_key: Option<&[u8; 32]>,
    proxy_status_identity: &str, target_path: ForwardingPath,
    headers: &mut Vec<Header>,
) -> Result<()> {
    if proxy_status_identity.is_empty() ||
        proxy_status_identity.chars().any(char::is_control)
    {
        return Err(Error::InvalidConfig);
    }

    let mut params = Parameters::new();
    if let Some(transform) = mode.forwarding() {
        params.insert(
            "transform".into(),
            BareItem::String(transform.wire_name().into()),
        );
        if transform == PacketTransform::ScrambleDt {
            let key = send_key.ok_or(Error::InvalidState)?;
            params.insert("scramble-key".into(), BareItem::ByteSeq(key.to_vec()));
        }
    }

    let forwarding =
        Item::with_params(BareItem::Boolean(mode.forwarding().is_some()), params)
            .serialize_value()
            .map_err(|_| Error::InvalidConfig)?;
    let port_sharing = Item::new(BareItem::Boolean(mode.port_sharing()))
        .serialize_value()
        .map_err(|_| Error::InvalidConfig)?;

    let mut proxy_params = Parameters::new();
    proxy_params.insert(
        "next-hop".into(),
        BareItem::String(target_path.peer.to_string()),
    );
    let proxy_status = Item::with_params(
        BareItem::String(proxy_status_identity.into()),
        proxy_params,
    )
    .serialize_value()
    .map_err(|_| Error::InvalidConfig)?;

    headers.push(Header::new(CAPSULE_PROTOCOL, b"?1"));
    headers.push(Header::new(FORWARDING, forwarding.as_bytes()));
    headers.push(Header::new(PORT_SHARING, port_sharing.as_bytes()));
    headers.push(Header::new(PROXY_STATUS, proxy_status.as_bytes()));
    Ok(())
}

pub(super) fn parse_response_headers<T: NameValue>(
    headers: &[T], offered: &[PacketTransform], offered_port_sharing: bool,
) -> Result<(NegotiatedMode, Option<[u8; 32]>)> {
    if item_boolean(headers, CAPSULE_PROTOCOL)? != Some(true) {
        return Ok((NegotiatedMode::new(None, false), None));
    }

    let port_sharing = offered_port_sharing &&
        item_boolean(headers, PORT_SHARING)?.unwrap_or(false);
    let Some(item) = find_item(headers, FORWARDING)? else {
        return Ok((NegotiatedMode::new(None, port_sharing), None));
    };

    if item.bare_item.as_bool() != Some(true) {
        return Ok((NegotiatedMode::new(None, port_sharing), None));
    }

    let Some(name) = item.params.get("transform").and_then(BareItem::as_str)
    else {
        return Ok((NegotiatedMode::new(None, port_sharing), None));
    };
    let Some(transform) = PacketTransform::from_wire_name(name) else {
        return Err(Error::ProtocolViolation);
    };
    if !offered.contains(&transform) {
        return Err(Error::ProtocolViolation);
    }

    let key = if transform == PacketTransform::ScrambleDt {
        let Some(key) = item
            .params
            .get("scramble-key")
            .and_then(BareItem::as_byte_seq)
            .and_then(|value| value.as_slice().try_into().ok())
        else {
            return Ok((NegotiatedMode::new(None, port_sharing), None));
        };
        Some(key)
    } else {
        None
    };

    Ok((NegotiatedMode::new(Some(transform), port_sharing), key))
}

fn find_item<T: NameValue>(headers: &[T], name: &[u8]) -> Result<Option<Item>> {
    let mut found = None;
    for header in headers {
        if !header.name().eq_ignore_ascii_case(name) {
            continue;
        }
        if found.is_some() {
            return Err(Error::ProtocolViolation);
        }

        found = Some(
            Parser::parse_item(header.value())
                .map_err(|_| Error::ProtocolViolation)?,
        );
    }
    Ok(found)
}

fn item_boolean<T: NameValue>(
    headers: &[T], name: &[u8],
) -> Result<Option<bool>> {
    find_item(headers, name)?
        .map(|item| item.bare_item.as_bool().ok_or(Error::ProtocolViolation))
        .transpose()
}

fn parse_transforms(value: &str) -> Vec<PacketTransform> {
    let mut transforms = Vec::new();
    for name in value.split(',').map(str::trim) {
        if let Some(transform) = PacketTransform::from_wire_name(name) {
            if !transforms.contains(&transform) {
                transforms.push(transform);
            }
        }
    }
    transforms
}
