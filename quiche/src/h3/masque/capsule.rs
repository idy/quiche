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

use super::Error;
use super::Result;

pub(super) const REGISTER_CLIENT_CID: u64 = 0xffe800;
pub(super) const REGISTER_TARGET_CID: u64 = 0xffe801;
pub(super) const ACK_CLIENT_CID: u64 = 0xffe802;
pub(super) const ACK_CLIENT_VCID: u64 = 0xffe803;
pub(super) const ACK_TARGET_CID: u64 = 0xffe804;
pub(super) const REJECT_CLIENT_CID: u64 = 0xffe805;
pub(super) const REJECT_TARGET_CID: u64 = 0xffe806;
pub(super) const CLOSE_CLIENT_CID: u64 = 0xffe807;
pub(super) const CLOSE_TARGET_CID: u64 = 0xffe808;
pub(super) const MAX_CONNECTION_IDS: u64 = 0xffe809;

pub(super) const DEFAULT_REASON: u64 = 0;
pub(super) const TOO_SHORT_REASON: u64 = 1;
pub(super) const CONFLICT_REASON: u64 = 2;

const MAX_KNOWN_PAYLOAD: usize = 512;
const MAX_UNDECODED: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Capsule {
    RegisterClient {
        reason: u64,
        cid: Vec<u8>,
    },
    RegisterTarget {
        reason: u64,
        cid: Vec<u8>,
        reset_token: Option<[u8; 16]>,
    },
    AckClient {
        cid: Vec<u8>,
        vcid: Vec<u8>,
    },
    AckClientVcid {
        cid: Vec<u8>,
        vcid: Vec<u8>,
        reset_token: Option<[u8; 16]>,
    },
    AckTarget {
        cid: Vec<u8>,
        vcid: Vec<u8>,
        reset_token: Option<[u8; 16]>,
    },
    RejectClient {
        reason: u64,
        cid: Vec<u8>,
    },
    RejectTarget {
        reason: u64,
        cid: Vec<u8>,
    },
    CloseClient {
        reason: u64,
        cid: Vec<u8>,
    },
    CloseTarget {
        reason: u64,
        cid: Vec<u8>,
    },
    MaxConnectionIds(u64),
}

impl Capsule {
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        let (ty, payload) = match self {
            Capsule::RegisterClient { reason, cid } => {
                validate_cid(cid)?;
                let mut payload = Vec::new();
                put_varint(&mut payload, *reason)?;
                payload.extend_from_slice(cid);
                (REGISTER_CLIENT_CID, payload)
            },

            Capsule::RegisterTarget {
                reason,
                cid,
                reset_token,
            } => {
                let mut payload = Vec::new();
                put_varint(&mut payload, *reason)?;
                put_len_bytes(&mut payload, cid)?;
                put_token(&mut payload, reset_token.as_ref())?;
                (REGISTER_TARGET_CID, payload)
            },

            Capsule::AckClient { cid, vcid } => {
                let mut payload = Vec::new();
                put_len_bytes(&mut payload, cid)?;
                put_len_bytes(&mut payload, vcid)?;
                (ACK_CLIENT_CID, payload)
            },

            Capsule::AckClientVcid {
                cid,
                vcid,
                reset_token,
            } => {
                let mut payload = Vec::new();
                put_len_bytes(&mut payload, cid)?;
                put_len_bytes(&mut payload, vcid)?;
                put_token(&mut payload, reset_token.as_ref())?;
                (ACK_CLIENT_VCID, payload)
            },

            Capsule::AckTarget {
                cid,
                vcid,
                reset_token,
            } => {
                let mut payload = Vec::new();
                put_len_bytes(&mut payload, cid)?;
                put_len_bytes(&mut payload, vcid)?;
                put_token(&mut payload, reset_token.as_ref())?;
                (ACK_TARGET_CID, payload)
            },

            Capsule::RejectClient { reason, cid } =>
                (REJECT_CLIENT_CID, encode_reason_cid(*reason, cid)?),

            Capsule::RejectTarget { reason, cid } =>
                (REJECT_TARGET_CID, encode_reason_cid(*reason, cid)?),

            Capsule::CloseClient { reason, cid } =>
                (CLOSE_CLIENT_CID, encode_reason_cid(*reason, cid)?),

            Capsule::CloseTarget { reason, cid } =>
                (CLOSE_TARGET_CID, encode_reason_cid(*reason, cid)?),

            Capsule::MaxConnectionIds(value) => {
                let mut payload = Vec::new();
                put_varint(&mut payload, *value)?;
                (MAX_CONNECTION_IDS, payload)
            },
        };

        if payload.len() > MAX_KNOWN_PAYLOAD {
            return Err(Error::Capacity);
        }

        let mut encoded = Vec::with_capacity(16 + payload.len());
        put_varint(&mut encoded, ty)?;
        put_varint(&mut encoded, payload.len() as u64)?;
        encoded.extend_from_slice(&payload);
        Ok(encoded)
    }

    fn decode(ty: u64, payload: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(payload);

        let capsule = match ty {
            REGISTER_CLIENT_CID => Capsule::RegisterClient {
                reason: reader.varint()?,
                cid: reader.rest_cid()?,
            },

            REGISTER_TARGET_CID => Capsule::RegisterTarget {
                reason: reader.varint()?,
                cid: reader.len_bytes()?,
                reset_token: reader.token()?,
            },

            ACK_CLIENT_CID => Capsule::AckClient {
                cid: reader.len_bytes()?,
                vcid: reader.len_bytes()?,
            },

            ACK_CLIENT_VCID => Capsule::AckClientVcid {
                cid: reader.len_bytes()?,
                vcid: reader.len_bytes()?,
                reset_token: reader.token()?,
            },

            ACK_TARGET_CID => Capsule::AckTarget {
                cid: reader.len_bytes()?,
                vcid: reader.len_bytes()?,
                reset_token: reader.token()?,
            },

            REJECT_CLIENT_CID => Capsule::RejectClient {
                reason: reader.varint()?,
                cid: reader.rest_cid()?,
            },

            REJECT_TARGET_CID => Capsule::RejectTarget {
                reason: reader.varint()?,
                cid: reader.rest_cid()?,
            },

            CLOSE_CLIENT_CID => Capsule::CloseClient {
                reason: reader.varint()?,
                cid: reader.rest_cid()?,
            },

            CLOSE_TARGET_CID => Capsule::CloseTarget {
                reason: reader.varint()?,
                cid: reader.rest_cid()?,
            },

            MAX_CONNECTION_IDS => Capsule::MaxConnectionIds(reader.varint()?),

            _ => return Err(Error::InvalidState),
        };

        if !reader.is_empty() {
            return Err(Error::ProtocolViolation);
        }

        Ok(capsule)
    }
}

#[derive(Clone, Default)]
pub(super) struct Decoder {
    buffer: Vec<u8>,
    skip_remaining: u64,
}

impl Decoder {
    pub(super) fn receive(&mut self, input: &[u8]) -> Result<Vec<Capsule>> {
        let mut capsules = Vec::new();
        let mut offset = 0;

        while offset < input.len() {
            if self.skip_remaining > 0 {
                let skipped = usize::try_from(self.skip_remaining)
                    .unwrap_or(usize::MAX)
                    .min(input.len() - offset);
                self.skip_remaining -= skipped as u64;
                offset += skipped;
                continue;
            }

            if self.buffer.len() >= MAX_UNDECODED {
                return Err(Error::ProtocolViolation);
            }

            self.buffer.push(input[offset]);
            offset += 1;

            while let Some((ty, ty_len)) = decode_varint(&self.buffer)? {
                let Some((payload_len, len_len)) =
                    decode_varint(&self.buffer[ty_len..])?
                else {
                    break;
                };
                let header_len = ty_len + len_len;

                if !is_known(ty) {
                    self.buffer.drain(..header_len);
                    self.skip_remaining = payload_len;
                    break;
                }

                let payload_len = usize::try_from(payload_len)
                    .map_err(|_| Error::ProtocolViolation)?;
                if payload_len > MAX_KNOWN_PAYLOAD {
                    return Err(Error::ProtocolViolation);
                }

                let total = header_len
                    .checked_add(payload_len)
                    .ok_or(Error::ProtocolViolation)?;
                if self.buffer.len() < total {
                    break;
                }

                let payload = self.buffer[header_len..total].to_vec();
                self.buffer.drain(..total);
                capsules.push(Capsule::decode(ty, &payload)?);
            }
        }

        Ok(capsules)
    }

    pub(super) fn finish(&self) -> Result<()> {
        if self.buffer.is_empty() && self.skip_remaining == 0 {
            Ok(())
        } else {
            Err(Error::ProtocolViolation)
        }
    }
}

fn is_known(ty: u64) -> bool {
    matches!(
        ty,
        REGISTER_CLIENT_CID |
            REGISTER_TARGET_CID |
            ACK_CLIENT_CID |
            ACK_CLIENT_VCID |
            ACK_TARGET_CID |
            REJECT_CLIENT_CID |
            REJECT_TARGET_CID |
            CLOSE_CLIENT_CID |
            CLOSE_TARGET_CID |
            MAX_CONNECTION_IDS
    )
}

fn validate_cid(cid: &[u8]) -> Result<()> {
    if cid.len() <= u8::MAX as usize {
        Ok(())
    } else {
        Err(Error::InvalidConfig)
    }
}

fn put_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    validate_cid(bytes)?;
    put_varint(out, bytes.len() as u64)?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_token(out: &mut Vec<u8>, token: Option<&[u8; 16]>) -> Result<()> {
    match token {
        Some(token) => {
            put_varint(out, token.len() as u64)?;
            out.extend_from_slice(token);
        },

        None => put_varint(out, 0)?,
    }

    Ok(())
}

fn encode_reason_cid(reason: u64, cid: &[u8]) -> Result<Vec<u8>> {
    validate_cid(cid)?;
    let mut payload = Vec::new();
    put_varint(&mut payload, reason)?;
    payload.extend_from_slice(cid);
    Ok(payload)
}

fn put_varint(out: &mut Vec<u8>, value: u64) -> Result<()> {
    let len = octets::varint_len(value);
    let start = out.len();
    out.resize(start + len, 0);
    let mut writer = octets::OctetsMut::with_slice(&mut out[start..]);
    writer.put_varint(value).map_err(|_| Error::InvalidConfig)?;
    Ok(())
}

fn decode_varint(input: &[u8]) -> Result<Option<(u64, usize)>> {
    let Some(first) = input.first() else {
        return Ok(None);
    };
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return Ok(None);
    }

    let mut reader = octets::Octets::with_slice(&input[..len]);
    let value = reader.get_varint().map_err(|_| Error::ProtocolViolation)?;
    Ok(Some((value, len)))
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn varint(&mut self) -> Result<u64> {
        let Some((value, len)) = decode_varint(&self.input[self.offset..])?
        else {
            return Err(Error::ProtocolViolation);
        };
        self.offset += len;
        Ok(value)
    }

    fn len_bytes(&mut self) -> Result<Vec<u8>> {
        let len = usize::try_from(self.varint()?)
            .map_err(|_| Error::ProtocolViolation)?;
        if len > u8::MAX as usize || self.input.len() - self.offset < len {
            return Err(Error::ProtocolViolation);
        }

        let value = self.input[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(value)
    }

    fn token(&mut self) -> Result<Option<[u8; 16]>> {
        let token = self.len_bytes()?;
        match token.len() {
            0 => Ok(None),
            16 => Ok(Some(
                token.try_into().map_err(|_| Error::ProtocolViolation)?,
            )),
            _ => Err(Error::ProtocolViolation),
        }
    }

    fn rest_cid(&mut self) -> Result<Vec<u8>> {
        let cid = self.input[self.offset..].to_vec();
        validate_cid(&cid).map_err(|_| Error::ProtocolViolation)?;
        self.offset = self.input.len();
        Ok(cid)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }
}
