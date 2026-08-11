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

use super::transform;
use super::Error;
use super::PacketTransform;
use super::Result;

pub(super) fn is_long(packet: &[u8]) -> Result<bool> {
    packet
        .first()
        .map(|first| first & 0x80 != 0)
        .ok_or(Error::ProtocolViolation)
}

pub(super) fn long_dcid(packet: &[u8]) -> Result<Option<&[u8]>> {
    if !is_long(packet)? {
        return Ok(None);
    }
    let cid_len = *packet.get(5).ok_or(Error::ProtocolViolation)? as usize;
    let end = 6usize
        .checked_add(cid_len)
        .ok_or(Error::ProtocolViolation)?;
    packet.get(6..end).map(Some).ok_or(Error::ProtocolViolation)
}

pub(super) fn rewrite(
    packet: &mut Vec<u8>, old_cid_len: usize, new_cid: &[u8],
    transform: Option<PacketTransform>, key: Option<&[u8; 32]>, inverse: bool,
) -> Result<()> {
    if packet.len() < 1 + old_cid_len || new_cid.len() > u8::MAX as usize {
        return Err(Error::ProtocolViolation);
    }
    if transform == Some(PacketTransform::ScrambleDt) {
        if packet.len() < 1 + old_cid_len + 16 {
            return Err(Error::ProtocolViolation);
        }
        if key.is_none() {
            return Err(Error::InvalidState);
        }
    }

    if inverse {
        apply_transform(packet, old_cid_len, transform, key, true)?;
        transform::replace_cid(packet, old_cid_len, new_cid)?;
    } else {
        let old_cid = packet[1..1 + old_cid_len].to_vec();
        transform::replace_cid(packet, old_cid_len, new_cid)?;
        if let Err(error) =
            apply_transform(packet, new_cid.len(), transform, key, false)
        {
            transform::replace_cid(packet, new_cid.len(), &old_cid)
                .expect("validated CID rollback");
            return Err(error);
        }
    }

    Ok(())
}

fn apply_transform(
    packet: &mut [u8], cid_len: usize, transform: Option<PacketTransform>,
    key: Option<&[u8; 32]>, inverse: bool,
) -> Result<()> {
    match transform {
        None | Some(PacketTransform::Identity) => Ok(()),

        Some(PacketTransform::ScrambleDt) => {
            let key = key.ok_or(Error::InvalidState)?;
            transform::scramble(packet, cid_len, key, inverse)
        },
    }
}
