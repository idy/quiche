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

#[derive(Clone)]
pub(super) struct Mapping {
    pub(super) cid: Vec<u8>,
    pub(super) vcid: Vec<u8>,
    pub(super) reset_token: Option<[u8; 16]>,
    pub(super) acknowledged: bool,
}

pub(super) fn conflicts(left: &[u8], right: &[u8]) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub(super) fn generate_vcid<F>(cid: &[u8], conflict: F) -> Result<Vec<u8>>
where
    F: FnMut(&[u8]) -> bool,
{
    generate_vcid_at_least(cid, cid.len(), conflict)
}

pub(super) fn generate_vcid_at_least<F>(
    cid: &[u8], min_len: usize, mut conflict: F,
) -> Result<Vec<u8>>
where
    F: FnMut(&[u8]) -> bool,
{
    if cid.len() > 20 || min_len > 20 {
        return Err(Error::Capacity);
    }

    let len = cid.len().max(min_len).max(8);
    for _ in 0..16 {
        let mut vcid = vec![0; len];
        super::super::super::rand::rand_bytes(&mut vcid);
        if !conflict(&vcid) {
            return Ok(vcid);
        }
    }

    Err(Error::Capacity)
}

pub(super) fn packet_cid_matches(packet: &[u8], cid: &[u8]) -> bool {
    packet.len() > cid.len() && packet[1..].starts_with(cid)
}

pub(super) fn stateless_reset_matches(
    packet: &[u8], token: Option<&[u8; 16]>,
) -> bool {
    let Some(token) = token else {
        return false;
    };
    packet.len() >= 21 && packet.ends_with(token)
}
