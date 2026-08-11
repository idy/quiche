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

use boring::symm::Cipher;
use boring::symm::Crypter;
use boring::symm::Mode;

use super::Error;
use super::Result;

pub(super) fn replace_cid(
    packet: &mut Vec<u8>, original_len: usize, replacement: &[u8],
) -> Result<()> {
    if packet.len() < 1 + original_len || replacement.len() > u8::MAX as usize {
        return Err(Error::ProtocolViolation);
    }

    packet.splice(1..1 + original_len, replacement.iter().copied());
    Ok(())
}

pub(super) fn scramble(
    packet: &mut [u8], cid_len: usize, key: &[u8; 32], inverse: bool,
) -> Result<()> {
    if packet.len() < 1 + cid_len + 16 {
        return Err(Error::ProtocolViolation);
    }

    let iv_range = 1 + cid_len..1 + cid_len + 16;
    let encrypted_iv: [u8; 16] = packet[iv_range.clone()]
        .try_into()
        .map_err(|_| Error::ProtocolViolation)?;
    let iv = if inverse {
        aes_ecb(&key[16..], &encrypted_iv, Mode::Decrypt)?
    } else {
        encrypted_iv
    };

    let mut ctr_input = Vec::with_capacity(packet.len() - cid_len - 16);
    ctr_input.push(packet[0]);
    ctr_input.extend_from_slice(&packet[iv_range.end..]);
    let ctr_output = aes_ctr(&key[..16], &iv, &ctr_input)?;
    let transformed_iv = if inverse {
        iv
    } else {
        aes_ecb(&key[16..], &iv, Mode::Encrypt)?
    };

    packet[0] = ctr_output[0] & 0x7f;
    packet[iv_range].copy_from_slice(&transformed_iv);
    packet[1 + cid_len + 16..].copy_from_slice(&ctr_output[1..]);
    Ok(())
}

fn aes_ctr(key: &[u8], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ctr();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))
        .map_err(|_| Error::Crypto)?;
    crypter.pad(false);

    let mut output = vec![0; input.len() + cipher.block_size()];
    let count = crypter
        .update(input, &mut output)
        .map_err(|_| Error::Crypto)?;
    let rest = crypter
        .finalize(&mut output[count..])
        .map_err(|_| Error::Crypto)?;
    output.truncate(count + rest);
    Ok(output)
}

fn aes_ecb(key: &[u8], input: &[u8; 16], mode: Mode) -> Result<[u8; 16]> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter =
        Crypter::new(cipher, mode, key, None).map_err(|_| Error::Crypto)?;
    crypter.pad(false);

    let mut output = [0; 32];
    let count = crypter
        .update(input, &mut output)
        .map_err(|_| Error::Crypto)?;
    let rest = crypter
        .finalize(&mut output[count..])
        .map_err(|_| Error::Crypto)?;
    if count + rest != 16 {
        return Err(Error::Crypto);
    }

    output[..16].try_into().map_err(|_| Error::Crypto)
}
