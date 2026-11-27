//! Strict CBOR for Nitro COSE_Sign1 documents.
//!
//! Attestation bytes are parsed before the signature is checked, so this
//! accepts only the definite-length subset NSM emits, plus the one indefinite
//! root map a real attestation document uses. Shortest-form arguments only.

use spr_tvc_wire::error::{ErrorCode, TvcError};

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;
const COSE_SIGN1_TAG: u64 = 18;
const MAX_DEPTH: usize = 16;
const MAX_INDEFINITE_ROOT_MAP_ENTRIES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CborKey {
    Int(i64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Null,
    Array(Vec<Cbor>),
    Map(Vec<(CborKey, Cbor)>),
}

impl Cbor {
    pub(crate) fn as_bytes(&self) -> Result<&[u8], TvcError> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            _ => Err(boot()),
        }
    }

    pub(crate) fn as_str(&self) -> Result<&str, TvcError> {
        match self {
            Self::Text(text) => Ok(text),
            _ => Err(boot()),
        }
    }

    pub(crate) fn as_i64(&self) -> Result<i64, TvcError> {
        match self {
            Self::Int(value) => Ok(*value),
            _ => Err(boot()),
        }
    }

    pub(crate) fn as_array(&self) -> Result<&[Cbor], TvcError> {
        match self {
            Self::Array(items) => Ok(items),
            _ => Err(boot()),
        }
    }

    pub(crate) fn as_map(&self) -> Result<&[(CborKey, Cbor)], TvcError> {
        match self {
            Self::Map(entries) => Ok(entries),
            _ => Err(boot()),
        }
    }

    pub(crate) fn map_get<'a>(&'a self, key: &CborKey) -> Result<&'a Cbor, TvcError> {
        self.as_map()?
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
            .ok_or_else(boot)
    }
}

fn boot() -> TvcError {
    TvcError::new(ErrorCode::BootProofUnverified)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    allow_indefinite_root_map: bool,
}

impl<'a> Reader<'a> {
    fn decode(bytes: &'a [u8], nitro: bool) -> Result<Cbor, TvcError> {
        let mut reader = Self {
            bytes,
            offset: 0,
            allow_indefinite_root_map: nitro,
        };
        let value = reader.read(0)?;
        if reader.offset != reader.bytes.len() {
            return Err(boot());
        }
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, TvcError> {
        let value = *self.bytes.get(self.offset).ok_or_else(boot)?;
        self.offset += 1;
        Ok(value)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TvcError> {
        let end = self.offset.checked_add(length).ok_or_else(boot)?;
        let slice = self.bytes.get(self.offset..end).ok_or_else(boot)?;
        self.offset = end;
        Ok(slice)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, TvcError> {
        if additional < 24 {
            return Ok(u64::from(additional));
        }
        if additional == 24 {
            let value = u64::from(self.byte()?);
            if value < 24 {
                return Err(boot());
            }
            return Ok(value);
        }
        if matches!(additional, 25..=27) {
            let width = match additional {
                25 => 2,
                26 => 4,
                _ => 8,
            };
            let raw = self.take(width)?;
            let mut value = 0u64;
            for byte in raw {
                value = value.checked_shl(8).ok_or_else(boot)? | u64::from(*byte);
            }
            let minimum = match additional {
                25 => 0x100,
                26 => 0x1_0000,
                _ => 0x1_0000_0000,
            };
            if value < minimum {
                return Err(boot());
            }
            return Ok(value);
        }
        Err(boot())
    }

    fn read(&mut self, depth: usize) -> Result<Cbor, TvcError> {
        if depth > MAX_DEPTH {
            return Err(boot());
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if major == MAJOR_SIMPLE {
            return match additional {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err(boot()),
            };
        }
        if additional == 31 && major == MAJOR_MAP && depth == 0 && self.allow_indefinite_root_map {
            return self.indefinite_root_map(depth);
        }
        let argument = self.argument(additional)?;
        match major {
            MAJOR_UNSIGNED => Ok(Cbor::Int(i64::try_from(argument).map_err(|_| boot())?)),
            MAJOR_NEGATIVE => {
                let magnitude = i64::try_from(argument).map_err(|_| boot())?;
                Ok(Cbor::Int(magnitude.checked_neg().ok_or_else(boot)? - 1))
            }
            MAJOR_BYTES => Ok(Cbor::Bytes(
                self.take(usize::try_from(argument).map_err(|_| boot())?)?
                    .to_vec(),
            )),
            MAJOR_TEXT => {
                let bytes = self.take(usize::try_from(argument).map_err(|_| boot())?)?;
                let text = std::str::from_utf8(bytes).map_err(|_| boot())?;
                Ok(Cbor::Text(text.to_owned()))
            }
            MAJOR_ARRAY => {
                let len = usize::try_from(argument).map_err(|_| boot())?;
                if len > self.bytes.len() - self.offset {
                    return Err(boot());
                }
                let mut items = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    items.push(self.read(depth + 1)?);
                }
                Ok(Cbor::Array(items))
            }
            MAJOR_MAP => {
                let len = usize::try_from(argument).map_err(|_| boot())?;
                if len > (self.bytes.len() - self.offset) / 2 {
                    return Err(boot());
                }
                Ok(Cbor::Map(self.entries(depth, len)?))
            }
            MAJOR_TAG => {
                if argument != COSE_SIGN1_TAG || depth != 0 {
                    return Err(boot());
                }
                self.read(depth + 1)
            }
            _ => Err(boot()),
        }
    }

    fn entries(&mut self, depth: usize, len: usize) -> Result<Vec<(CborKey, Cbor)>, TvcError> {
        let mut entries = Vec::with_capacity(len.min(64));
        for _ in 0..len {
            let key = map_key(self.read(depth + 1)?)?;
            if entries.iter().any(|(existing, _)| existing == &key) {
                return Err(boot());
            }
            entries.push((key, self.read(depth + 1)?));
        }
        Ok(entries)
    }

    fn indefinite_root_map(&mut self, depth: usize) -> Result<Cbor, TvcError> {
        let mut entries = Vec::new();
        while self.bytes.get(self.offset) != Some(&0xff) {
            if entries.len() >= MAX_INDEFINITE_ROOT_MAP_ENTRIES {
                return Err(boot());
            }
            let key = map_key(self.read(depth + 1)?)?;
            if self.bytes.get(self.offset) == Some(&0xff) {
                return Err(boot());
            }
            if entries.iter().any(|(existing, _)| existing == &key) {
                return Err(boot());
            }
            entries.push((key, self.read(depth + 1)?));
        }
        self.byte()?;
        Ok(Cbor::Map(entries))
    }
}

fn map_key(value: Cbor) -> Result<CborKey, TvcError> {
    match value {
        Cbor::Int(value) => Ok(CborKey::Int(value)),
        Cbor::Text(value) => Ok(CborKey::Text(value)),
        _ => Err(boot()),
    }
}

pub(crate) fn decode_cbor(bytes: &[u8]) -> Result<Cbor, TvcError> {
    Reader::decode(bytes, false)
}

pub(crate) fn decode_nitro_cbor(bytes: &[u8]) -> Result<Cbor, TvcError> {
    Reader::decode(bytes, true)
}

/// `["Signature1", protected, h'', payload]`, definite-length.
pub(crate) fn encode_cose_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let context = b"Signature1";
    let mut out = encode_head(MAJOR_ARRAY, 4);
    out.extend(encode_head(MAJOR_TEXT, context.len()));
    out.extend_from_slice(context);
    for item in [protected, &[][..], payload] {
        out.extend(encode_head(MAJOR_BYTES, item.len()));
        out.extend_from_slice(item);
    }
    out
}

fn encode_head(major: u8, argument: usize) -> Vec<u8> {
    let prefix = major << 5;
    let argument = argument as u64;
    if argument < 24 {
        return vec![prefix | argument as u8];
    }
    if argument < 0x100 {
        return vec![prefix | 24, argument as u8];
    }
    if argument < 0x1_0000 {
        return vec![prefix | 25, (argument >> 8) as u8, argument as u8];
    }
    if argument < 0x1_0000_0000 {
        return vec![
            prefix | 26,
            (argument >> 24) as u8,
            (argument >> 16) as u8,
            (argument >> 8) as u8,
            argument as u8,
        ];
    }
    vec![
        prefix | 27,
        (argument >> 56) as u8,
        (argument >> 48) as u8,
        (argument >> 40) as u8,
        (argument >> 32) as u8,
        (argument >> 24) as u8,
        (argument >> 16) as u8,
        (argument >> 8) as u8,
        argument as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(hex_str: &str) -> Cbor {
        decode_cbor(&hex::decode(hex_str).unwrap()).unwrap()
    }

    #[test]
    fn decodes_the_attestation_subset() {
        assert_eq!(decode_hex("00"), Cbor::Int(0));
        assert_eq!(decode_hex("1818"), Cbor::Int(24));
        assert_eq!(decode_hex("1903e8"), Cbor::Int(1000));
        assert_eq!(
            decode_hex("1b000001977420dc00"),
            Cbor::Int(1_750_000_000_000)
        );
        assert_eq!(decode_hex("20"), Cbor::Int(-1));
        assert_eq!(decode_hex("f6"), Cbor::Null);
        assert_eq!(decode_hex("6449455446"), Cbor::Text("IETF".into()));
        assert_eq!(
            decode_hex("83010203"),
            Cbor::Array(vec![Cbor::Int(1), Cbor::Int(2), Cbor::Int(3)])
        );
    }

    #[test]
    fn rejects_non_minimal_arguments_and_trailing_bytes() {
        assert!(decode_cbor(&hex::decode("1800").unwrap()).is_err());
        assert!(decode_cbor(&hex::decode("0000").unwrap()).is_err());
    }

    #[test]
    fn rejects_huge_container_lengths_without_allocating() {
        // Definite array and map claiming 2^32 entries with zero body bytes.
        assert!(decode_cbor(&hex::decode("9b0000000100000000").unwrap()).is_err());
        assert!(decode_cbor(&hex::decode("bb0000000100000000").unwrap()).is_err());
    }

    #[test]
    fn cose_sig_structure_matches_the_canonical_vector() {
        let encoded = encode_cose_sig_structure(&[0xa1, 0x01, 0x38], &[1, 2, 3, 4, 5]);
        assert_eq!(
            hex::encode(&encoded),
            "846a5369676e61747572653143a1013840450102030405"
        );
    }
}
