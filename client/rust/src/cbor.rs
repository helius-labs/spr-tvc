//! Strict CBOR for Nitro COSE_Sign1 documents.
//!
//! Attestation bytes are parsed before the signature is checked, so this
//! accepts only the definite-length subset NSM emits, plus the one indefinite
//! root map a real attestation document uses. Shortest-form arguments only.

use spr_tvc_wire::error::{ErrorCode, TvcError};

const MAJOR_SHIFT: u8 = 5;
const ADDITIONAL_MASK: u8 = 0x1f;

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const INLINE_ARG_LIMIT: u8 = 24;
const ADDITIONAL_U8: u8 = 24;
const ADDITIONAL_U16: u8 = 25;
const ADDITIONAL_U32: u8 = 26;
const ADDITIONAL_U64: u8 = 27;
const ADDITIONAL_INDEFINITE: u8 = 31;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;
const CBOR_BREAK: u8 = 0xff;

const COSE_SIGN1_TAG: u64 = 18;
const COSE_SIG_STRUCTURE_ELEMENTS: usize = 4;
const MAX_DEPTH: usize = 16;
const MAX_INDEFINITE_ROOT_MAP_ENTRIES: usize = 32;
const MAX_PREALLOC: usize = 64;

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
        let (value, minimum) = match additional {
            0..INLINE_ARG_LIMIT => return Ok(u64::from(additional)),
            ADDITIONAL_U8 => (u64::from(self.byte()?), u64::from(INLINE_ARG_LIMIT)),
            ADDITIONAL_U16 => {
                let raw: [u8; size_of::<u16>()] = self
                    .take(size_of::<u16>())?
                    .try_into()
                    .map_err(|_| boot())?;
                (u64::from(u16::from_be_bytes(raw)), u64::from(u8::MAX) + 1)
            }
            ADDITIONAL_U32 => {
                let raw: [u8; size_of::<u32>()] = self
                    .take(size_of::<u32>())?
                    .try_into()
                    .map_err(|_| boot())?;
                (u64::from(u32::from_be_bytes(raw)), u64::from(u16::MAX) + 1)
            }
            ADDITIONAL_U64 => {
                let raw: [u8; size_of::<u64>()] = self
                    .take(size_of::<u64>())?
                    .try_into()
                    .map_err(|_| boot())?;
                (u64::from_be_bytes(raw), u64::from(u32::MAX) + 1)
            }
            _ => return Err(boot()),
        };
        if value < minimum {
            return Err(boot());
        }
        Ok(value)
    }

    fn read(&mut self, depth: usize) -> Result<Cbor, TvcError> {
        if depth > MAX_DEPTH {
            return Err(boot());
        }
        let initial = self.byte()?;
        let major = initial >> MAJOR_SHIFT;
        let additional = initial & ADDITIONAL_MASK;
        if major == MAJOR_SIMPLE {
            return match additional {
                SIMPLE_FALSE => Ok(Cbor::Bool(false)),
                SIMPLE_TRUE => Ok(Cbor::Bool(true)),
                SIMPLE_NULL => Ok(Cbor::Null),
                _ => Err(boot()),
            };
        }
        if additional == ADDITIONAL_INDEFINITE
            && major == MAJOR_MAP
            && depth == 0
            && self.allow_indefinite_root_map
        {
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
                let mut items = Vec::with_capacity(len.min(MAX_PREALLOC));
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
        let mut entries = Vec::with_capacity(len.min(MAX_PREALLOC));
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
        while self.bytes.get(self.offset) != Some(&CBOR_BREAK) {
            if entries.len() >= MAX_INDEFINITE_ROOT_MAP_ENTRIES {
                return Err(boot());
            }
            let key = map_key(self.read(depth + 1)?)?;
            if self.bytes.get(self.offset) == Some(&CBOR_BREAK) {
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
    let mut out = Vec::new();
    push_head(&mut out, MAJOR_ARRAY, COSE_SIG_STRUCTURE_ELEMENTS);
    push_head(&mut out, MAJOR_TEXT, context.len());
    out.extend_from_slice(context);
    for item in [protected, &[][..], payload] {
        push_head(&mut out, MAJOR_BYTES, item.len());
        out.extend_from_slice(item);
    }
    out
}

fn push_head(out: &mut Vec<u8>, major: u8, argument: usize) {
    let prefix = major << MAJOR_SHIFT;
    let argument = argument as u64;
    if argument < u64::from(INLINE_ARG_LIMIT) {
        out.push(prefix | argument as u8);
    } else if let Ok(value) = u8::try_from(argument) {
        out.push(prefix | ADDITIONAL_U8);
        out.push(value);
    } else if let Ok(value) = u16::try_from(argument) {
        out.push(prefix | ADDITIONAL_U16);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(argument) {
        out.push(prefix | ADDITIONAL_U32);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(prefix | ADDITIONAL_U64);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

#[cfg(test)]
#[path = "../tests/unit/cbor.rs"]
mod tests;
