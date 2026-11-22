use minicbor::{data::Type, encode::write::Cursor, Decoder, Encoder};

pub(super) const MAX_REQUEST: usize = 0x1000;
pub(super) const MAX_RESPONSE: usize = 0x3000;

pub(super) fn encode_request<'a>(
    buffer: &'a mut [u8],
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<&'a [u8], minicbor::encode::Error<minicbor::encode::write::EndOfSlice>> {
    let mut encoder = Encoder::new(Cursor::new(&mut *buffer));
    encoder.map(1)?.str("Attestation")?.map(3)?;
    for (name, value) in [
        ("user_data", user_data),
        ("nonce", nonce),
        ("public_key", public_key),
    ] {
        encoder.str(name)?;
        match value {
            Some(bytes) => encoder.bytes(bytes)?,
            None => encoder.null()?,
        };
    }
    let length = encoder.into_writer().position();
    Ok(&buffer[..length])
}

pub(super) fn decode_response(response: &[u8]) -> Option<&[u8]> {
    if response.len() > MAX_RESPONSE {
        return None;
    }
    let mut decoder = Decoder::new(response);
    let outer = decoder.map().ok()?;
    if outer.is_some_and(|length| length != 1) || decoder.str().ok()? != "Attestation" {
        return None;
    }
    let body = decoder.map().ok()?;
    if body.is_some_and(|length| length != 1) || decoder.str().ok()? != "document" {
        return None;
    }
    let document = decoder.bytes().ok()?;
    finish_container(&mut decoder, body)?;
    finish_container(&mut decoder, outer)?;
    (!document.is_empty() && decoder.position() == response.len()).then_some(document)
}

fn finish_container(decoder: &mut Decoder<'_>, length: Option<u64>) -> Option<()> {
    if length.is_none() {
        if decoder.datatype().ok()? != Type::Break {
            return None;
        }
        decoder.skip().ok()?;
    }
    Some(())
}

/// Read the timestamp from a fresh document returned by the local NSM.
pub(super) fn timestamp_ms(document: &[u8]) -> Option<u64> {
    if document.len() > MAX_RESPONSE {
        return None;
    }
    let mut cose = Decoder::new(document);
    if cose.datatype().ok()? == Type::Tag && cose.tag().ok()?.as_u64() != 18 {
        return None;
    }
    let array = cose.array().ok()?;
    if array.is_some_and(|length| length != 4) {
        return None;
    }
    cose.bytes().ok()?;
    if !matches!(cose.datatype().ok()?, Type::Map | Type::MapIndef) {
        return None;
    }
    cose.skip().ok()?;
    let payload = cose.bytes().ok()?;
    if cose.bytes().ok()?.is_empty() {
        return None;
    }
    finish_container(&mut cose, array)?;
    if cose.position() != document.len() {
        return None;
    }

    let mut decoder = Decoder::new(payload);
    let mut remaining = decoder.map().ok()?;
    let mut timestamp = None;
    while remaining != Some(0) {
        if remaining.is_none() && decoder.datatype().ok()? == Type::Break {
            finish_container(&mut decoder, None)?;
            break;
        }
        if decoder.str().ok()? == "timestamp" {
            if timestamp.is_some() {
                return None;
            }
            timestamp = Some(decoder.u64().ok()?);
        } else {
            if decoder.datatype().ok()? == Type::Break {
                return None;
            }
            decoder.skip().ok()?;
        }
        remaining = remaining.map(|length| length - 1);
    }
    timestamp.filter(|&value| value > 0 && decoder.position() == payload.len())
}
