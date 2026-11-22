use minicbor::{encode::write::Cursor, Encoder};

use crate::codec::{decode_response, encode_request, timestamp_ms, MAX_REQUEST, MAX_RESPONSE};

#[test]
fn request_matches_the_aws_sdk_wire_format() {
    let mut buffer = [0; MAX_REQUEST];
    assert_eq!(
        encode_request(&mut buffer, Some(&[1, 2]), Some(&[0x20]), Some(&[0x30])).unwrap(),
        b"\xa1\x6bAttestation\xa3\x69user_data\x41\x20\x65nonce\x41\x30\x6apublic_key\x42\x01\x02"
    );
    assert_eq!(
        encode_request(&mut buffer, None, None, None).unwrap(),
        b"\xa1\x6bAttestation\xa3\x69user_data\xf6\x65nonce\xf6\x6apublic_key\xf6"
    );
    assert!(encode_request(&mut buffer, Some(&[0; MAX_REQUEST]), None, None).is_err());
}

#[test]
fn accepts_only_a_complete_bounded_attestation_response() {
    let response = b"\xa1\x6bAttestation\xa1\x68document\x43\x01\x02\x03";
    assert_eq!(decode_response(response), Some([1, 2, 3].as_slice()));
    assert_eq!(
        decode_response(b"\xbf\x6bAttestation\xbf\x68document\x41\x01\xff\xff"),
        Some([1].as_slice())
    );
    assert_eq!(decode_response(&response[..response.len() - 1]), None);
    assert_eq!(decode_response(&[response.as_slice(), &[0]].concat()), None);
    assert_eq!(decode_response(b"\xa1\x65Error\x6fInvalidArgument"), None);
    assert_eq!(
        decode_response(b"\xa1\x6bAttestation\xa1\x68document\x40"),
        None
    );
    assert_eq!(decode_response(&[0; MAX_RESPONSE + 1]), None);
    assert_eq!(
        decode_response(b"\xbf\x6bAttestation\xbf\x68document\x41\x01\xff"),
        None
    );
}

#[test]
fn reads_time_from_an_aws_nitro_document() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../sdk/tests/attestation/fixtures/aws-nitro-devnet.json"
    ))
    .unwrap();
    let document = hex::decode(fixture["evidence"].as_str().unwrap()).unwrap();
    assert_eq!(timestamp_ms(&document), Some(1_795_290_719_965));
    assert_eq!(
        timestamp_ms(&[&[0xd2], document.as_slice()].concat()),
        Some(1_795_290_719_965)
    );
    assert_eq!(timestamp_ms(&[&[0xd1], document.as_slice()].concat()), None);
    assert_eq!(timestamp_ms(&document[..document.len() - 1]), None);
    assert_eq!(timestamp_ms(&[document.as_slice(), &[0]].concat()), None);
}

#[test]
fn rejects_absent_ambiguous_or_malformed_local_time() {
    for payload in [
        b"\xa0".as_slice(),
        b"\xa1\x69timestamp\x00",
        b"\xa1\x69timestamp\x20",
        b"\xa1\x69timestamp\x01\x00",
        b"\xa2\x69timestamp\x01\x69timestamp\x02",
        b"\xa2\x69timestamp\x01\x61x",
    ] {
        let mut buffer = [0; 64];
        let mut cose = Encoder::new(Cursor::new(&mut buffer[..]));
        cose.array(4)
            .unwrap()
            .bytes(&[])
            .unwrap()
            .map(0)
            .unwrap()
            .bytes(payload)
            .unwrap()
            .bytes(&[1])
            .unwrap();
        let length = cose.into_writer().position();
        assert_eq!(timestamp_ms(&buffer[..length]), None);
    }
}
