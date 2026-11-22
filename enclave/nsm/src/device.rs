use std::{fs::OpenOptions, io, mem::size_of, os::fd::AsRawFd};

use crate::codec::{decode_response, encode_request, MAX_REQUEST, MAX_RESPONSE};

// Linux nsm.h defines the raw ioctl as two { __u64 addr, __u64 len } pairs.
#[repr(C)]
struct NsmBuffer {
    addr: u64,
    len: u64,
}

#[repr(C)]
struct NsmRaw {
    request: NsmBuffer,
    response: NsmBuffer,
}

const _: () = assert!(size_of::<NsmRaw>() == 32);

/// Request an AWS-signed attestation document without changing its bytes.
pub fn attest(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> io::Result<Vec<u8>> {
    let mut request = [0; MAX_REQUEST];
    let request = encode_request(&mut request, public_key, user_data, nonce).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "NSM request exceeds 4096 bytes",
        )
    })?;
    let device = OpenOptions::new().read(true).write(true).open("/dev/nsm")?;
    let mut response = [0; MAX_RESPONSE];
    let mut message = NsmRaw {
        request: NsmBuffer {
            addr: request.as_ptr() as usize as u64,
            len: request.len() as u64,
        },
        response: NsmBuffer {
            addr: response.as_mut_ptr() as usize as u64,
            len: response.len() as u64,
        },
    };
    // SAFETY: Both buffers stay live during the synchronous ioctl. The message
    // describes their actual lengths. Only the returned length is used below.
    #[allow(unsafe_code)]
    let status = unsafe {
        nix::libc::ioctl(
            device.as_raw_fd(),
            nix::request_code_readwrite!(0x0a, 0, size_of::<NsmRaw>()),
            &mut message as *mut NsmRaw,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(message.response.len).ok();
    length
        .and_then(|length| response.get(..length))
        .and_then(decode_response)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid NSM attestation response",
            )
        })
}
