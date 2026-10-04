#![no_main]
//! Transport acknowledgements and store-and-forward requests.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = meshstar_core::transport::Ack::decode(data);
    let _ = meshstar_core::store_forward::StoreRequest::decode(data);
});
