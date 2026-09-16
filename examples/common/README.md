# Shared firmware pieces

`console.rs` implements the serial console used by both examples. It is
included with `#[path]` so each example stays a standalone crate.
