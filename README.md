# crc-fast-rs

This is a CRC algorithm generator with SIMD support.

## How the repository works

The `gen_crates.sh` generates all the specific CRC algorithm crates using the
template directory `crc-crate-template` based on the algorithm list in
`algos.csv`.

The generated `lib.rs` file contains a single expression `crc!(...)` and a
dependency on the `crc-fast-gen` crate which contains the proc macro logic.

## Questions

**Why one crate per algorithm and not just one crate?**

- In general, granular crates are preferred in the Rust ecosystem.
- From a consumer point of view, it's unlikely you'll need more than 1 or 2 CRCs
  for a given application. Explicit crates per algorithm makes it clearer which
  one you're depending on.
- It makes it possible to pre-expand the code (in the future, WIP) without
  bloating a single crate (making it slow to download, among other things).
  Pre-expanding will also improve compilation times.
- It's easier to review the expanded code of a single algorithm for e.g.
  security compared to the complicated macro.
- It's easier to hotfix if there is a problem with a single algorithm
- Better statistics on CRC populatity, that can guide future development

## License

Everything is licensed under the MIT license (see [LICENSE](LICENSE)).

## References

- https://reveng.sourceforge.io/crc-catalogue/ good collection of CRC:s with all
  the relevant parameters
- https://crccalc.com/ used to double-check some values
