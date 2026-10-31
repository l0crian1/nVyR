# nftables JSON samples

`listings.json` contains actual JSON captured from nftables 1.1.7 on 2026-10-18.
`listing.nft` is the input used to create these objects in a disposable network
namespace. No active router configuration was changed.

The keys identify separate `nft -j list ...` queries: `ruleset`, `chain`, `set`,
`map`, and the `chains` inventory. Handles, remaining timeout values, and last-used
ages are observations, not stable identifiers for expectations across new runs.

Unit tests compare full and scoped structures, inspect known semantic fields,
and preserve unknown expressions. Opt-in live tests replay the input and also
generate all rule-keymap fields and NAT map results with nVyR's formatters.
