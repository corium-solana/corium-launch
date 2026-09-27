# Corium Launch program source

Source-only mirror of the Anchor program deployed at
`NovanpiewpH4zvYgtzAQN2zWQ94KcKWrHCTswWdZ1Y1` on Solana mainnet-beta: the fee router and supernova-bounty
distributor behind [corium.so](https://corium.so). Published so the build can be
reproduced and verified; the site, server and history live in a private repo.

Reproduce the deployed binary:

```bash
cargo install solana-verify --locked
cd onchain
solana-verify build --library-name corium_launch --arch v3 \
  --base-image solanafoundation/solana-verifiable-build:4.0.3
solana-verify get-executable-hash target/deploy/corium_launch.so
solana-verify get-program-hash NovanpiewpH4zvYgtzAQN2zWQ94KcKWrHCTswWdZ1Y1
```

Verify against this repo:

```bash
solana-verify verify-from-repo \
  --program-id NovanpiewpH4zvYgtzAQN2zWQ94KcKWrHCTswWdZ1Y1 \
  --library-name corium_launch --mount-path onchain --arch v3 \
  --base-image solanafoundation/solana-verifiable-build:4.0.3 \
  <this repo url>
```

Security contact is embedded in the program
([solana-security-txt](https://github.com/neodyme-labs/solana-security-txt)): see
`onchain/programs/corium_launch/src/lib.rs`, or <https://corium.so/security.txt>.
Docs: <https://docs.corium.so/rules/program>.

## Licence

Published for verification, not for reuse. **All rights reserved** - no licence
is granted, expressly or by implication.

Read it, build it, and compare it against the deployed program: that is the
point of publishing it, and reporting what you find is welcome. Redeploying this
source, or a derivative of it, as your own program or service is not permitted.
