# BEAM Validator Manager: Pre-Audit Summary

### Changes Implemented
1. Introduction of secondary ERC721 Staking system which co-exists with Native Staking system.
2. Integration with https://github.com/euler-xyz/reward-streams for reward distribution which replaces the inbuilt reward distribution.
3. Validators and delegators now can only unlock their tokens after 'unlockDelayDuration'.
4. Redelegation for Native and ERC721 staking which skips the unlock period and unlocking/locking of assets.

### Reward Distribution
There are 2 instances of `TrackingRewardStreams` from euler-xyz/reward-streams contracts reposible for Native and ERC271 tokens weights respectively. These contracts enable distribution of multiple reward tokens simultaneously on an epoch basis.

Whenever uptime is submitted, `balanceTrackerHook` is called which updates the effective weight for an account based on the account's delegations and validations.

### Uptime
We use validator uptime to calculate reward weights. A signed uptime message can be obtained from the validator and submitted using `submitUptimeProof`. The message spec does not contain the timestamp of signing, just total uptime. Hence in the contracts, `currentEpochUptime = uptime - previousEpochUptime`. The staking weights are multiplied by this uptime percentage to get final weights for reward streams.

Uptime proofs can submitted perimssionlessly by anyone, however we will ensure we submit uptimes for each validator every epoch to ensure no stale weights.

### Notes
1. The secondary ERC721 Staking system does not interact with p-chain for weight updates. It only accepts upTime messages for setting secondary reward weight.
2. To start validation, validator must stake atleast 20k BEAM and 1 NFT.