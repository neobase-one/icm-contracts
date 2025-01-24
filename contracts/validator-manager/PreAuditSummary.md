# BEAM Validator Manager: Pre-Audit Summary

### Changes Implemented
1. Introduction of secondary ERC721 Staking system which co-exists with Native Staking system. ([NODE NFT](https://nodes.onbeam.com) - This does not influence voting power or stake weight of delegators/validators only used for distribution of secondary rewards)
2. Integration with https://github.com/euler-xyz/reward-streams for reward distribution which replaces the inbuilt reward distribution.
3. Delegators now can only unlock their tokens after 'unlockDelayDuration'.
4. Redelegation for Native and ERC721 staking which skips the unlock period and unlocking/locking of assets.

### Reward Distribution
There are 2 instances of TrackingRewardStreams from euler-xyz/reward-streams contracts reposible for Native and ERC271 tokens weights respectively. These contracts enable distribution of multiple reward tokens simultaneously on an epoch basis.

Whenever uptime is submitted, balanceTrackerHook is called which updates the effective reward weight for an account based on the account's delegations and validations.

### Network Rewards:
#### Primary rewards -> BEAM Stakers
- Gas fees ($BEAM)

### Secondary rewards -> 80% to NODE stakers, 20% to BEAM stakers
- Rewards for validation sponsored by the Beam Foundation Treasury
- Swap fees, bridge fees and marketplace fees
- Performance fees from other ventures of Beam

*Validators charge the same commission on both*

### Uptime
We use validator uptime to calculate reward weights. A [signed uptime message](https://github.com/ava-labs/subnet-evm/blob/master/examples/sign-uptime-message/main.go) can be obtained from the validator and submitted using submitUptimeProof. The [message](https://github.com/ava-labs/subnet-evm/blob/master/warp/messages/validator_uptime.go) spec does not contain the timestamp of signing, just total uptime. Hence in the contracts, currentEpochUptime = uptime - previousEpochUptime. The staking weights are multiplied by this uptime percentage to get final weights for reward streams.

Uptime proofs can submitted perimssionlessly by anyone, however beam will run a service that automatically polls and submits these for each validator every epoch to ensure no stale weights.

### Notes
1. The secondary ERC721 Staking system does not interact with p-chain for weight updates. It only accepts upTime messages for setting secondary reward weight.
2. To start validation, validator must stake atleast 20k BEAM and 1 NFT.