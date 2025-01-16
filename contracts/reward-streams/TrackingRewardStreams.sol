// SPDX-License-Identifier: GPL-2.0-or-later

pragma solidity ^0.8.0;

import {Set, SetStorage} from "evc/Set.sol";
import {BaseRewardStreams} from "./BaseRewardStreams.sol";
import {ITrackingRewardStreams} from "./interfaces/IRewardStreams.sol";

/// @title TrackingRewardStreams
/// @custom:security-contact security@euler.xyz
/// @author Euler Labs (https://www.eulerlabs.com/)
/// @notice This contract inherits from `BaseRewardStreams` and implements `ITrackingRewardStreams`.
/// It allows for the rewards to be distributed to the rewarded token holders without requiring explicit staking.
/// The rewarded token contract must implement `IBalanceTracker` and the `balanceTrackerHook` function.
/// `balanceTrackerHook` must be called with:
/// - the account's new balance when account's balance changes,
/// - the current account's balance when the balance forwarding is enabled,
/// - the account's balance of 0 when the balance forwarding is disabled.
contract TrackingRewardStreams is BaseRewardStreams, ITrackingRewardStreams {
    using Set for SetStorage;

    /// @notice Constructor for the TrackingRewardStreams contract.
    /// @param evc The Ethereum Vault Connector contract.
    /// @param epochDuration The duration of an epoch.
    constructor(address evc, uint48 epochDuration) BaseRewardStreams(evc, epochDuration) {}

    /// @notice Executes the balance tracking hook for an account
    /// @param account The account address to execute the hook for
    /// @param newAccountBalance The new balance of the account
    /// @param forfeitRecentReward Whether to forfeit the most recent reward and not update the accumulator. Ignored
    /// when the new balance is greater than the current balance.
    function balanceTrackerHook(
        address account,
        uint256 newAccountBalance,
        bool forfeitRecentReward
    ) external override {
        address rewarded = msg.sender;
        AccountStorage storage accountStorage = accounts[account][rewarded];
        uint256 currentAccountBalance = accountStorage.balance;
        address[] memory rewards = accountStorage.enabledRewards.get();

        if (newAccountBalance > currentAccountBalance) forfeitRecentReward = false;

        for (uint256 i = 0; i < rewards.length; ++i) {
            address reward = rewards[i];
            DistributionStorage storage distributionStorage = distributions[rewarded][reward];

            // We always allocate rewards before updating any balances.
            updateRewardInternal(
                distributionStorage,
                accountStorage.earned[reward],
                rewarded,
                reward,
                currentAccountBalance,
                forfeitRecentReward
            );

            distributionStorage.totalEligible =
                distributionStorage.totalEligible + newAccountBalance - currentAccountBalance;
        }

        accountStorage.balance = newAccountBalance;

        emit BalanceUpdated(account, rewarded, currentAccountBalance, newAccountBalance);
    }

    /// @notice Checks if an account has any unclaimed rewards for a given rewarded token
    /// @param account The account address to check
    /// @param rewarded The rewarded token address
    /// @return bool True if the account has any unclaimed rewards
    function hasRewards(address account, address rewarded) external view returns (bool) {
        // Get all enabled reward tokens for this account and rewarded token
        address[] memory enabled = enabledRewards(account, rewarded);
        
        // Check each enabled reward token for any earned rewards
        for (uint256 i = 0; i < enabled.length; i++) {
            if (earnedReward(account, rewarded, enabled[i], false) > 0) {
                return true;
            }
        }
        
        return false;
    }

    /// @notice Claims all rewards for an account from a specific rewarded token
    /// @param account The account to claim rewards for
    /// @param recipient The address to receive the rewards
    /// @return amounts The amounts of rewards claimed for each reward token
    function claim(
        address account,
        address recipient
    ) external returns (uint256[] memory amounts) {
        address rewarded = msg.sender;
        AccountStorage storage accountStorage = accounts[account][rewarded];
        address[] memory rewards = accountStorage.enabledRewards.get();
        amounts = new uint256[](rewards.length);

        for (uint256 i = 0; i < rewards.length; ++i) {
            amounts[i] = claimReward(account, rewarded, rewards[i], recipient, false);
        }

        return amounts;
    }

    /// @notice Claims a specific reward token for an account
    /// @param account The account to claim rewards for
    /// @param rewarded The rewarded token address
    /// @param reward The reward token to claim
    /// @param recipient The address to receive the rewards
    /// @param ignoreRecentReward Whether to ignore the most recent reward
    /// @return The amount of rewards claimed
    function claimReward(
        address account,
        address rewarded,
        address reward,
        address recipient,
        bool ignoreRecentReward
    ) public returns (uint256) {

        // If the account disables the rewards we pass an account balance of zero to not accrue any.
        AccountStorage storage accountStorage = accounts[account][rewarded];
        uint256 currentAccountBalance = accountStorage.enabledRewards.contains(reward) ? accountStorage.balance : 0;

        updateRewardInternal(
            distributions[rewarded][reward],
            accountStorage.earned[reward],
            rewarded,
            reward,
            currentAccountBalance,
            ignoreRecentReward
        );

        return claim(account, rewarded, reward, recipient);
    }
}
