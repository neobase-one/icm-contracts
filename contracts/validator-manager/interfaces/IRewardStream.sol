// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

/**
 * @notice Interface for reward streams
 */
interface IRewardStream {
   /// @notice Executes the balance tracking hook for an account
    /// @param account The account address to execute the hook for
    /// @param newAccountBalance The new balance of the account
    /// @param forfeitRecentReward Whether to forfeit the most recent reward and not update the accumulator. Ignored
    /// when the new balance is greater than the current balance.
  function balanceTrackerHook(
        address account,
        uint256 newAccountBalance,
        bool forfeitRecentReward
    ) external;

  function hasRewards(address account) external view returns (bool);  
}
