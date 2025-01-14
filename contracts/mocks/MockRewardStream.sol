// SPDX-License-Identifier: Ecosystem
pragma solidity 0.8.25;

import {IRewardStream} from "../validator-manager/interfaces/IRewardStream.sol";

contract MockRewardStream is IRewardStream {
    mapping(address => uint256) public balances;
    
    event BalanceUpdated(
        address indexed account,
        address indexed rewarded,
        uint256 oldBalance,
        uint256 newBalance
    );

    function balanceTrackerHook(
        address account,
        uint256 amount,
        bool isDelegator
    ) external  {
        uint256 currentBalance = balances[account];
        
        if (amount > currentBalance) {
            isDelegator = false;
        }

        balances[account] = amount;

        emit BalanceUpdated(account, msg.sender, currentBalance, amount);
    }

    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }

    function hasRewards(address account) external view returns (bool) {
        return true; // TODO: need to change this for testcases
    }
}