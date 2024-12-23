// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {ValidatorRegistrationInput} from "./IValidatorManager.sol";
import {IPoSValidatorManager} from "./IPoSValidatorManager.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * Proof of Stake Validator Manager that stakes ERC721 tokens.
 */
interface IERC721TokenStakingManager is IPoSValidatorManager {
    /**
     * @notice Begins the validator registration process. Locks the specified ERC721 token in the contract as the stake.
     * @param registrationInput The inputs for a validator registration.
     * @param delegationFeeBips The fee that delegators must pay to delegate to this validator.
     * @param minStakeDuration The minimum amount of time this validator must be staked for in seconds.
     * @param tokenId The ID of the NFT to stake.
     */
    function initializeValidatorRegistration(
        ValidatorRegistrationInput calldata registrationInput,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 tokenId
    ) external returns (bytes32 validationID);

    /**
     * @notice Begins the delegator registration process. Locks the specified ERC721 token in the contract as the stake.
     * @param validationID The ID of the validator to stake to.
     * @param tokenId The ID of the NFT to stake.
     */
    function initializeDelegatorRegistration(
        bytes32 validationID,
        uint256 tokenId
    ) external returns (bytes32);

    /**
     * @notice Returns the ERC721 token contract used for staking
     */
    function erc721() external view returns (IERC721);

    /**
     * @notice Returns the ERC20 token contract used for rewards
     */
    function rewardToken() external view returns (IERC20);

    /**
     * @notice Funds the contract with reward tokens
     * @param amount Amount of reward tokens to transfer to the contract
     */
    function fundRewards(uint256 amount) external;
}