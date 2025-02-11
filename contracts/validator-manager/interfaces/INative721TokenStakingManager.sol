// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {IStakingManager} from "./IStakingManager.sol";
import {PChainOwner} from "../ACP99Manager.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";


// TODO; complete interface
/**
 * Proof of Stake Validator Manager that stakes ERC721 tokens.
 */
interface INative721TokenStakingManager is IStakingManager {
    /**
     * @notice Begins the validator registration process. Locks the provided native asset in the contract as the stake.
     * @param nodeID The ID of the node to add to the L1.
     * @param blsPublicKey The BLS public key of the validator.
     * @param registrationExpiry The time after which this message is invalid.
     * @param remainingBalanceOwner The remaining balance owner of the validator.
     * @param disableOwner The disable owner of the validator.
     * @param delegationFeeBips The fee that delegators must pay to delegate to this validator.
     * @param minStakeDuration The minimum amount of time this validator must be staked for in seconds.
     */
    function initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        uint64 registrationExpiry,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256[] memory tokenIDs
    ) external payable returns (bytes32 validationID);

    /**
     * @notice Returns the ERC721 token contract used for staking
     */
    function erc721() external view returns (IERC721);

    /**
    * @notice Registers an NFT delegation for a specified validator and delegator.
    * @dev This function locks the specified NFTs by transferring them to the contract and then registers the delegation 
    *      with the given validator. The NFTs are transferred from the delegator's address to the contract, and the delegation 
    *      is recorded for the specified validator.
    * @param validationID The unique identifier of the validator to which the NFT delegation is being registered.
    * @param delegatorAddress The address of the delegator registering the NFT delegation.
    * @param tokenIDs An array of token IDs representing the NFTs to be locked and delegated.
    * @return delegationID A unique identifier for the newly registered NFT delegation.
    *
    */
    function registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress,
        uint256[] memory tokenIDs
    ) external returns (bytes32);

    /**
    * @notice Redelegates an NFT delegation from one validator to another.
    * @dev This function ends the current NFT delegation, optionally including an uptime proof,
    *      and registers the NFT delegation with a new validator. The NFTs are transferred from the current delegation
    *      to the new validator as part of the redelegation process.
    * @param delegationID The unique identifier of the NFT delegation to be redelegated.
    * @param includeUptimeProof A boolean indicating whether to include an uptime proof during the redelegation process.
    * @param messageIndex The index of the Warp message for obtaining the uptime proof, if `includeUptimeProof` is `true`.
    * @param nextValidationID The unique identifier of the new validator to which the NFTs will be redelegated.
    *
    * Reverts if:
    * - The current delegation cannot be ended or the redelegation cannot be registered.
    */
    function registerNFTRedelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex,
        bytes32 nextValidationID
    ) external;

    /**
    * @notice Initiates the process of ending an NFT delegation for a given delegation ID.
    * @dev This function calls `_initializeEndNFTDelegation` to validate and update the status of the NFT delegation.
    *      It ensures the delegation is active and optionally includes an uptime proof.
    * @param delegationID The unique identifier of the NFT delegation to be ended.
    * @param includeUptimeProof A boolean indicating whether to include an uptime proof during the delegation termination process.
    * @param messageIndex The index of the Warp message for obtaining the uptime proof, if `includeUptimeProof` is `true`.
    */
    function initiateNFTDelegatorRemoval(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external;

    /**
    * @notice Completes the process of ending an NFT delegation and unlocks the associated NFTs.
    * @dev This function validates that the NFT delegation has been marked as `PendingRemoved` and ensures
    *      that the unlock duration has passed. It calls `_completeEndNFTDelegation` to finalize the process
    *      and unlocks the NFTs by transferring them back to the delegator's address.
    * @param delegationID The unique identifier of the NFT delegation to be completed.
    *
    */
    function completeNFTDelegatorRemoval(
        bytes32 delegationID
    ) external;
}