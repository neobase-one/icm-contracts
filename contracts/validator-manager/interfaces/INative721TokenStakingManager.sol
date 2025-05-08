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
     * @notice Event emitted when a delegator registration is an NFT delegation
     * @param delegationID The ID of the delegation
     * @param tokenIDs List of tokenIDs that are being delegated
    **/
    event DelegatedNFTs(
        bytes32 indexed delegationID,
        uint256[] tokenIDs
    );

    /**
     * @notice Event emitted when reward is registered
     * @param primary True if the reward is primary, false if secondary
     * @param epoch The epoch for which the reward is being registered
     * @param token The reward token
     * @param amount The amount of the reward
    **/
    event RewardRegistered(
        bool primary,
        uint64 epoch,
        address token,
        uint256 amount
    );

    /**
    * @notice Event emitted when a reward is cancelled
    * @param primary True if the reward is primary, false if secondary
    * @param epoch The epoch for which the reward is being cancelled
    * @param token The reward token
    **/
    event RewardCancelled(
        bool primary,
        uint64 epoch,
        address token
    );

    event RewardClaimed(
        bool primary,
        uint64 epoch,
        address account,
        address token,
        uint256 amount
    );

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
     * @notice Initiates the registration of a delegator for staking with a validator.
     * @dev Calls the internal function `_initiateDelegatorRegistration` to handle the registration process.
     * The function locks the sent Ether as stake and associates it with the validator.
     * @param validationID The unique identifier of the validator to delegate to.
     * @return The delegation ID, which uniquely identifies this delegation.
     */
    function initiateDelegatorRegistration(
        bytes32 validationID
    ) external payable returns (bytes32);

    /**
     * @notice Claims rewards for the caller from a specified epoch and transfers them to a recipient.
     * @dev The function ensures the claim period has started before allowing withdrawals.
     * @param primary A boolean indicating whether to claim from the primary reward pool (true) or the NFT pool (false).
     * @param epoch The staking epoch for which to claim rewards.
     * @param tokens An array of token addresses to claim rewards for.
     * @param recipient The address that will receive the claimed rewards.
     *
     * Requirements:
     * - The claim period must have started (i.e., `block.timestamp` must be past the reward claim delay).
     * - The caller must have earned rewards in the specified epoch.
     * - The function updates the withdrawn reward balance to prevent double claims.
     *
     * Emits:
     * - Transfers the claimed rewards to the recipient.
     */
    function claimRewards(
        bool primary,
        uint64 epoch,
        address[] memory tokens,
        address recipient
    ) external;

    /**
     * @notice Registers a reward amount for a specific epoch and token.
     * @dev This function allows the contract owner to deposit rewards into the system.
     * @param primary A boolean indicating whether to register in the primary reward pool (true) or the NFT pool (false).
     * @param epoch The staking epoch for which rewards are being registered.
     * @param token The address of the token being allocated as a reward.
     * @param amount The amount of the token to be distributed as rewards.
     *
     * Requirements:
     * - Only the contract owner can call this function.
     * - The function transfers the specified reward amount from the sender to the contract.
     *
     * Emits:
     * - `RewardRegistered` event upon successfully registering the reward.
     */
    function registerRewards(
        bool primary,
        uint64 epoch,
        address token,
        uint256 amount
    ) external;

    /**
     * @notice Cancels previously registered rewards before the claim period starts.
     * @dev The function allows the contract owner to withdraw unclaimed rewards if the claim period has not begun.
     * @param primary A boolean indicating whether to cancel from the primary reward pool (true) or the NFT pool (false).
     * @param epoch The staking epoch for which rewards should be canceled.
     * @param token The address of the token whose rewards should be canceled.
     *
     * Requirements:
     * - Only the contract owner can call this function.
     * - The cancellation must happen before the claim period starts (`block.timestamp` must be before the reward claim delay).
     *
     * Emits:
     * - `RewardCancelled` event upon successfully canceling the reward.
     */
    function cancelRewards(
        bool primary,
        uint64 epoch,
        address token
    ) external;

    /**
     * @notice Submits multiple uptime proofs for validation and processing.
     * @dev This function iterates through a list of validation IDs and their corresponding warp message indexes,
     *      calling `_updateUptime` for each one to update their recorded uptime.
     * @param validationIDs An array of validator IDs whose uptime proofs are being submitted.
     * @param messageIndexes An array of corresponding warp message indexes containing the uptime proofs.
     *
     * Requirements:
     * - The `validationIDs` and `messageIndexes` arrays must have the same length.
     * - The function can only be called by the contract owner.
     *
     * Reverts:
     * - `InvalidInputLengths` if the input arrays have different lengths.
     */
    function submitUptimeProofs(bytes32[] memory validationIDs, uint32[] memory messageIndexes) external;

    /**
    * @notice Registers an NFT delegation for a specified validator and delegator.
    * @dev This function locks the specified NFTs by transferring them to the contract and then registers the delegation 
    *      with the given validator. The NFTs are transferred from the delegator's address to the contract, and the delegation 
    *      is recorded for the specified validator.
    * @param validationID The unique identifier of the validator to which the NFT delegation is being registered.
    * @param tokenIDs An array of token IDs representing the NFTs to be locked and delegated.
    * @return delegationID A unique identifier for the newly registered NFT delegation.
    *
    */
    function registerNFTDelegation(
        bytes32 validationID,
        uint256[] memory tokenIDs
    ) external returns (bytes32);

    /**
    * @notice Redelegates an NFT delegation from one validator to another.
    * @dev This function ends the current NFT delegation, optionally including an uptime proof,
    *      and registers the NFT delegation with a new validator. The NFTs are transferred from the current delegation
    *      to the new validator as part of the redelegation process.
    * @param delegationID The unique identifier of the NFT delegation to be redelegated.
    * @param nextValidationID The unique identifier of the new validator to which the NFTs will be redelegated.
    *
    * Reverts if:
    * - The current delegation cannot be ended or the redelegation cannot be registered.
    */
    function registerNFTRedelegation(
        bytes32 delegationID,
        bytes32 nextValidationID
    ) external;

    /**
    * @notice Initiates the process of ending an NFT delegation for a given delegation ID.
    * @dev This function calls `_initializeEndNFTDelegation` to validate and update the status of the NFT delegation.
    *      It ensures the delegation is active and optionally includes an uptime proof.
    * @param delegationID The unique identifier of the NFT delegation to be ended.
    */
    function initiateNFTDelegatorRemoval(
        bytes32 delegationID
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

    /**
     * @notice Returns the ERC721 token contract used for staking
     */
    function erc721() external view returns (IERC721);
}
