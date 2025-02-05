// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {IValidatorManager, ValidatorManagerSettings} from "./IValidatorManager.sol";
import {IRewardCalculator} from "./IRewardCalculator.sol";
import {IBalanceTracker} from "@euler-xyz/reward-streams@1.0.0/interfaces/IBalanceTracker.sol";

/**
 * @dev Delegator status
 */
enum DelegatorStatus {
    Unknown,
    PendingAdded,
    Active,
    PendingRemoved
}

/**
 * @notice PoS Validator Manager settings, used to initialize the PoS Validator Manager
 * @notice baseSettings specified the base settings for the Validator Manager. See {IValidatorManager-ValidatorManagerSettings}
 * @notice minimumStakeAmount is the minimum amount of stake required to stake to a validator
 * @notice maximumStakeAmount is the maximum amount of stake that can be staked to a validator
 * @notice minimumStakeDuration is the minimum duration that validators must stake for
 * @notice minimumDelegationFeeBips is the minimum delegation fee in basis points that validators can charge
 * @notice maximumStakeMultiplier is the multiplier applied to validator's initial stake amount to determine
 * the maximum amount of stake a validator can have with delegations.
 * @notice weightToValueFactor is the factor used to convert validator weight to value
 * @notice rewardCalculator is the reward calculator used to calculate rewards for this validator manager
 * @notice uptimeBlockchainID is the ID of the blockchain that submits uptime proofs.
 * This must be a blockchain validated by the l1ID that this contract manages.
 */
struct PoSValidatorManagerSettings {
    ValidatorManagerSettings baseSettings;
    uint256 minimumStakeAmount;
    uint256 maximumStakeAmount;
    uint64 minimumStakeDuration;
    uint64 unlockDuration;
    uint16 minimumDelegationFeeBips;
    uint8 maximumStakeMultiplier;
    uint256 weightToValueFactor;
    IBalanceTracker balanceTracker;
    uint64 epochDuration;
    bytes32 uptimeBlockchainID;
}

/**
 * @dev Contains the active state of a Delegator
 */
struct Delegator {
    DelegatorStatus status;
    address owner;
    bytes32 validationID;
    uint64 weight;
    uint64 startedAt;
    uint64 endedAt;
    uint64 startingNonce;
    uint64 endingNonce;
}

struct DelegatorNFT {
    DelegatorStatus status;
    address owner;
    bytes32 validationID;
    uint64 weight;
    uint64 startedAt;
    uint64 endedAt;
    uint256[] tokenIDs;
}

/**
 * @dev Describes the active state of a PoS Validator in addition the information in {IValidatorManager-Validator}
 */
struct PoSValidatorInfo {
    address owner;
    uint16 delegationFeeBips;
    uint64 minStakeDuration;
    uint64 uptimeSeconds;
    uint64 currentEpoch;
    uint64 prevEpochUptimeSeconds;
    uint64 weight;
    uint256[] tokenIDs;
    uint64 nftWeight;
}

/**
 * @notice Interface for Proof of Stake Validator Managers
 */
interface IPoSValidatorManager is IValidatorManager {
    /**
     * @notice Event emitted when a delegator registration is initiated
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validation period being delegated to
     * @param delegatorAddress The address of the delegator
     * @param nonce The message nonce used to update the validator weight
     * @param validatorWeight The updated validator weight that is sent to the P-Chain
     * @param delegatorWeight The weight of the delegator
     * @param setWeightMessageID The ID of the ICM message that updates the validator's weight on the P-Chain
     */
    event DelegatorAdded(
        bytes32 indexed delegationID,
        bytes32 indexed validationID,
        address indexed delegatorAddress,
        uint64 nonce,
        uint64 validatorWeight,
        uint64 delegatorWeight,
        bytes32 setWeightMessageID
    );

     /**
     * @notice Event emitted when a NFT delegator is added 
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validation period being delegated to
     * @param delegatorAddress The address of the delegator
     * @param nonce The message nonce used to update the validator weight
     * @param delegatorWeight The weight of the delegator
     * @param tokenIDs The list of tokenIDs delegated
     */
    event DelegatorAddedNFT(
        bytes32 indexed delegationID,
        bytes32 indexed validationID,
        address indexed delegatorAddress,
        uint64 nonce,
        uint64 delegatorWeight,
        uint256[] tokenIDs
    );

    /**
     * @notice Event emitted when a delegator registration is completed
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validation period
     * @param startTime The time at which the registration was completed
     */
    event DelegatorRegistered(
        bytes32 indexed delegationID, bytes32 indexed validationID, uint256 startTime
    );

    /**
     * @notice Event emitted when delegator removal is initiated
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validation period the delegator was staked to
     */
    event DelegatorRemovalInitialized(bytes32 indexed delegationID, bytes32 indexed validationID);

    /**
     * @notice Event emitted when delegator removal is completed
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validator the delegator was staked to
     * @param rewards The rewards given to the delegator
     * @param fees The portion of the delegator's rewards paid to the validator
     */
    event DelegationEnded(
        bytes32 indexed delegationID, bytes32 indexed validationID, uint256 rewards, uint256 fees
    );

    /**
     * @notice Event emitted when the uptime of a validator is updated. Only emitted when the uptime is greater than the stored uptime.
     * @param validationID The ID of the validation period
     * @param uptime The updated uptime of the validator
     * @param epoch The epoch of updation
     */
    event UptimeUpdated(bytes32 indexed validationID, uint64 uptime, uint64 epoch);

    /**
     * @notice Updates the uptime of the validationID if the submitted proof is greated than the stored uptime.
     * Anybody may call this function to ensure the stored uptime is accurate. Callable only when the validation period is active.
     * @param validationID The ID of the validation period
     * @param messageIndex The index of the ICM message to be received providing the uptime proof
     */
    function submitUptimeProof(bytes32 validationID, uint32 messageIndex) external;

    /**
     * @notice Begins the process of ending an active validation period, and reverts if the validation period is not eligible
     * for uptime-based rewards. This function is used to exit the validator set when rewards are expected.
     * The validation period must have been previously started by a successful call to {completeValidatorRegistration} with the given validationID.
     * Any rewards for this validation period will stop accruing when this function is called.
     * Note: Reverts if the uptime is not eligible for rewards.
     * @param validationID The ID of the validation period being ended.
     * @param includeUptimeProof Whether or not an uptime proof is provided for the validation period. If no uptime proof is provided,
     * the latest known uptime will be used.
     * @param messageIndex The index of the ICM message to be received providing the uptime proof.
     */
    function initializeEndValidation(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external;

    /**
     * @notice Completes the delegator registration process by submitting an acknowledgement of the registration of a
     * validationID from the P-Chain. After this function is called, the validator's weight is updated in the contract state.
     * Any P-Chain acknowledgement with a nonce greater than or equal to the nonce used to initialize registration of the
     * delegator is valid, as long as that nonce has been sent by the contract. For the purposes of computing delegation rewards,
     * the delegation is considered active after this function is completed.
     * Note: Only the specified delegation will be marked as registered, even if the validator weight update
     * message implicitly includes multiple weight changes.
     * @param delegationID The ID of the delegation being registered.
     * @param messageIndex The index of the ICM message to be received providing the acknowledgement.
     */
    function completeDelegatorRegistration(bytes32 delegationID, uint32 messageIndex) external;

    /**
     * @notice Begins the process of removing a delegator from a validation period, and reverts if the delegation is not eligible for rewards.
     * The delegator must have been previously registered with the given validationID. For the purposes of computing delegation rewards,
     * the delegation period is considered ended when this function is called. Uses the supplied uptime proof to calculate rewards.
     * If none is provided in the call, the latest known uptime will be used. Reverts if the uptime is not eligible for rewards.
     * Note: This function can only be called by the address that registered the delegation.
     * Note: Reverts if the uptime is not eligible for rewards.
     * @param delegationID The ID of the delegation being removed.
     * @param includeUptimeProof Whether or not an uptime proof is provided for the validation period.
     * If the validator has completed its validation period, it has already provided an uptime proof, so {includeUptimeProof}
     * will be ignored and can be set to false. If the validator has not completed its validation period and no uptime proof
     * is provided, the latest known uptime will be used.
     * @param messageIndex If {includeUptimeProof} is true, the index of the ICM message to be received providing the
     * uptime proof.
     */
    function initializeEndDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external;

    /**
     * @notice Resubmits a delegator registration or delegator end message to be sent to the P-Chain.
     * Only necessary if the original message can't be delivered due to validator churn.
     * @param delegationID The ID of the delegation.
     */
    function resendUpdateDelegation(bytes32 delegationID) external;

    /**
     * @notice Completes the process of ending a delegation by receiving an acknowledgement from the P-Chain.
     * After this function is called, the validator's weight is updated in the contract state.
     * Any P-Chain acknowledgement with a nonce greater than or equal to the nonce used to initialize the end of the
     * delegator's delegation is valid, as long as that nonce has been sent by the contract. This is because the validator
     * weight change pertaining to the delegation ending is included in any subsequent validator weight update messages.
     * Note: Only the specified delegation will be marked as completed, even if the validator weight update
     * message implicitly includes multiple weight changes.
     * @param delegationID The ID of the delegation being removed.
     * @param messageIndex The index of the ICM message to be received providing the acknowledgement.
     */
    function completeEndDelegation(bytes32 delegationID, uint32 messageIndex) external;

    function getPoSValidatorInfo(bytes32 validationID) external view returns (PoSValidatorInfo memory);
}
