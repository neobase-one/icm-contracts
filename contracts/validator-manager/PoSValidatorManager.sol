// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {ValidatorManager} from "./ValidatorManager.sol";
import {ValidatorMessages} from "./ValidatorMessages.sol";
import {
    Delegator,
    DelegatorNFT,
    DelegatorStatus,
    IPoSValidatorManager,
    PoSValidatorInfo,
    PoSValidatorManagerSettings
} from "./interfaces/IPoSValidatorManager.sol";
import {
    Validator,
    ValidatorRegistrationInput,
    ValidatorStatus
} from "./interfaces/IValidatorManager.sol";
import {IRewardCalculator} from "./interfaces/IRewardCalculator.sol";
import {IERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/utils/SafeERC20.sol";
import {IBalanceTracker} from "@euler-xyz/reward-streams@1.0.0/interfaces/IBalanceTracker.sol";
import {WarpMessage} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";
import {ReentrancyGuardUpgradeable} from
    "@openzeppelin/contracts-upgradeable@5.0.2/utils/ReentrancyGuardUpgradeable.sol";
import {PoSUtils } from "./PoSUtils.sol";

/**
 * @dev Implementation of the {IPoSValidatorManager} interface.
 *
 * @custom:security-contact https://github.com/ava-labs/icm-contracts/blob/main/SECURITY.md
 */
abstract contract PoSValidatorManager is
    IPoSValidatorManager,
    ValidatorManager,
    ReentrancyGuardUpgradeable
{
    // solhint-disable private-vars-leading-underscore
    /// @custom:storage-location erc7201:avalanche-icm.storage.PoSValidatorManager
    struct PoSValidatorManagerStorage {
        /// @notice The minimum amount of stake required to be a validator.
        uint256 _minimumStakeAmount;
        /// @notice The maximum amount of stake allowed to be a validator.
        uint256 _maximumStakeAmount;
        /// @notice The minimum amount of stake required to be a validator.
        uint256 _minimumNFTAmount;
        /// @notice The maximum amount of stake allowed to be a validator.
        uint256 _maximumNFTAmount;
        /// @notice The minimum amount of time in seconds a validator must be staked for. Must be at least {_churnPeriodSeconds}.
        uint64 _minimumStakeDuration;
        /// @notice The minimum delegation fee percentage, in basis points, required to delegate to a validator.
        uint16 _minimumDelegationFeeBips;
        /// @notice The duration in seconds after a delegator's delegation is ended before the delegator's stake is unlocked.
        uint64 _unlockDelegateDuration;
        /**
         * @notice A multiplier applied to validator's initial stake amount to determine
         * the maximum amount of stake a validator can have with delegations.
         * Note: Setting this value to 1 would disable delegations to validators, since
         * the maximum stake would be equal to the initial stake.
         */
        uint64 _maximumStakeMultiplier;
        /// @notice The factor used to convert between weight and value.
        uint256 _weightToValueFactor;
        /// @notice The reward stream balance tracker for this validator manager.
        IBalanceTracker _balanceTracker;
        /// @notice The reward stream balance tracker for this validator manager.
        IBalanceTracker _balanceTrackerNFT;
        /// @notice The duration of an epoch in seconds
        uint64 _epochDuration;
        /// @notice The ID of the blockchain that submits uptime proofs. This must be a blockchain validated by the l1ID that this contract manages.
        bytes32 _uptimeBlockchainID;
        /// @notice Maps the validation ID to its requirements.
        mapping(bytes32 validationID => PoSValidatorInfo) _posValidatorInfo;
        /// @notice Maps the delegation ID to the delegator information.
        mapping(bytes32 delegationID => Delegator) _delegatorStakes;
        /// @notice Maps the delegation ID to the delegator information.
        mapping(bytes32 delegationID => DelegatorNFT) _delegatorNFTStakes;
        /// @notice Maps validation ID to array of delegation IDs
        mapping(bytes32 validationID => bytes32[]) _validatorDelegations;
        /// @notice Maps validation ID to array of delegation IDs
        mapping(bytes32 validationID => bytes32[]) _validatorNFTDelegations;
        /// @notice Maps account to array of validationIDs
        mapping(address => bytes32[]) _accountValidations;
        /// @notice Maps account to array of delegationIDs
        mapping(address => bytes32[]) _accountDelegations;
        /// @notice Maps account to array of delegationIDs
        mapping(address => bytes32[]) _accountNFTDelegations;
    }
    // solhint-enable private-vars-leading-underscore

    // keccak256(abi.encode(uint256(keccak256("avalanche-icm.storage.PoSValidatorManager")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 public constant POS_VALIDATOR_MANAGER_STORAGE_LOCATION =
        0x4317713f7ecbdddd4bc99e95d903adedaa883b2e7c2551610bd13e2c7e473d00;

    uint8 public constant MAXIMUM_STAKE_MULTIPLIER_LIMIT = 10;

    uint16 public constant MAXIMUM_DELEGATION_FEE_BIPS = 10000;

    uint16 public constant BIPS_CONVERSION_FACTOR = 10000;

    error InvalidDelegationFee(uint16 delegationFeeBips);
    error InvalidDelegationID(bytes32 delegationID);
    error InvalidDelegatorStatus(DelegatorStatus status);
    error InvalidNonce(uint64 nonce);
    error InvalidStakeAmount(uint256 stakeAmount);
    error InvalidMinStakeDuration(uint64 minStakeDuration);
    error InvalidStakeMultiplier(uint8 maximumStakeMultiplier);
    error MaxWeightExceeded(uint64 newValidatorWeight);
    error MinStakeDurationNotPassed(uint64 endTime);
    error UnlockDelegateDurationNotPassed(uint64 endTime);
    error UnauthorizedOwner(address sender);
    error ValidatorNotPoS(bytes32 validationID);
    error ZeroWeightToValueFactor();
    error InvalidUptimeBlockchainID(bytes32 uptimeBlockchainID);

    // solhint-disable ordering
    /**
     * @dev This storage is visible to child contracts for convenience.
     *      External getters would be better practice, but code size limitations are preventing this.
     *      Child contracts should probably never write to this storage.
     */
    function _getPoSValidatorManagerStorage()
        internal
        pure
        returns (PoSValidatorManagerStorage storage $)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := POS_VALIDATOR_MANAGER_STORAGE_LOCATION
        }
    }

    // solhint-disable-next-line func-name-mixedcase
    function __POS_Validator_Manager_init(PoSValidatorManagerSettings calldata settings)
        internal
        onlyInitializing
    {
        __ValidatorManager_init(settings.baseSettings);
        __ReentrancyGuard_init();
        __POS_Validator_Manager_init_unchained({
            minimumStakeAmount: settings.minimumStakeAmount,
            maximumStakeAmount: settings.maximumStakeAmount,
            minimumStakeDuration: settings.minimumStakeDuration,
            unlockDelegateDuration: settings.unlockDelegateDuration,
            minimumDelegationFeeBips: settings.minimumDelegationFeeBips,
            maximumStakeMultiplier: settings.maximumStakeMultiplier,
            weightToValueFactor: settings.weightToValueFactor,
            rewardCalculator: settings.rewardCalculator,
            balanceTracker: settings.balanceTracker,
            balanceTrackerNFT: settings.balanceTrackerNFT,
            epochDuration: settings.epochDuration,
            minimumNFTAmount: settings.minimumNFTAmount,
            maximumNFTAmount: settings.maximumNFTAmount,
            uptimeBlockchainID: settings.uptimeBlockchainID
        });
    }

    // solhint-disable-next-line func-name-mixedcase
    function __POS_Validator_Manager_init_unchained(
        uint256 minimumStakeAmount,
        uint256 maximumStakeAmount,
        uint64 minimumStakeDuration,
        uint64 unlockDelegateDuration,
        uint16 minimumDelegationFeeBips,
        uint8 maximumStakeMultiplier,
        uint256 weightToValueFactor,
        IRewardCalculator rewardCalculator,
        IBalanceTracker balanceTracker,
        IBalanceTracker balanceTrackerNFT,
        uint64 epochDuration,
        uint256 minimumNFTAmount,
        uint256 maximumNFTAmount,
        bytes32 uptimeBlockchainID
    ) internal onlyInitializing {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        if (minimumDelegationFeeBips == 0 || minimumDelegationFeeBips > MAXIMUM_DELEGATION_FEE_BIPS)
        {
            revert InvalidDelegationFee(minimumDelegationFeeBips);
        }
        if (minimumStakeAmount > maximumStakeAmount) {
            revert InvalidStakeAmount(minimumStakeAmount);
        }
        if (maximumStakeMultiplier == 0 || maximumStakeMultiplier > MAXIMUM_STAKE_MULTIPLIER_LIMIT)
        {
            revert InvalidStakeMultiplier(maximumStakeMultiplier);
        }
        // Minimum stake duration should be at least one churn period in order to prevent churn tracker abuse.
        if (minimumStakeDuration < _getChurnPeriodSeconds()) {
            revert InvalidMinStakeDuration(minimumStakeDuration);
        }
        if (weightToValueFactor == 0) {
            revert ZeroWeightToValueFactor();
        }
        if (uptimeBlockchainID == bytes32(0)) {
            revert InvalidUptimeBlockchainID(uptimeBlockchainID);
        }

        $._minimumStakeAmount = minimumStakeAmount;
        $._maximumStakeAmount = maximumStakeAmount;
        $._minimumStakeDuration = minimumStakeDuration;
        $._minimumNFTAmount = minimumNFTAmount;
        $._maximumNFTAmount = maximumNFTAmount;
        $._minimumDelegationFeeBips = minimumDelegationFeeBips;
        $._maximumStakeMultiplier = maximumStakeMultiplier;
        $._weightToValueFactor = weightToValueFactor;
        $._balanceTracker = balanceTracker;
        $._balanceTrackerNFT = balanceTrackerNFT;
        $._epochDuration = epochDuration;
        $._uptimeBlockchainID = uptimeBlockchainID;
        $._unlockDelegateDuration = unlockDelegateDuration;
    }

    /**
     * @notice See {IPoSValidatorManager-submitUptimeProof}.
     */
    function submitUptimeProof(bytes32 validationID, uint32 messageIndex) external {
        if (!_isPoSValidator(validationID)) {
            revert ValidatorNotPoS(validationID);
        }
        ValidatorStatus status = getValidator(validationID).status;
        if (status != ValidatorStatus.Active) {
            revert InvalidValidatorStatus(status);
        }

        // Uptime proofs include the absolute number of seconds the validator has been active.
        _updateUptime(validationID, messageIndex);
    }

    /**
     * @notice See {IPoSValidatorManager-initializeEndValidation}.
     */
    function initializeEndValidation(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external {
        _initializeEndPoSValidation(validationID, includeUptimeProof, messageIndex);
    }

    /**
     * @dev Helper function that initializes the end of a PoS validation period.
     * Returns false if it is possible for the validator to claim rewards, but it is not eligible.
     * Returns true otherwise.
     */
    function _initializeEndPoSValidation(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        Validator memory validator = _initializeEndValidation(validationID);

        // Non-PoS validators are required to boostrap the network, but are not eligible for rewards.
        if (!_isPoSValidator(validationID)) {
            return;
        }

        // PoS validations can only be ended by their owners.
        if ($._posValidatorInfo[validationID].owner != _msgSender()) {
            revert UnauthorizedOwner(_msgSender());
        }

        // Check that minimum stake duration has passed.
        if (
            validator.endedAt
                < validator.startedAt + $._posValidatorInfo[validationID].minStakeDuration
        ) {
            revert MinStakeDurationNotPassed(validator.endedAt);
        }

        // Uptime proofs include the absolute number of seconds the validator has been active.
        uint64 uptimeSeconds;
        if (includeUptimeProof) {
            uptimeSeconds = _updateUptime(validationID, messageIndex);
        } else {
            uptimeSeconds = $._posValidatorInfo[validationID].uptimeSeconds;
        }
    }

    /**
     * @notice See {IValidatorManager-completeEndValidation}.
     */
    function completeEndValidation(uint32 messageIndex) external virtual nonReentrant {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        (bytes32 validationID, Validator memory validator) = _completeEndValidation(messageIndex);

        // Return now if this was originally a PoA validator that was later migrated to this PoS manager,
        // or the validator was part of the initial validator set.
        if (!_isPoSValidator(validationID)) {
            return;
        }

        // The stake is unlocked whether the validation period is completed or invalidated.
        _unlock($._posValidatorInfo[validationID].owner, weightToValue(validator.startingWeight));
    }

    /**
     * @dev Helper function that extracts the uptime from a ValidationUptimeMessage Warp message
     * If the uptime is greater than the stored uptime, update the stored uptime.
     */
    function _updateUptime(bytes32 validationID, uint32 messageIndex) virtual internal returns (uint64) {
        (WarpMessage memory warpMessage, bool valid) =
            WARP_MESSENGER.getVerifiedWarpMessage(messageIndex);
        if (!valid) {
            revert InvalidWarpMessage();
        }

        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        // The uptime proof must be from the specifed uptime blockchain
        if (warpMessage.sourceChainID != $._uptimeBlockchainID) {
            revert InvalidWarpSourceChainID(warpMessage.sourceChainID);
        }

        // The sender is required to be the zero address so that we know the validator node
        // signed the proof directly, rather than as an arbitrary on-chain message
        if (warpMessage.originSenderAddress != address(0)) {
            revert InvalidWarpOriginSenderAddress(warpMessage.originSenderAddress);
        }
        if (warpMessage.originSenderAddress != address(0)) {
            revert InvalidWarpOriginSenderAddress(warpMessage.originSenderAddress);
        }

        (bytes32 uptimeValidationID, uint64 uptime) =
            ValidatorMessages.unpackValidationUptimeMessage(warpMessage.payload);
        if (validationID != uptimeValidationID) {
            revert InvalidValidationID(validationID);
        }

        if (uptime > $._posValidatorInfo[validationID].uptimeSeconds) {
            $._posValidatorInfo[validationID].uptimeSeconds = uptime;
            emit UptimeUpdated(validationID, uptime, 0);
        } else {
            uptime = $._posValidatorInfo[validationID].uptimeSeconds;
        }

        return uptime;
    }

    function _initializeValidatorRegistration(
        ValidatorRegistrationInput calldata registrationInput,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 stakeAmount
    ) internal virtual returns (bytes32) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        // Validate and save the validator requirements
        if (
            delegationFeeBips < $._minimumDelegationFeeBips
                || delegationFeeBips > MAXIMUM_DELEGATION_FEE_BIPS
        ) {
            revert InvalidDelegationFee(delegationFeeBips);
        }

        if (minStakeDuration < $._minimumStakeDuration) {
            revert InvalidMinStakeDuration(minStakeDuration);
        }

        // Ensure the stake amount is within the valid range.
        if (stakeAmount < $._minimumStakeAmount || stakeAmount > $._maximumStakeAmount) {
            revert InvalidStakeAmount(stakeAmount);
        }

        // Lock the stake in the contract.
        uint256 lockedValue = _lock(stakeAmount);

        uint64 weight = valueToWeight(lockedValue);
        bytes32 validationID = _initializeValidatorRegistration(registrationInput, weight);

        address owner = _msgSender();

        $._posValidatorInfo[validationID].owner = owner;
        $._posValidatorInfo[validationID].delegationFeeBips = delegationFeeBips;
        $._posValidatorInfo[validationID].minStakeDuration = minStakeDuration;
        $._posValidatorInfo[validationID].uptimeSeconds = 0;

        return validationID;
    }

    /**
     * @notice Converts a token value to a weight.
     * @param value Token value to convert.
     */
    function valueToWeight(uint256 value) public view returns (uint64) {
        uint256 weight = value / _getPoSValidatorManagerStorage()._weightToValueFactor;
        if (weight == 0 || weight > type(uint64).max) {
            revert InvalidStakeAmount(value);
        }
        return uint64(weight);
    }

    /**
     * @notice Converts a weight to a token value.
     * @param weight weight to convert.
     */
    function weightToValue(uint64 weight) public view returns (uint256) {
        return uint256(weight) * _getPoSValidatorManagerStorage()._weightToValueFactor;
    }

    /**
     * @notice Locks tokens in this contract.
     * @param value Number of tokens to lock.
     */
    function _lock(uint256 value) internal virtual returns (uint256);

    /**
     * @notice Unlocks token to a specific address.
     * @param to Address to send token to.
     * @param value Number of tokens to lock.
     */
    function _unlock(address to, uint256 value) internal virtual;

    function _initializeDelegatorRegistration(
        bytes32 validationID,
        address delegatorAddress,
        uint256 delegationAmount
    ) internal returns (bytes32) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        uint64 weight = valueToWeight(_lock(delegationAmount));

        // Ensure the validation period is active
        Validator memory validator = getValidator(validationID);
        // Check that the validation ID is a PoS validator
        if (!_isPoSValidator(validationID)) {
            revert ValidatorNotPoS(validationID);
        }
        if (validator.status != ValidatorStatus.Active) {
            revert InvalidValidatorStatus(validator.status);
        }

        // Update the validator weight
        uint64 newValidatorWeight = validator.weight + weight;
        if (newValidatorWeight > validator.startingWeight * $._maximumStakeMultiplier) {
            revert MaxWeightExceeded(newValidatorWeight);
        }

        (uint64 nonce, bytes32 messageID) = _setValidatorWeight(validationID, newValidatorWeight);

        bytes32 delegationID = keccak256(abi.encodePacked(validationID, nonce));

        // Store the delegation information. Set the delegator status to pending added,
        // so that it can be properly started in the complete step, even if the delivered
        // nonce is greater than the nonce used to initialize registration.
        $._delegatorStakes[delegationID].status = DelegatorStatus.PendingAdded;
        $._delegatorStakes[delegationID].owner = delegatorAddress;
        $._delegatorStakes[delegationID].validationID = validationID;
        $._delegatorStakes[delegationID].weight = weight;
        $._delegatorStakes[delegationID].startedAt = 0;
        $._delegatorStakes[delegationID].startingNonce = nonce;
        $._delegatorStakes[delegationID].endingNonce = 0;

        emit DelegatorAdded({
            delegationID: delegationID,
            validationID: validationID,
            delegatorAddress: delegatorAddress,
            nonce: nonce,
            validatorWeight: newValidatorWeight,
            delegatorWeight: weight,
            setWeightMessageID: messageID
        });
        return delegationID;
    }

    /**
     * @notice See {IPoSValidatorManager-completeDelegatorRegistration}.
     */
    function completeDelegatorRegistration(bytes32 delegationID, uint32 messageIndex) external {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;
        Validator memory validator = getValidator(validationID);

        // Ensure the delegator is pending added. Since anybody can call this function once
        // delegator registration has been initialized, we need to make sure that this function is only
        // callable after that has been done.
        if (delegator.status != DelegatorStatus.PendingAdded) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        // In the case where the validator has completed its validation period, we can no
        // longer stake and should move our status directly to completed and return the stake.
        if (validator.status == ValidatorStatus.Completed) {
            return _completeEndDelegation(delegationID);
        }

        // Unpack the Warp message
        (bytes32 messageValidationID, uint64 nonce,) = ValidatorMessages
            .unpackL1ValidatorWeightMessage(_getPChainWarpMessage(messageIndex).payload);

        if (validationID != messageValidationID) {
            revert InvalidValidationID(delegator.validationID);
        }

        // The received nonce should be no greater than the highest sent nonce, and at least as high as
        // the delegation's starting nonce. This allows a weight update using a higher nonce
        // (which implicitly includes the delegation's weight update) to be used to complete delisting
        // for an earlier delegation. This is necessary because the P-Chain is only willing to sign the latest weight update.
        if (validator.messageNonce < nonce || delegator.startingNonce > nonce) {
            revert InvalidNonce(nonce);
        }

        // Update the delegation status
        $._delegatorStakes[delegationID].status = DelegatorStatus.Active;
        $._delegatorStakes[delegationID].startedAt = uint64(block.timestamp);

        $._accountDelegations[delegator.owner].push(delegationID);
        $._validatorDelegations[validationID].push(delegationID);

        emit DelegatorRegistered({
            delegationID: delegationID,
            validationID: validationID,
            startTime: uint64(block.timestamp)
        });
    }

    /**
     * @notice See {IPoSValidatorManager-initializeEndDelegation}.
     */
    function initializeEndDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external {
        _initializeEndDelegation(delegationID, includeUptimeProof, messageIndex);
    }

    function initializeRedelegation(
        bytes32 delegationID,
        uint32 messageIndex,
        bytes32 validationID
    ) external returns (bytes32) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        Delegator memory delegator = $._delegatorStakes[delegationID];

        if (delegator.owner != _msgSender()) {
            revert UnauthorizedOwner(_msgSender());
        }

        // Ensure the delegator is pending removed.
        if (delegator.status != DelegatorStatus.PendingRemoved) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        if (getValidator(delegator.validationID).status != ValidatorStatus.Completed) {
            // Unpack the Warp message
            WarpMessage memory warpMessage = _getPChainWarpMessage(messageIndex);
            (bytes32 unpackedValidationID, uint64 unPackednonce,) =
                ValidatorMessages.unpackL1ValidatorWeightMessage(warpMessage.payload);
            
            if (delegator.validationID != unpackedValidationID) {
                revert InvalidValidationID(unpackedValidationID);
            }

            // The received nonce should be at least as high as the delegation's ending nonce. This allows a weight
            // update using a higher nonce (which implicitly includes the delegation's weight update) to be used to
            // complete delisting for an earlier delegation. This is necessary because the P-Chain is only willing
            // to sign the latest weight update.
            if (delegator.endingNonce > unPackednonce) {
                revert InvalidNonce(unPackednonce);
            }
        }

        // To prevent churn tracker abuse, check that one full churn period has passed,
        // so a delegator may not stake twice in the same churn period.
        if (block.timestamp < delegator.startedAt + _getChurnPeriodSeconds()) {
            revert MinStakeDurationNotPassed(uint64(block.timestamp));
        }

        delete $._delegatorStakes[delegationID];

        emit DelegationEnded(delegationID, delegator.validationID, 0, 0);

        // Ensure the validation period is active
        Validator memory validator = getValidator(validationID);
        if (!_isPoSValidator(validationID)) {
            revert ValidatorNotPoS(validationID);
        }
        if (validator.status != ValidatorStatus.Active) {
            revert InvalidValidatorStatus(validator.status);
        }

        // Update the validator weight
        uint64 newValidatorWeight = validator.weight + delegator.weight;
        if (newValidatorWeight > validator.startingWeight * $._maximumStakeMultiplier) {
            revert MaxWeightExceeded(newValidatorWeight);
        }

        (uint64 nonce, bytes32 messageID) = _setValidatorWeight(validationID, newValidatorWeight);

        delegationID = keccak256(abi.encodePacked(validationID, nonce));

        // Store the delegation information. Set the delegator status to pending added,
        // so that it can be properly started in the complete step, even if the delivered
        // nonce is greater than the nonce used to initialize registration.
        $._delegatorStakes[delegationID].status = DelegatorStatus.PendingAdded;
        $._delegatorStakes[delegationID].owner = delegator.owner;
        $._delegatorStakes[delegationID].validationID = validationID;
        $._delegatorStakes[delegationID].weight = delegator.weight;
        $._delegatorStakes[delegationID].startedAt = 0;
        $._delegatorStakes[delegationID].startingNonce = nonce;
        $._delegatorStakes[delegationID].endingNonce = 0;

        emit DelegatorAdded({
            delegationID: delegationID,
            validationID: validationID,
            delegatorAddress: delegator.owner,
            nonce: nonce,
            validatorWeight: newValidatorWeight,
            delegatorWeight: delegator.weight,
            setWeightMessageID: messageID
        });

        return delegationID;
    }

    /**
     * @dev Helper function that initializes the end of a PoS delegation period.
     * Returns false if it is possible for the delegator to claim rewards, but it is not eligible.
     * Returns true otherwise.
     */
    function _initializeEndDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;
        Validator memory validator = getValidator(validationID);

        // Ensure the delegator is active
        if (delegator.status != DelegatorStatus.Active) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        // Only the delegation owner or parent validator can end the delegation.
        if (delegator.owner != _msgSender()) {
            // Validators can only remove delegations after the minimum stake duration has passed.
            if ($._posValidatorInfo[validationID].owner != _msgSender()) {
                revert UnauthorizedOwner(_msgSender());
            }

            if (
                block.timestamp
                    < validator.startedAt + $._posValidatorInfo[validationID].minStakeDuration
            ) {
                revert MinStakeDurationNotPassed(uint64(block.timestamp));
            }
        }

        if (validator.status == ValidatorStatus.Active) {
            // Check that minimum stake duration has passed.
            if (block.timestamp < delegator.startedAt + $._minimumStakeDuration) {
                revert MinStakeDurationNotPassed(uint64(block.timestamp));
            }

            if (includeUptimeProof) {
                // Uptime proofs include the absolute number of seconds the validator has been active.
                _updateUptime(validationID, messageIndex);
            }

            // Set the delegator status to pending removed, so that it can be properly removed in
            // the complete step, even if the delivered nonce is greater than the nonce used to
            // initialize the removal.
            $._delegatorStakes[delegationID].status = DelegatorStatus.PendingRemoved;
            $._delegatorStakes[delegationID].endedAt = uint64(block.timestamp);

            ($._delegatorStakes[delegationID].endingNonce,) =
                _setValidatorWeight(validationID, validator.weight - delegator.weight);

            emit DelegatorRemovalInitialized({
                delegationID: delegationID,
                validationID: validationID
            });
        } else if (validator.status == ValidatorStatus.Completed) {
            _completeEndDelegation(delegationID);
            // If the validator has completed, then no further uptimes may be submitted, so we always
            // end the delegation.
        } else {
            revert InvalidValidatorStatus(validator.status);
        }
    }

    /**
     * @notice See {IPoSValidatorManager-resendUpdateDelegation}.
     * @dev Resending the latest validator weight with the latest nonce is safe because all weight changes are
     * cumulative, so the latest weight change will always include the weight change for any added delegators.
     */
    function resendUpdateDelegation(bytes32 delegationID) external {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        Delegator memory delegator = $._delegatorStakes[delegationID];
        if (
            delegator.status != DelegatorStatus.PendingAdded
                && delegator.status != DelegatorStatus.PendingRemoved
        ) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        Validator memory validator = getValidator(delegator.validationID);
        if (validator.messageNonce == 0) {
            // Should be unreachable.
            revert InvalidDelegationID(delegationID);
        }

        // Submit the message to the Warp precompile.
        WARP_MESSENGER.sendWarpMessage(
            ValidatorMessages.packL1ValidatorWeightMessage(
                delegator.validationID, validator.messageNonce, validator.weight
            )
        );
    }

    /**
     * @notice See {IPoSValidatorManager-completeEndDelegation}.
     */
    function completeEndDelegation(
        bytes32 delegationID,
        uint32 messageIndex
    ) external nonReentrant {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        Delegator memory delegator = $._delegatorStakes[delegationID];

        // Ensure the delegator is pending removed. Since anybody can call this function once
        // end delegation has been initialized, we need to make sure that this function is only
        // callable after that has been done.
        if (delegator.status != DelegatorStatus.PendingRemoved) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        if (getValidator(delegator.validationID).status != ValidatorStatus.Completed) {
            // Unpack the Warp message
            WarpMessage memory warpMessage = _getPChainWarpMessage(messageIndex);
            (bytes32 validationID, uint64 nonce,) =
                ValidatorMessages.unpackL1ValidatorWeightMessage(warpMessage.payload);

            if (delegator.validationID != validationID) {
                revert InvalidValidationID(validationID);
            }

            // The received nonce should be at least as high as the delegation's ending nonce. This allows a weight
            // update using a higher nonce (which implicitly includes the delegation's weight update) to be used to
            // complete delisting for an earlier delegation. This is necessary because the P-Chain is only willing
            // to sign the latest weight update.
            if (delegator.endingNonce > nonce) {
                revert InvalidNonce(nonce);
            }
        }
        if(block.timestamp < delegator.endedAt + $._unlockDelegateDuration) {
            revert UnlockDelegateDurationNotPassed(uint64(block.timestamp));
        }

        _completeEndDelegation(delegationID);
    }

    function _completeEndDelegation(bytes32 delegationID) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;

        // To prevent churn tracker abuse, check that one full churn period has passed,
        // so a delegator may not stake twice in the same churn period.
        if (block.timestamp < delegator.startedAt + _getChurnPeriodSeconds()) {
            revert MinStakeDurationNotPassed(uint64(block.timestamp));
        }

        PoSUtils.removeFromBytes32Array($._validatorDelegations[validationID], delegationID);
        PoSUtils.removeFromBytes32Array($._accountDelegations[delegator.owner], delegationID);

        // Once this function completes, the delegation is completed so we can clear it from state now.
        delete $._delegatorStakes[delegationID];

        // Unlock the delegator's stake.
        _unlock(delegator.owner, weightToValue(delegator.weight));

        emit DelegationEnded(delegationID, validationID, 0, 0);
    }

    /**
     * @dev This function must be implemented to mint rewards to validators and delegators.
     */
    function _reward(address account, uint256 amount) internal virtual;

    /**
     * @dev Return true if this is a PoS validator with locked stake. Returns false if this was originally a PoA
     * validator that was later migrated to this PoS manager, or the validator was part of the initial validator set.
     */
    function _isPoSValidator(bytes32 validationID) internal view returns (bool) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        return $._posValidatorInfo[validationID].owner != address(0);
    }
}
