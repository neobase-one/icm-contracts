// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {ValidatorManager} from "./ValidatorManager.sol";
import {ValidatorMessages} from "./ValidatorMessages.sol";
import {
    Delegator,
    DelegatorStatus,
    IPoSValidatorManager,
    PoSValidatorManagerSettings,
    PoSValidatorManagerStorage
} from "./interfaces/IPoSValidatorManager.sol";
import {
    Validator,
    ValidatorRegistrationInput,
    ValidatorStatus
} from "./interfaces/IValidatorManager.sol";
import {ITrackingRewardStreams} from "../reward-streams/interfaces/IRewardStreams.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {WarpMessage} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";
import {ReentrancyGuardUpgradeable} from
    "@openzeppelin/contracts-upgradeable@5.0.2/utils/ReentrancyGuardUpgradeable.sol";

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
    using SafeERC20 for IERC20;
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
    error ValidatorIneligibleForRewards(bytes32 validationID);
    error DelegatorIneligibleForRewards(bytes32 delegationID);
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
            rewardStream: settings.rewardStream,
            uptimeBlockchainID: settings.uptimeBlockchainID,
            epochDuration: settings.epochDuration
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
        ITrackingRewardStreams rewardStream,
        bytes32 uptimeBlockchainID,
        uint48 epochDuration
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
        $._minimumDelegationFeeBips = minimumDelegationFeeBips;
        $._maximumStakeMultiplier = maximumStakeMultiplier;
        $._weightToValueFactor = weightToValueFactor;
        $._rewardStream = rewardStream;
        $._uptimeBlockchainID = uptimeBlockchainID;
        $._unlockDelegateDuration = unlockDelegateDuration;
        $._epochDuration = epochDuration;
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

        // update uptime
        _updateUptime(validationID, messageIndex);
    }

    /// @dev Updates the balance tracker for a delegator with specific uptime and epoch
    /// @param delegationID The delegator's ID
    /// @param currentUptime The current uptime
    /// @param previousUptime The previous uptime
    /// @param epoch The epoch to record for
    function _updateDelegatorBalanceTrackerWithUptime(bytes32 delegationID, uint64 currentUptime, uint64 previousUptime, uint48 epoch) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        
        // Only update if not already updated for this epoch
        if ($._delegatorLastTrackedEpoch[delegationID] < epoch) {
            $._delegatorLastTrackedEpoch[delegationID] = epoch;
            
            // Call balanceTracker with the delegator's uptime
            Delegator memory delegator = $._delegatorStakes[delegationID];
            if (delegator.owner != address(0)) {
                uint256 delegateEffectiveWeight = calculateEffectiveWeight(
                    delegator.weight,
                    currentUptime,
                    previousUptime
                );
                $._rewardStream.balanceTrackerHook(delegator.owner, delegateEffectiveWeight, false);
            }
        }
    }

    /**
     * @notice See {IPoSValidatorManager-initializeEndValidation}.
     */
    function initializeEndValidation(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external {
        _initializeEndValidationWithCheck(
            validationID, includeUptimeProof, messageIndex
        );
    }

    function _initializeEndValidationWithCheck(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        _initializeEndPoSValidation(
            validationID, includeUptimeProof, messageIndex
        );
    }

    /**
     * @notice See {IPoSValidatorManager-forceInitializeEndValidation}.
     */
    function forceInitializeEndValidation(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external {
        // Ignore the return value here to force end validation, regardless of possible missed rewards
        _initializeEndPoSValidation(validationID, includeUptimeProof, messageIndex);
    }

    /**
     * @dev Helper function that initializes the end of a PoS validation period.
    
     */
    function _initializeEndPoSValidation(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal  {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        Validator memory validator = _initializeEndValidation(validationID);

        // Non-PoS validators are required to boostrap the network, but are not eligible for rewards.
        if (!_isPoSValidator(validationID)) {
            return ;
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
    function completeEndValidation(uint32 messageIndex) external nonReentrant {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        (bytes32 validationID, ) = _completeEndValidation(messageIndex);

        // Return now if this was originally a PoA validator that was later migrated to this PoS manager,
        // or the validator was part of the initial validator set.
        if (!_isPoSValidator(validationID)) {
            return;
        }

        address owner = $._posValidatorInfo[validationID].owner;

        // The stake is unlocked whether the validation period is completed or invalidated.
        _unlock(owner, validationID, true);
        _deleteValidatorNft(validationID);
    }

    /**
     * @dev Helper function that extracts the uptime from a ValidationUptimeMessage Warp message
     * If the uptime is greater than the stored uptime, update the stored uptime.
     */
    function _updateUptime(bytes32 validationID, uint32 messageIndex) internal returns (uint64) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        // Get and validate the warp message
        (WarpMessage memory warpMessage, bool valid) =
            WARP_MESSENGER.getVerifiedWarpMessage(messageIndex);
        if (!valid) {
            revert InvalidWarpMessage();
        }

        // The uptime proof must be from the specified uptime blockchain
        if (warpMessage.sourceChainID != $._uptimeBlockchainID) {
            revert InvalidWarpSourceChainID(warpMessage.sourceChainID);
        }

        // The sender is required to be the zero address so that we know the validator node
        // signed the proof directly, rather than as an arbitrary on-chain message
        if (warpMessage.originSenderAddress != address(0)) {
            revert InvalidWarpOriginSenderAddress(warpMessage.originSenderAddress);
        }

        // Get the uptime from the message
        (bytes32 messageValidationID, uint64 uptimeSeconds) = 
            ValidatorMessages.unpackValidationUptimeMessage(warpMessage.payload);

        if (validationID != messageValidationID) {
            revert InvalidValidationID(validationID);
        }

        // Get current epoch
        uint48 epoch = currentEpoch();

        // Store uptime for current epoch
        // Only update if the new uptime is greater than the stored uptime for this epoch
        uint64 currentEpochUptime = $._validatorEpochUptime[validationID][epoch];
        if (uptimeSeconds > currentEpochUptime) {
            $._validatorEpochUptime[validationID][epoch] = uptimeSeconds;
            emit UptimeUpdated(validationID, uptimeSeconds);
        }
        Validator memory validator = getValidator(validationID);
        address owner = $._posValidatorInfo[validationID].owner;
        uint64 previousEpochUptime = epoch > 0 ? $._validatorEpochUptime[validationID][epoch - 1] : 0;
        if (owner != address(0)) {
            uint256 validatorEffectiveWeight = calculateEffectiveWeight(
                validator.weight, 
                uptimeSeconds,
                previousEpochUptime
            );
            $._rewardStream.balanceTrackerHook(owner, validatorEffectiveWeight, false);
        }
        // Update balance trackers for all active delegators
        bytes32[] memory activeDelegations = getActiveDelegations(validationID);
        for (uint256 i = 0; i < activeDelegations.length; i++) {
            _updateDelegatorBalanceTrackerWithUptime(activeDelegations[i], uptimeSeconds, previousEpochUptime, epoch);
        }

        return uptimeSeconds;
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
        // Ensure the weight is within the valid range.
        if (stakeAmount < $._minimumStakeAmount || stakeAmount > $._maximumStakeAmount) {
            revert InvalidStakeAmount(stakeAmount);
        }
        // Lock the stake in the contract.
        uint256 lockedValue = _lock(stakeAmount);
        uint64 weight = valueToWeight(lockedValue);
        bytes32 validationID = _initializeValidatorRegistration(registrationInput, weight);
        _addValidatorNft(validationID, stakeAmount);

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
     * @param validationID ID of validator
     * @param isValidator Whether the unlock is for a validator or a delegator
     */
    function _unlock(address to, bytes32 validationID, bool isValidator) internal virtual;

    function _addValidatorNft(bytes32 validationID, uint256 tokenId) internal virtual;

    function _deleteValidatorNft(
        bytes32 validationID
    ) internal virtual;

    function _addDelegatorNft(bytes32 delegationID, uint256 tokenId) internal virtual;

    function _deleteDelegatorNft(
        bytes32 delegationID
    ) internal virtual;

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
        _addDelegatorNft(delegationID, delegationAmount);
        _addDelegationToValidator(validationID, delegationID);
        _calculateAndUpdateEffectiveWeights(
            $,
            validationID,
            delegatorAddress,
            weight,
            validator
        );
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

    function _calculateAndUpdateEffectiveWeights(
        PoSValidatorManagerStorage storage $,
        bytes32 validationID,
        address delegatorAddress,
        uint64 delegatorWeight,
        Validator memory validator
    ) internal {
        uint64 currentUptime = $._posValidatorInfo[validationID].uptimeSeconds;
        uint48 epoch = currentEpoch();
        uint64 previousEpochUptime = epoch > 0 ? $._validatorEpochUptime[validationID][epoch - 1] : 0;
        uint256 delegatorEffectiveWeight = calculateEffectiveWeight(
            delegatorWeight,
            currentUptime,
            previousEpochUptime
        );
        uint256 validatorEffectiveWeight = calculateEffectiveWeight(
            validator.weight,
            currentUptime,
            previousEpochUptime
        );
        $._rewardStream.balanceTrackerHook($._posValidatorInfo[validationID].owner, validatorEffectiveWeight, false);
        $._rewardStream.balanceTrackerHook(delegatorAddress, delegatorEffectiveWeight, false);
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
            revert InvalidValidationID(validationID);
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
        _initializeEndDelegationWithCheck(
            delegationID, includeUptimeProof, messageIndex
        );
    }

    function _initializeEndDelegationWithCheck(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        _initializeEndDelegation(
            delegationID, includeUptimeProof, messageIndex
        );
    }

    /**
     * @notice See {IPoSValidatorManager-forceInitializeEndDelegation}.
     */
    function forceInitializeEndDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external {
        // Ignore the return value here to force end delegation, regardless of possible missed rewards
        _initializeEndDelegation(delegationID, includeUptimeProof, messageIndex);
    }


    /**
     * @dev Helper function that initializes the end of a PoS delegation period.
     */
    function _initializeEndDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal  {
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

            uint48 epoch = currentEpoch();
            uint64 previousEpochUptime = epoch > 0 ? $._validatorEpochUptime[validationID][epoch - 1] : 0;
          
            uint256 validatorEffectiveWeight = calculateEffectiveWeight(
                validator.weight - delegator.weight,
                $._posValidatorInfo[validationID].uptimeSeconds,
                previousEpochUptime
            );
            $._rewardStream.balanceTrackerHook($._posValidatorInfo[validationID].owner, validatorEffectiveWeight, false);
            
            emit DelegatorRemovalInitialized({
                delegationID: delegationID,
                validationID: validationID
            });
            
        } else if (validator.status == ValidatorStatus.Completed) {
            _completeEndDelegation(delegationID);
            
        } else {
            revert InvalidValidatorStatus(validator.status);
        }
    }

    /// @notice Returns the current epoch based on the block timestamp.
    /// @return The current epoch.
    function currentEpoch() public view returns (uint48) {
        return getEpoch(uint48(block.timestamp));
    }

    /// @notice Returns the epoch for a given timestamp.
    /// @param timestamp The timestamp to get the epoch for.
    /// @return The epoch for the given timestamp.
    function getEpoch(uint48 timestamp) public view returns (uint48) {
        return uint48(timestamp / _getPoSValidatorManagerStorage()._epochDuration);
    }

    /**
     * @dev Return true if this is a PoS validator with locked stake. Returns false if this was originally a PoA
     * validator that was later migrated to this PoS manager, or the validator was part of the initial validator set.
     */
    function _isPoSValidator(bytes32 validationID) internal view returns (bool) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        return $._posValidatorInfo[validationID].owner != address(0);
    }
 

    function getDelegator(
        bytes32 delegationID
    ) public view returns (Delegator memory) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        return $._delegatorStakes[delegationID];
    }

    function getDelegatorNfts(
        bytes32 delegationID
    ) public view returns (uint256[] memory) {
        return _getPoSValidatorManagerStorage()._delegatorNFTs[delegationID].nftIds;
    }

    function calculateEffectiveWeight(
        uint256 weight,
        uint64 currentUptime,
        uint64 previousUptime
    ) internal view returns (uint256) {

        if(currentUptime == 0) {
            return 0;
        }
        // Calculate effective weight based on both weight and time period
        return (weight * (currentUptime - previousUptime)) / _getPoSValidatorManagerStorage()._epochDuration;
    }

    /**
     * @dev Returns array of active delegation IDs for a validator
     * @param validationID The validator's ID
     * @return Array of active delegation IDs
     */
    function getActiveDelegations(bytes32 validationID) internal view returns (bytes32[] memory) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        
        bytes32[] memory allDelegations = $._validatorDelegations[validationID];
        
        // First pass to count active delegations
        uint256 activeCount = 0;
        for (uint256 i = 0; i < allDelegations.length; i++) {
            if ($._delegatorStakes[allDelegations[i]].status == DelegatorStatus.Active) {
                activeCount++;
            }
        }
        
        // Second pass to fill active delegations array
        bytes32[] memory activeDelegations = new bytes32[](activeCount);
        uint256 activeIndex = 0;
        for (uint256 i = 0; i < allDelegations.length; i++) {
            if ($._delegatorStakes[allDelegations[i]].status == DelegatorStatus.Active) {
                activeDelegations[activeIndex] = allDelegations[i];
                activeIndex++;
            }
        }
        
        return activeDelegations;
    }

    /**
     * @dev Adds a delegation ID to a validator's delegation list
     * @param validationID The validator's ID
     * @param delegationID The delegation ID to add
     */
    function _addDelegationToValidator(bytes32 validationID, bytes32 delegationID) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        $._validatorDelegations[validationID].push(delegationID);
    }

    /**
     * @dev Removes a delegation ID from a validator's delegation list
     * @param validationID The validator's ID
     * @param delegationID The delegation ID to remove
     */
    function _removeDelegationFromValidator(bytes32 validationID, bytes32 delegationID) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        bytes32[] storage delegations = $._validatorDelegations[validationID];
        
        // Find and remove the delegation ID
        for (uint256 i = 0; i < delegations.length; i++) {
            if (delegations[i] == delegationID) {
                // Move the last element to this position and pop
                delegations[i] = delegations[delegations.length - 1];
                delegations.pop();
                break;
            }
        }
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


        // Remove delegation from validator's list
        _removeDelegationFromValidator(validationID, delegationID);

        // Unlock the delegator's stake.
        _unlock(delegator.owner, delegationID, false);
        // Once this function completes, the delegation is completed so we can clear it from state now.
        delete $._delegatorStakes[delegationID];
        _deleteDelegatorNft(delegationID);

        emit DelegationEnded(delegationID, validationID);
    }

    /**
     * @dev Gets the last known uptime value for a validator by searching backwards through epochs
     * @param validationID The validator's ID
     * @param fromEpoch The epoch to start searching from
     * @return lastKnownUptime The last known uptime value
     * @return lastKnownEpoch The epoch where the last known uptime was found
     */
    function _getLastKnownUptime(bytes32 validationID, uint48 fromEpoch) 
        internal 
        view 
        returns (uint64 lastKnownUptime, uint48 lastKnownEpoch) 
    {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        
        lastKnownEpoch = fromEpoch;
        // Search back through epochs until we find a non-zero uptime or reach epoch 0
        while (lastKnownEpoch > 0) {
            lastKnownUptime = $._validatorEpochUptime[validationID][lastKnownEpoch];
            if (lastKnownUptime > 0) {
                break;
            }
            lastKnownEpoch--;
        }
        
        return (lastKnownUptime, lastKnownEpoch);
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
}
