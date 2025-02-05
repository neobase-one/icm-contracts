// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {
    PoSValidatorManager
} from "./PoSValidatorManager.sol";
import {
    Validator,
    ValidatorRegistrationInput,
    ValidatorStatus,
    IValidatorManager
} from "./interfaces/IValidatorManager.sol";

import {
    Delegator,
    DelegatorStatus,
    IPoSValidatorManager,
    PoSValidatorInfo,
    PoSValidatorManagerSettings
} from "./interfaces/IPoSValidatorManager.sol";
import {IERC721TokenStakingManager} from "./interfaces/IERC721TokenStakingManager.sol";
import {IERC721Manager} from "./interfaces/IERC721Manager.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {Address} from "@openzeppelin/contracts@5.0.2/utils/Address.sol";
import {ICMInitializable} from "@utilities/ICMInitializable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable@5.0.2/proxy/utils/Initializable.sol";

import {WarpMessage} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";

import {ValidatorMessages} from "./ValidatorMessages.sol";
import {IERC721Receiver} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721Receiver.sol";

/**
 * @dev Implementation of the {IERC721TokenStakingManager} interface.
 *
 * @custom:security-contact https://github.com/ava-labs/icm-contracts/blob/main/SECURITY.md
 */
contract ERC721TokenStakingManager is
    Initializable,
    PoSValidatorManager,
    IERC721TokenStakingManager
{
    using Address for address payable;

    // solhint-disable private-vars-leading-underscore
    /// @custom:storage-location erc7201:avalanche-icm.storage.ERC721TokenStakingManager
    struct ERC721TokenStakingManagerStorage {
        IERC721Manager _erc721Manager;
    }
    // solhint-enable private-vars-leading-underscore

    // keccak256(abi.encode(uint256(keccak256("avalanche-icm.storage.ERC721TokenStakingManager")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 public constant ERC721_STAKING_MANAGER_STORAGE_LOCATION =
        0xf2d79c30881febd0da8597832b5b1bf1f4d4b2209b19059420303eb8fcab8a00;

    error InvalidERC721ManagerAddress(address);

    // solhint-disable ordering
    function _getERC721StakingManagerStorage()
        private
        pure
        returns (ERC721TokenStakingManagerStorage storage $)
    {
        assembly {
            $.slot := ERC721_STAKING_MANAGER_STORAGE_LOCATION
        }
    }

    constructor(ICMInitializable init) {
        if (init == ICMInitializable.Disallowed) {
            _disableInitializers();
        }
    }

    /**
     * @notice Initialize the ERC721 token staking manager
     * @dev Uses reinitializer(2) on the PoS staking contracts to make sure after migration from PoA, the PoS contracts can reinitialize with its needed values.
     * @param settings Initial settings for the PoS validator manager
     * @param erc721Manager The ERC721 token to be staked
     */
    function initialize(
        PoSValidatorManagerSettings calldata settings,
        IERC721Manager erc721Manager
    ) external reinitializer(2) {
        __POS_Validator_Manager_init(settings);

        ERC721TokenStakingManagerStorage storage $ = _getERC721StakingManagerStorage();

        if (address(erc721Manager) == address(0)) {
            revert InvalidERC721ManagerAddress(address(erc721Manager));
        }

        $._erc721Manager = erc721Manager;
    }

    /**
     * @notice See {IERC721TokenStakingManager-initializeValidatorRegistration}
     */
    function initializeValidatorRegistration(
        ValidatorRegistrationInput calldata registrationInput,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256[] memory tokenIds
    ) external payable nonReentrant returns (bytes32 validationID) {
        return _initializeValidatorRegistration(
            registrationInput, delegationFeeBips, minStakeDuration, msg.value, tokenIds
        );
    }

    /**
     * @notice See {INativeTokenStakingManager-initializeDelegatorRegistration}.
     */
    function initializeDelegatorRegistration(bytes32 validationID)
        external
        payable
        nonReentrant
        returns (bytes32)
    {
        return _initializeDelegatorRegistration(validationID, _msgSender(), msg.value);
    }

    /**
     * @notice See {IValidatorManager-completeEndValidation}.
     */
    function completeEndValidation(uint32 messageIndex) external override (PoSValidatorManager, IValidatorManager) nonReentrant {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        (bytes32 validationID, Validator memory validator) = _completeEndValidation(messageIndex);
        // Return now if this was originally a PoA validator that was later migrated to this PoS manager,
        // or the validator was part of the initial validator set.
        if (!_isPoSValidator(validationID)) {
            return;
        }

        address owner = $._posValidatorInfo[validationID].owner;

        _getERC721StakingManagerStorage()._erc721Manager.unregisterValidator(validationID, owner);

        // The stake is unlocked whether the validation period is completed or invalidated.
        _unlock(owner, weightToValue(validator.startingWeight));
    }

    function calculateEffectiveWeight(
      uint64 weight,
      uint64 currentUptime,
      uint64 previousUptime
    ) external view returns (uint256) {
        _calculateEffectiveWeight(weight, currentUptime, previousUptime);
    }

    /**
     * @notice See {PoSValidatorManager-_lock}
     */
    function _lock(uint256 value) internal virtual override returns (uint256) {
        return value;
    }

    /**
     * @notice See {PoSValidatorManager-_unlock}
     * Note: Must be guarded with reentrancy guard for safe transfer.
     */
    function _unlock(address to, uint256 value) internal virtual override {
        payable(to).sendValue(value);
    }

    /**
    * @notice Initializes a new validator registration with the provided input parameters.
    * @dev This function validates and stores the information for a new PoS validator, including requirements for
    *      delegation fees, stake amount, NFT amounts, and other configurations. The stake and NFTs are locked in
    *      the contract, and the validator's state is initialized.
    * @param registrationInput A struct containing the details for the validator registration (e.g., validator name, network details).
    * @param delegationFeeBips The delegation fee in basis points (bps) for the validator (must be within allowed limits).
    * @param minStakeDuration The minimum stake duration (in seconds) before delegations can be removed (must meet minimum requirement).
    * @param stakeAmount The amount of stake to be locked for the validator (must be within allowed range).
    * @param tokenIDs An array of token IDs representing the NFTs locked for the validator's staking (must meet minimum/maximum limits).
    * @return validationID A unique identifier for the newly registered validator.
    *
    * Reverts if:
    * - The delegation fee is not within the allowed range (`InvalidDelegationFee`).
    * - The minimum stake duration is too short (`InvalidMinStakeDuration`).
    * - The stake amount is outside the valid range (`InvalidStakeAmount`).
    * - The number of NFTs is not within the allowed range (`InvalidNFTAmount`).
    */
    function _initializeValidatorRegistration(
        ValidatorRegistrationInput calldata registrationInput,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 stakeAmount,
        uint256[] memory tokenIDs
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

        address owner = _msgSender();

        // Lock the stake in the contract.
        uint64 weight = valueToWeight(_lock(stakeAmount));

        bytes32 validationID = _initializeValidatorRegistration(registrationInput, weight);
        
        _getERC721StakingManagerStorage()._erc721Manager.registerValidator(validationID, owner, tokenIDs);

        $._posValidatorInfo[validationID].owner = owner;
        $._posValidatorInfo[validationID].delegationFeeBips = delegationFeeBips;
        $._posValidatorInfo[validationID].minStakeDuration = minStakeDuration;
        $._posValidatorInfo[validationID].weight = weight;
        $._posValidatorInfo[validationID].tokenIDs = tokenIDs;

        return validationID;
    }

    function _updateBalanceTracker(bytes32 validationID) internal returns (int256) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        PoSValidatorInfo storage validatorInfo = $._posValidatorInfo[validationID];

        uint256 valWeight;
        valWeight += _calculateEffectiveWeight(
            validatorInfo.weight,
            validatorInfo.uptimeSeconds,
            validatorInfo.prevEpochUptimeSeconds
        );

        bytes32[] memory delegations = $._validatorDelegations[validationID];
        for (uint256 i = 0; i < delegations.length; i++) {
            Delegator memory delegator = $._delegatorStakes[delegations[i]];
            if (delegator.status == DelegatorStatus.Active) {
                uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                    delegator.weight,
                    validatorInfo.uptimeSeconds,
                    validatorInfo.prevEpochUptimeSeconds
                );
                uint256 delegatorFeeWeight = (delegateEffectiveWeight * validatorInfo.delegationFeeBips)
            / BIPS_CONVERSION_FACTOR;

                uint256 delWeight = delegateEffectiveWeight - delegatorFeeWeight;
                valWeight += delegatorFeeWeight;

                uint256 delBalance = uint256(int256($._accountRewardBalance[delegator.owner]) + int256(delWeight) - int256(delegator.rewardBalance));
                delegator.rewardBalance = delWeight;

                $._accountRewardBalance[delegator.owner] = delBalance;
                $._balanceTracker.balanceTrackerHook(delegator.owner, delBalance, false);
            }
        }

        int256 delta = int256(valWeight) - int256(validatorInfo.rewardBalance);
        validatorInfo.rewardBalance = valWeight;


        uint256 valBalance = uint256(int256($._accountRewardBalance[validatorInfo.owner]) + delta);
        $._accountRewardBalance[validatorInfo.owner] = valBalance;
        $._balanceTracker.balanceTrackerHook(validatorInfo.owner, valBalance, false);
    }

    /**
    * @notice Updates the uptime of a validator based on a verified ValidationUptimeMessage received via Warp.
    * @dev This function extracts the uptime from a Warp message, validates its authenticity, and updates the
    *      stored uptime for the specified validator if the provided uptime is greater than the currently stored uptime.
    *      It also updates the validator's epoch information and balance trackers for both standard and NFT delegations.
    * @param validationID The unique identifier of the validator whose uptime is being updated.
    * @param messageIndex The index of the Warp message in the Warp messenger to validate and process.
    * @return The updated uptime for the specified validator, or the current uptime if no update is performed.
    *
    * Reverts if:
    * - The Warp message is invalid.
    * - The source chain ID in the Warp message does not match the expected uptime blockchain ID.
    * - The origin sender address in the Warp message is not the zero address.
    * - The `validationID` in the Warp message payload does not match the provided `validationID`.
    *
    * Emits:
    * - `UptimeUpdated` event when the uptime is successfully updated for a validator.
    */
    function _updateUptime(bytes32 validationID, uint32 messageIndex) internal override returns (uint64) {
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

        (bytes32 uptimeValidationID, uint64 uptime) =
            ValidatorMessages.unpackValidationUptimeMessage(warpMessage.payload);
        if (validationID != uptimeValidationID) {
            revert InvalidValidationID(validationID);
        }

        uint64 currentEpoch = uint64(block.timestamp / $._epochDuration);

        PoSValidatorInfo storage validatorInfo = $._posValidatorInfo[validationID];

        if (uptime > validatorInfo.uptimeSeconds) {
            if(currentEpoch > validatorInfo.currentEpoch){
                validatorInfo.currentEpoch = currentEpoch;
                validatorInfo.prevEpochUptimeSeconds = validatorInfo.uptimeSeconds;
            }
            validatorInfo.uptimeSeconds = uptime;
            emit UptimeUpdated(validationID, uptime, currentEpoch);

            _updateBalanceTracker(validationID);
            _getERC721StakingManagerStorage()._erc721Manager.updateBalanceTracker(validationID);
        } else {
            uptime = $._posValidatorInfo[validationID].uptimeSeconds;
        }
        return uptime;
    }

    /**
    * @notice Calculates the effective weight of a delegator's stake based on the change in uptime over an epoch.
    * @dev This function computes the effective weight by considering the delegator's stake (`weight`) and the
    *      difference between the current uptime and the previous epoch's uptime, normalized by the epoch duration.
    *      If the current uptime is zero or less than the previous uptime, the effective weight is zero.
    * @param weight The original weight of the delegator's stake.
    * @param currentUptime The validator's current uptime for the epoch.
    * @param previousUptime The validator's uptime for the previous epoch.
    * @return effectiveWeight The effective weight of the delegator's stake based on uptime and epoch duration.
    // */
    // function calculateEffectiveWeight(
    //      uint64 weight,
    //      uint64 currentUptime,
    //      uint64 previousUptime
    // ) external view returns (uint256) {
    //     if(previousUptime > currentUptime || currentUptime == 0) {
    //         return 0;
    //     }
    //     // Calculate effective weight based on both weight and time period
    //     return (weight * (currentUptime - previousUptime)) / _getPoSValidatorManagerStorage()._epochDuration;
    // }

     function _calculateEffectiveWeight(
         uint64 weight,
         uint64 currentUptime,
         uint64 previousUptime
    ) internal view returns (uint256) {
        if(previousUptime > currentUptime || currentUptime == 0) {
            return 0;
        }
        // Calculate effective weight based on both weight and time period
        return (weight * (currentUptime - previousUptime)) / _getPoSValidatorManagerStorage()._epochDuration;
    }

 
}
