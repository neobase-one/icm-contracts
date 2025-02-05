// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {Address} from "@openzeppelin/contracts@5.0.2/utils/Address.sol";
import {ICMInitializable} from "@utilities/ICMInitializable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable@5.0.2/proxy/utils/Initializable.sol";

import {WarpMessage} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";

import {IERC721Receiver} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721Receiver.sol";
import {ReentrancyGuardUpgradeable} from
    "@openzeppelin/contracts-upgradeable@5.0.2/utils/ReentrancyGuardUpgradeable.sol";
import {IERC721Manager, ERC721ManagerSettings, DelegatorNFT} from "./interfaces/IERC721Manager.sol";
import {IERC721TokenStakingManager} from "./interfaces/IERC721TokenStakingManager.sol";
import {
    DelegatorStatus
} from "./interfaces/IPoSValidatorManager.sol";
import {IBalanceTracker} from "@euler-xyz/reward-streams@1.0.0/interfaces/IBalanceTracker.sol";
import {
    Validator,
    ValidatorStatus
} from "./interfaces/IValidatorManager.sol";
import {
    Delegator,
    DelegatorStatus,
    IPoSValidatorManager,
    PoSValidatorInfo,
    PoSValidatorManagerSettings
} from "./interfaces/IPoSValidatorManager.sol";
import {ContextUpgradeable} from
    "@openzeppelin/contracts-upgradeable@5.0.2/utils/ContextUpgradeable.sol";

/**
 * @dev Implementation of the {IERC721Manager} interface.
 *
 * @custom:security-contact https://github.com/ava-labs/icm-contracts/blob/main/SECURITY.md
 */
contract ERC721Manager is
    Initializable,
    IERC721Manager,
    IERC721Receiver,
    ContextUpgradeable,
    ReentrancyGuardUpgradeable
{
    using Address for address payable;

    // solhint-disable private-vars-leading-underscore
    /// @custom:storage-location erc7201:avalanche-icm.storage.ERC721Manager
    struct ERC721ManagerStorage {
        IERC721 _token;
        IERC721TokenStakingManager _posManager;
        IBalanceTracker _balanceTrackerNFT;

        uint256 _minimumNFTAmount;
        uint256 _maximumNFTAmount;

        /// @notice Maps account to array of delegationIDs
        mapping(address => bytes32[]) _accountNFTDelegations;
        /// @notice Maps the delegation ID to the delegator information.
        mapping(bytes32 delegationID => DelegatorNFT) _delegatorNFTStakes;
        /// @notice Maps validation ID to array of delegation IDs
        mapping(bytes32 validationID => bytes32[]) _validatorNFTDelegations;
        /// @notice Maps validation ID to array of delegation IDs
        mapping(bytes32 validationID => uint256[]) _validationNFTs;
        mapping(bytes32 validationID => uint64) _validationNonce;
        mapping(address => uint256) _accountRewardBalance;
    }
    // solhint-enable private-vars-leading-underscore

    // keccak256(abi.encode(uint256(keccak256("avalanche-icm.storage.ERC721Manager")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 public constant ERC721_STAKING_MANAGER_STORAGE_LOCATION =
        0xf2d79c30881febd0da8597832b5b1bf1f4d4b2209b19059420303eb8fcab8a00;

    uint16 public constant BIPS_CONVERSION_FACTOR = 10000;

    error InvalidNFTAmount(uint256 nftAmount);
    error InvalidTokenAddress(address tokenAddress);
    error InvalidDelegatorStatus(DelegatorStatus status);
    error UnlockDurationNotPassed(uint64 endTime);
    error InvalidValidatorStatus(ValidatorStatus status);
    error UnauthorizedOwner(address sender);
    error MinStakeDurationNotPassed(uint64 endTime);


    // solhint-disable ordering
    function _getERC721ManagerStorage()
        private
        pure
        returns (ERC721ManagerStorage storage $)
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
     */
    function initialize(
        ERC721ManagerSettings calldata settings
    ) external reinitializer(2) {
        // TODO: add input validations
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();

        $._token = settings._token;
        $._posManager = settings._posManager;
        $._minimumNFTAmount = settings.minimumNFTAmount;
        $._maximumNFTAmount = settings.maximumNFTAmount;
        $._balanceTrackerNFT = settings.balanceTrackerNFT;
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    /**
    * @notice See {IERC721Manager-registerNFTDelegation}.
    *
    */
    function registerValidator(
        bytes32 validationID,
        address validator,
        uint256[] memory tokenIDs
    ) external nonReentrant returns (bytes32) {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();
        if (tokenIDs.length < $._minimumNFTAmount || tokenIDs.length > $._maximumNFTAmount) {
            revert InvalidNFTAmount(tokenIDs.length);
        }

        $._validationNFTs[validationID] = tokenIDs;

        _lockNFTs(validator, tokenIDs);
    }

    /**
    * @notice See {IERC721Manager-registerNFTDelegation}.
    *
    */
    function unregisterValidator(
        bytes32 validationID,
        address validator
    ) external nonReentrant returns (bytes32) {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();

        _unlockNFTs(validator, $._validationNFTs[validationID]);

        delete $._validationNFTs[validationID];

    } 
    
    /**
    * @notice See {IERC721Manager-registerNFTDelegation}.
    *
    */
    function registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress,
        uint256[] memory tokenIDs
    ) external nonReentrant returns (bytes32) {
        _lockNFTs(delegatorAddress, tokenIDs);
        return _registerNFTDelegation(validationID, delegatorAddress, tokenIDs);
    }

    /**
    * @notice See {IERC721Manager-initializeEndNFTDelegation}.
    *
    */
    function initializeEndNFTDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external nonReentrant {
        _initializeEndNFTDelegation(delegationID, includeUptimeProof, messageIndex);
    }

    /**
    * @notice See {IERC721Manager-completeEndNFTDelegation}.
    *
    */
    function completeEndNFTDelegation(
        bytes32 delegationID
    ) external nonReentrant {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();
        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];

        // Ensure the delegator is pending removed. Since anybody can call this function once
        // end delegation has been initialized, we need to make sure that this function is only
        // callable after that has been done.
        if (delegator.status != DelegatorStatus.PendingRemoved) {
            revert InvalidDelegatorStatus(delegator.status);
        } 

        // if(block.timestamp < delegator.endedAt + $._posManager._unlockDuration) {
            // revert UnlockDurationNotPassed(uint64(block.timestamp));
        // }

        uint256[] memory tokenIDs = _completeEndNFTDelegation(delegationID);
        _unlockNFTs(delegator.owner, tokenIDs);
    }

    /**
    * @notice See {IERC721Manager-registerNFTRedelegation}.
    */
    function registerNFTRedelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex,
        bytes32 nextValidationID
    ) external nonReentrant {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();
        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];

        _initializeEndNFTDelegation(delegationID, includeUptimeProof, messageIndex);
        uint256[] memory tokenIDs = _completeEndNFTDelegation(delegationID);
        _registerNFTDelegation(nextValidationID, delegator.owner, tokenIDs);
    }

    /**
     * @notice See {IERC721Manager-erc721}.
     */
    function erc721() external view returns (IERC721) {
        return _getERC721ManagerStorage()._token;
    }

    /**
     * @notice See {PoSValidatorManager-_unlock}
     * Note: Must be guarded with reentrancy guard for safe transfer.
     */
    function _lockNFTs(address from, uint256[] memory tokenIDs) internal returns (uint256) {
        for (uint256 i = 0; i < tokenIDs.length; i++) {
            _getERC721ManagerStorage()._token.safeTransferFrom(from, address(this), tokenIDs[i]);
        }
        return tokenIDs.length;
    }

    /**
     * @notice See {PoSValidatorManager-_unlock}
     * Note: Must be guarded with reentrancy guard for safe transfer.
     */
    function _unlockNFTs(address to, uint256[] memory tokenIDs) internal virtual {
        for (uint256 i = 0; i < tokenIDs.length; i++) {
            _getERC721ManagerStorage()._token.safeTransferFrom(address(this), to, tokenIDs[i]);
        }
    }

    /**
     * @notice Converts a token value to a weight.
     * @param value Token value to convert.
     */
    function valueToWeightNFT(uint256 value) public pure returns (uint64) {
        return uint64(value * (10**6));
    }

    function _incrementAndGetNonce(bytes32 validationID) internal returns (uint64) {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();
        return ++$._validationNonce[validationID];
    }

    
    /**
    * @notice Registers a new NFT-based delegation for a specified validator and delegator.
    * @dev This function validates the input parameters, ensures the validator is active and a PoS validator,
    *      and creates a new NFT delegation. It assigns the delegation a unique ID and updates the validator's state.
    *      The delegation is marked as active and associated with the provided token IDs.
    * @param validationID The unique identifier of the validator for which the NFT delegation is being registered.
    * @param delegatorAddress The address of the delegator registering the NFT delegation.
    * @param tokenIDs An array of token IDs representing the NFT delegation's weight.
    * @return delegationID A unique identifier for the newly created NFT delegation.
    *
    * Reverts if:
    * - The specified validator is not a PoS validator (`ValidatorNotPoS`).
    * - The validator is not in an active state (`InvalidValidatorStatus`).
    *
    * Emits:
    * - `DelegatorAddedNFT` when the NFT delegation is successfully registered, providing details about the delegation.
    */
    function _registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress,
        uint256[] memory tokenIDs
    ) internal returns (bytes32) {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();
        uint64 weight = valueToWeightNFT(tokenIDs.length);

        // Ensure the validation period is active
        Validator memory validator = $._posManager.getValidator(validationID);


        // if (!_isPoSValidator(validationID)) {
            // revert ValidatorNotPoS(validationID);
        // }
        if (validator.status != ValidatorStatus.Active) {
            revert InvalidValidatorStatus(validator.status);
        }

        uint64 nonce = _incrementAndGetNonce(validationID);

        // Update the delegation status
        bytes32 delegationID = keccak256(abi.encodePacked(validationID, nonce));
        $._delegatorNFTStakes[delegationID].owner = delegatorAddress;
        $._delegatorNFTStakes[delegationID].validationID = validationID;
        $._delegatorNFTStakes[delegationID].weight = weight;
        $._delegatorNFTStakes[delegationID].status = DelegatorStatus.Active;
        $._delegatorNFTStakes[delegationID].startedAt = uint64(block.timestamp);
        $._delegatorNFTStakes[delegationID].tokenIDs = tokenIDs;

        $._accountNFTDelegations[delegatorAddress].push(delegationID);
        $._validatorNFTDelegations[validationID].push(delegationID);

        emit DelegatorAddedNFT({
            delegationID: delegationID,
            validationID: validationID,
            delegatorAddress: delegatorAddress,
            nonce: nonce,
            delegatorWeight: weight,
            tokenIDs: tokenIDs
        }); 
        return delegationID;
    }

   /**
    * @notice Initiates the process of ending an NFT delegation for a given delegation ID.
    * @dev This function ensures that the delegation is active and validates that the caller is authorized to end it.
    *      If the validator status is valid, the delegation status is updated to `PendingRemoved`.
    *      Optionally, an uptime proof can be included during the process.
    * @param delegationID The unique identifier of the NFT delegation to be ended.
    * @param includeUptimeProof A boolean indicating whether to include an uptime proof during the delegation termination process.
    * @param messageIndex The index of the Warp message for obtaining the uptime proof, if `includeUptimeProof` is `true`.
    *
    * Reverts if:
    * - The delegation is not active (`InvalidDelegatorStatus`).
    * - The caller is not authorized to end the delegation (`UnauthorizedOwner`).
    * - The minimum stake duration has not passed for the validator or the delegator (`MinStakeDurationNotPassed`).
    * - The validator is not in a valid state to end the delegation (`InvalidValidatorStatus`).
    */
    function _initializeEndNFTDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();
        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];

        bytes32 validationID = delegator.validationID;
        Validator memory validator = $._posManager.getValidator(validationID);
        PoSValidatorInfo memory posValidator = $._posManager.getPoSValidatorInfo(validationID);

        // Ensure the delegator is active
        if (delegator.status != DelegatorStatus.Active) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        // Only the delegation owner or parent validator can end the delegation.
        if (delegator.owner != _msgSender()) {
            // Validators can only remove delegations after the minimum stake duration has passed.
            if (posValidator.owner != _msgSender()) {
                revert UnauthorizedOwner(_msgSender());
            }

            if (
                block.timestamp
                    < validator.startedAt + posValidator.minStakeDuration
            ) {
                revert MinStakeDurationNotPassed(uint64(block.timestamp));
            }
        }

        if (validator.status == ValidatorStatus.Active || validator.status == ValidatorStatus.Completed) {
            // Check that minimum stake duration has passed.
            // if (validator.status != ValidatorStatus.Completed && block.timestamp < delegator.startedAt + $._minimumStakeDuration) {
                // revert MinStakeDurationNotPassed(uint64(block.timestamp));
            // }

            // if (includeUptimeProof) {
                // _updateUptime(validationID, messageIndex);
            // }

            $._delegatorNFTStakes[delegationID].status = DelegatorStatus.PendingRemoved;
            $._delegatorNFTStakes[delegationID].endedAt = uint64(block.timestamp);
            // emit DelegatorRemovalInitialized(delegationID, validationID);
        } else {
            revert InvalidValidatorStatus(validator.status);
        }
    }

    /**
    * @notice Completes the process of ending an NFT delegation and returns the associated token IDs.
    * @dev This function removes the delegation from the validator and account, retrieves the associated NFTs,
    *      and clears the delegation data from storage. It emits a `DelegationEnded` event upon completion.
    * @param delegationID The unique identifier of the NFT delegation to be completed.
    * @return tokenIDs An array of token IDs associated with the completed delegation.
    *
    * Emits:
    * - `DelegationEnded` when the delegation is successfully completed and removed from storage.
    */
    function _completeEndNFTDelegation(
        bytes32 delegationID
    ) internal returns (uint256[] memory tokenIDs) {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();

        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];
        bytes32 validationID = delegator.validationID;

        _removeNFTDelegationFromValidator(validationID, delegationID);

        tokenIDs = $._delegatorNFTStakes[delegationID].tokenIDs;

        // Once this function completes, the delegation is completed so we can clear it from state now.
        delete $._delegatorNFTStakes[delegationID];
        // emit DelegationEnded(delegationID, validationID, 0, 0);

        return tokenIDs;
    }

    function _removeNFTDelegationFromValidator(bytes32 validationID, bytes32 delegationID) internal {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();
        bytes32[] storage delegations = $._validatorNFTDelegations[validationID];

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


    function updateBalanceTracker(bytes32 validationID) external returns (int256) {
        ERC721ManagerStorage storage $ = _getERC721ManagerStorage();
        PoSValidatorInfo memory validatorInfo = $._posManager.getPoSValidatorInfo(validationID);

        uint256 valWeight;
        valWeight += $._posManager.calculateEffectiveWeight(
            valueToWeightNFT($._validationNFTs[validationID].length),
            validatorInfo.uptimeSeconds,
            validatorInfo.prevEpochUptimeSeconds
        );

        bytes32[] memory delegations = $._validatorNFTDelegations[validationID];
        for (uint256 i = 0; i < delegations.length; i++) {
            DelegatorNFT memory delegator = $._delegatorNFTStakes[delegations[i]];
            if (delegator.status == DelegatorStatus.Active) {
                uint256 delegateEffectiveWeight = $._posManager.calculateEffectiveWeight(
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
                $._balanceTrackerNFT.balanceTrackerHook(delegator.owner, delBalance, false);
            }
        }

        int256 delta = int256(valWeight) - int256(validatorInfo.rewardBalance);
        validatorInfo.rewardBalance = valWeight;


        uint256 valBalance = uint256(int256($._accountRewardBalance[validatorInfo.owner]) + delta);
        $._accountRewardBalance[validatorInfo.owner] = valBalance;
        $._balanceTrackerNFT.balanceTrackerHook(validatorInfo.owner, valBalance, false);
    }
}
