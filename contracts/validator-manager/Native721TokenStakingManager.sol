// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {StakingManager} from "./StakingManager.sol";
import {
    StakingManagerSettings
} from "./interfaces/IStakingManager.sol";
import {
    StakingManager
} from "./StakingManager.sol";

import {
    Delegator,
    DelegatorStatus,
    IStakingManager,
    PoSValidatorInfo,
    StakingManagerSettings
} from "./interfaces/IStakingManager.sol";
import {INative721TokenStakingManager} from "./interfaces/INative721TokenStakingManager.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {IERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/IERC20.sol";
import {Address} from "@openzeppelin/contracts@5.0.2/utils/Address.sol";
import {SafeERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/utils/SafeERC20.sol";
import {ICMInitializable} from "@utilities/ICMInitializable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable@5.0.2/proxy/utils/Initializable.sol";

import {WarpMessage} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";

import {ValidatorMessages} from "./ValidatorMessages.sol";
import {IERC721Receiver} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721Receiver.sol";

import {
    INativeTokenStakingManager, PChainOwner
} from "./interfaces/INativeTokenStakingManager.sol";
import {Validator, ValidatorStatus, PChainOwner} from "./ACP99Manager.sol";

/**
 * @dev Implementation of the {INative721TokenStakingManager} interface.
 *
 * @custom:security-contact https://github.com/ava-labs/icm-contracts/blob/main/SECURITY.md
 */
contract Native721TokenStakingManager is
    Initializable,
    StakingManager,
    INative721TokenStakingManager,
    IERC721Receiver
{
    using Address for address payable;

    // solhint-disable private-vars-leading-underscore
    /// @custom:storage-location erc7201:avalanche-icm.storage.Native721TokenStakingManager
    struct Native721TokenStakingManagerStorage {
        IERC721 _token;
    }
    // solhint-enable private-vars-leading-underscore

    // keccak256(abi.encode(uint256(keccak256("avalanche-icm.storage.Native721TokenStakingManager")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 public constant ERC721_STAKING_MANAGER_STORAGE_LOCATION =
        0xf2d79c30881febd0da8597832b5b1bf1f4d4b2209b19059420303eb8fcab8a00;

    error InvalidNFTAmount(uint256 nftAmount);
    error InvalidTokenAddress(address tokenAddress);


    // solhint-disable ordering
    function _getERC721StakingManagerStorage()
        private
        pure
        returns (Native721TokenStakingManagerStorage storage $)
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
     * @param stakingToken The ERC721 token to be staked
     */
    function initialize(
        StakingManagerSettings calldata settings,
        IERC721 stakingToken
    ) external reinitializer(2) {
        __Native721TokenStakingManager_init(settings, stakingToken);
    }

    /**
    * @notice Initializes both the PoS validator manager and the ERC721 token staking manager.
    * @dev This function initializes the parent contract (`StakingManager`) and then calls 
    *      the unchained initializer to set the ERC721 staking token. It ensures that the staking token 
    *      is properly initialized and ready for use in staking.
    * @param settings The settings for the PoS validator manager.
    * @param stakingToken The ERC721 token to be used for staking in the contract.
    */
    // solhint-disable-next-line func-name-mixedcase
    function __Native721TokenStakingManager_init(
        StakingManagerSettings calldata settings,
        IERC721 stakingToken
    ) internal onlyInitializing {
        __StakingManager_init(settings);
        __Native721TokenStakingManager_init_unchained(stakingToken);
    }

    /**
    * @notice Initializes the ERC721 token staking manager with the provided staking token.
    * @dev This function is called during the initialization of the contract to set the ERC721 token
    *      that will be used for staking. It ensures that the provided staking token address is valid
    *      and stores it in the contract's storage.
    * @param stakingToken The ERC721 token to be used for staking in the contract.
    *
    * Reverts if:
    * - The provided token address is the zero address (`InvalidTokenAddress`).
    */
    // solhint-disable-next-line func-name-mixedcase
    function __Native721TokenStakingManager_init_unchained(
        IERC721 stakingToken
    ) internal onlyInitializing {
        Native721TokenStakingManagerStorage storage $ = _getERC721StakingManagerStorage();

        if (address(stakingToken) == address(0)) {
            revert InvalidTokenAddress(address(stakingToken));
        }

        $._token = stakingToken;
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
     * @notice See {INativeTokenStakingManager-initiateValidatorRegistration}.
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
    ) external payable nonReentrant returns (bytes32) {
        return _initiateValidatorRegistration({
            nodeID: nodeID,
            blsPublicKey: blsPublicKey,
            registrationExpiry: registrationExpiry,
            remainingBalanceOwner: remainingBalanceOwner,
            disableOwner: disableOwner,
            delegationFeeBips: delegationFeeBips,
            minStakeDuration: minStakeDuration,
            stakeAmount: msg.value,
            tokenIDs: tokenIDs
        });
    }

    /**
     * @notice See {INativeTokenStakingManager-initiateDelegatorRegistration}.
     */
    function initiateDelegatorRegistration(bytes32 validationID)
        external
        payable
        nonReentrant
        returns (bytes32)
    {
        return _initiateDelegatorRegistration(validationID, _msgSender(), msg.value);
    }

    /**
     * @notice See {IStakingManager-completeValidatorRemoval}.
     * Extends the functionality of {ACP99Manager-completeValidatorRemoval} by unlocking staking rewards.
     */
    function completeValidatorRemoval(uint32 messageIndex)
        external override (IStakingManager, StakingManager)
        nonReentrant
        returns (bytes32)
    {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        // Check if the validator has been already been removed from the validator manager.
        bytes32 validationID = $._manager.completeValidatorRemoval(messageIndex);
        Validator memory validator = $._manager.getValidator(validationID);

        // Return now if this was originally a PoA validator that was later migrated to this PoS manager,
        // or the validator was part of the initial validator set.
        if (!_isPoSValidator(validationID)) {
            return validationID;
        }

        if(block.timestamp < validator.endTime + $._unlockDuration) {
            revert UnlockDurationNotPassed(uint64(block.timestamp));
        }

        address owner = $._posValidatorInfo[validationID].owner;

        // The stake is unlocked whether the validation period is completed or invalidated.
        _unlock(owner, weightToValue(validator.startingWeight));
        _unlockNFTs(owner, $._posValidatorInfo[validationID].tokenIDs);

        return validationID;
    }

    /**
    * @notice See {INative721TokenStakingManager-registerNFTDelegation}.
    *
    */
    function registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress,
        uint256[] memory tokenIDs
    ) external nonReentrant returns (bytes32) {
        _lockNFTs(tokenIDs);
        return _registerNFTDelegation(validationID, delegatorAddress, tokenIDs);
    }

    /**
    * @notice See {INative721TokenStakingManager-initializeEndNFTDelegation}.
    *
    */
    function initiateNFTDelegatorRemoval(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external nonReentrant {
        _initiateNFTDelegatorRemoval(delegationID, includeUptimeProof, messageIndex);
    }

    /**
    * @notice See {INative721TokenStakingManager-completeEndNFTDelegation}.
    *
    */
    function completeNFTDelegatorRemoval(
        bytes32 delegationID
    ) external nonReentrant {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        Delegator memory delegator = $._delegatorStakes[delegationID];

        // Ensure the delegator is pending removed. Since anybody can call this function once
        // end delegation has been initialized, we need to make sure that this function is only
        // callable after that has been done.
        if (delegator.status != DelegatorStatus.PendingRemoved) {
            revert InvalidDelegatorStatus(delegator.status);
        } 

        if(block.timestamp < delegator.endTime + $._unlockDuration) {
            revert UnlockDurationNotPassed(uint64(block.timestamp));
        }

        uint256[] memory tokenIDs = _completeNFTDelegatorRemoval(delegationID);
        _unlockNFTs(delegator.owner, tokenIDs);
    }

    /**
    * @notice See {INative721TokenStakingManager-registerNFTRedelegation}.
    */
    function registerNFTRedelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex,
        bytes32 nextValidationID
    ) external nonReentrant {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        Delegator memory delegator = $._delegatorStakes[delegationID];

        _initiateNFTDelegatorRemoval(delegationID, includeUptimeProof, messageIndex);
        uint256[] memory tokenIDs = _completeNFTDelegatorRemoval(delegationID);
        _registerNFTDelegation(nextValidationID, delegator.owner, tokenIDs);
    }

    /**
     * @notice See {INative721TokenStakingManager-erc721}.
     */
    function erc721() external view returns (IERC721) {
        return _getERC721StakingManagerStorage()._token;
    }

    /**
     * @notice See {StakingManager-_lock}
     */
    function _lock(uint256 value) internal virtual override returns (uint256) {
        return value;
    }

    /**
     * @notice See {StakingManager-_unlock}
     * Note: Must be guarded with reentrancy guard for safe transfer.
     */
    function _unlock(address to, uint256 value) internal virtual override {
        payable(to).sendValue(value);
    }

    /**
     * @notice See {StakingManager-_unlock}
     * Note: Must be guarded with reentrancy guard for safe transfer.
     */
    function _lockNFTs(uint256[] memory tokenIDs) internal returns (uint256) {
        for (uint256 i = 0; i < tokenIDs.length; i++) {
            _getERC721StakingManagerStorage()._token.safeTransferFrom(_msgSender(), address(this), tokenIDs[i]);
        }
        return tokenIDs.length;
    }

    /**
     * @notice See {StakingManager-_unlock}
     * Note: Must be guarded with reentrancy guard for safe transfer.
     */
    function _unlockNFTs(address to, uint256[] memory tokenIDs) internal virtual {
        for (uint256 i = 0; i < tokenIDs.length; i++) {
            _getERC721StakingManagerStorage()._token.transferFrom(address(this), to, tokenIDs[i]);
        }
    }

    /**
     * @notice Converts a token value to a weight.
     * @param value Token value to convert.
     */
    function valueToWeightNFT(uint256 value) public pure returns (uint64) {
        return uint64(value * (10**6));
    }

    /**
     * @notice See {StakingManager-_reward}
     * @dev Distributes ERC20 rewards to stakers
     */
    function _reward(address account, uint256 amount) internal virtual override {
    }

    /**
     * @notice Initiates validator registration. Extends the functionality of {ACP99Manager-_initiateValidatorRegistration}
     * by locking stake and setting staking and delegation parameters.
     * @param delegationFeeBips The delegation fee in basis points.
     * @param minStakeDuration The minimum stake duration in seconds.
     * @param stakeAmount The amount of stake to lock.
     */
    function _initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        uint64 registrationExpiry,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 stakeAmount,
        uint256[] memory tokenIDs
    ) internal virtual returns (bytes32) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
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

        if (tokenIDs.length < 1 || tokenIDs.length > $._maximumNFTAmount) {
            revert InvalidNFTAmount(tokenIDs.length);
        }

        // Lock the stake in the contract.
        uint64 weight = valueToWeight(_lock(stakeAmount));
        uint64 nftWeight = valueToWeightNFT(_lockNFTs(tokenIDs));

        bytes32 validationID = $._manager.initiateValidatorRegistration({
            nodeID: nodeID,
            blsPublicKey: blsPublicKey,
            registrationExpiry: registrationExpiry,
            remainingBalanceOwner: remainingBalanceOwner,
            disableOwner: disableOwner,
            weight: weight
        });

        address owner = _msgSender();

        $._posValidatorInfo[validationID].owner = owner;
        $._posValidatorInfo[validationID].delegationFeeBips = delegationFeeBips;
        $._posValidatorInfo[validationID].minStakeDuration = minStakeDuration;
        $._posValidatorInfo[validationID].uptimeSeconds = 0;
        $._posValidatorInfo[validationID].tokenIDs = tokenIDs;

        return validationID;
    }

    function _registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress,
        uint256[] memory tokenIDs
    ) internal returns (bytes32) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        uint64 weight = valueToWeightNFT(tokenIDs.length);

        // Ensure the validation period is active
        Validator memory validator = $._manager.getValidator(validationID);
        // Check that the validation ID is a PoS validator
        if (!_isPoSValidator(validationID)) {
            revert ValidatorNotPoS(validationID);
        }
        if (validator.status != ValidatorStatus.Active) {
            revert InvalidValidatorStatus(validator.status);
        }

        (uint64 nonce, bytes32 messageID) =
            $._manager.initiateValidatorWeightUpdate(validationID, validator.weight);

        // Update the delegation status
        bytes32 delegationID = keccak256(abi.encodePacked(validationID, nonce));
        $._delegatorStakes[delegationID].owner = delegatorAddress;
        $._delegatorStakes[delegationID].validationID = validationID;
        $._delegatorStakes[delegationID].weight = weight;
        $._delegatorStakes[delegationID].status = DelegatorStatus.Active;
        $._delegatorStakes[delegationID].startTime = uint64(block.timestamp);
        $._lockedNFTs[delegationID] = tokenIDs;

        $._validatorDelegations[validationID].push(delegationID);

        emit InitiatedDelegatorRegistration({
            delegationID: delegationID,
            validationID: validationID,
            delegatorAddress: delegatorAddress,
            nonce: nonce,
            validatorWeight: validator.weight,
            delegatorWeight: weight,
            setWeightMessageID: messageID
        });

        emit CompletedDelegatorRegistration({
            delegationID: delegationID,
            validationID: validationID,
            startTime: uint64(block.timestamp)
        });

        emit IsNFTDelegation({
            delegationID: delegationID,
            validationID: validationID,
            delegatorAddress: delegatorAddress,
            lockedNFTs: tokenIDs
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
    function _initiateNFTDelegatorRemoval(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;

        Validator memory validator = $._manager.getValidator(validationID);

        // Ensure the delegator is active
        if (delegator.status != DelegatorStatus.Active) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        if (delegator.owner != _msgSender()) {
            revert UnauthorizedOwner(_msgSender());
        }

        if (validator.status == ValidatorStatus.Active || validator.status == ValidatorStatus.Completed || validator.status == ValidatorStatus.PendingRemoved) {
            // Check that minimum stake duration has passed.
            if (validator.status != ValidatorStatus.Completed && block.timestamp < delegator.startTime + $._minimumStakeDuration) {
                revert MinStakeDurationNotPassed(uint64(block.timestamp));
            }

            if (includeUptimeProof) {
                _updateUptime(validationID, messageIndex);
            }

            $._delegatorStakes[delegationID].status = DelegatorStatus.PendingRemoved;
            $._delegatorStakes[delegationID].endTime = uint64(block.timestamp);
            emit InitiatedDelegatorRemoval(delegationID, validationID);
            if (validator.status == ValidatorStatus.Completed) {
                uint256[] memory tokenIDs = _completeNFTDelegatorRemoval(delegationID);
                _unlockNFTs(delegator.owner, tokenIDs);
                // If the validator has completed, then no further uptimes may be submitted, so we always
                // end the delegation.
            }
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
    function _completeNFTDelegatorRemoval(
        bytes32 delegationID
    ) internal returns (uint256[] memory tokenIDs) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;

        _removeDelegationFromValidator(validationID, delegationID);

        tokenIDs = $._lockedNFTs[delegationID];

        // Once this function completes, the delegation is completed so we can clear it from state now.
        delete $._delegatorStakes[delegationID];
        delete $._lockedNFTs[delegationID];

        emit CompletedDelegatorRemoval(delegationID, validationID, 0, 0);

        return tokenIDs;
    }

    function _updateBalanceTracker(bytes32 validationID) internal returns (int256) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        PoSValidatorInfo storage validatorInfo = $._posValidatorInfo[validationID];

        Validator memory validator = $._manager.getValidator(validationID);

        uint256 valWeight = _calculateEffectiveWeight(
            validator.startingWeight,
            validatorInfo.uptimeSeconds,
            validatorInfo.prevEpochUptimeSeconds
        );

        uint256 valNFTWeight = _calculateEffectiveWeight(
            valueToWeightNFT(validatorInfo.tokenIDs.length),
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
                
                // check if NFT delegation
                if($._lockedNFTs[delegations[i]].length == 0){
                    valWeight += delegatorFeeWeight;

                    uint256 accountBalance = uint256(int256($._accountRewardBalance[delegator.owner]) + int256(delWeight) - int256(delegator.rewardBalance));
                    delegator.rewardBalance = delWeight;

                    $._accountRewardBalance[delegator.owner] = accountBalance;
                    $._balanceTracker.balanceTrackerHook(delegator.owner, accountBalance, false);
                } else {
                    valNFTWeight += delegatorFeeWeight;

                    uint256 accountBalance = uint256(int256($._accountNFTRewardBalance[delegator.owner]) + int256(delWeight) - int256(delegator.rewardBalance));
                    delegator.rewardBalance = delWeight;

                    $._accountNFTRewardBalance[delegator.owner] = accountBalance;
                    $._balanceTrackerNFT.balanceTrackerHook(delegator.owner, accountBalance, false); 
                } 
            }
        }

        int256 delta = int256(valWeight) - int256(validatorInfo.rewardBalance);
        validatorInfo.rewardBalance = valWeight;

        uint256 valBalance = uint256(int256($._accountRewardBalance[validatorInfo.owner]) + delta);
        $._accountRewardBalance[validatorInfo.owner] = valBalance;
        $._balanceTracker.balanceTrackerHook(validatorInfo.owner, valBalance, false);

        int256 nftDelta = int256(valNFTWeight) - int256(validatorInfo.rewardBalanceNFT);
        validatorInfo.rewardBalanceNFT = valNFTWeight;

        uint256 valNFTBalance = uint256(int256($._accountNFTRewardBalance[validatorInfo.owner]) + nftDelta);
        $._accountNFTRewardBalance[validatorInfo.owner] = valNFTBalance;
        $._balanceTrackerNFT.balanceTrackerHook(validatorInfo.owner, valNFTBalance, false);
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

        StakingManagerStorage storage $ = _getStakingManagerStorage();
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
            revert UnexpectedValidationID(uptimeValidationID, validationID);
        }

        uint64 currentEpoch = uint64(block.timestamp / $._epochDuration);

        PoSValidatorInfo storage validatorInfo = $._posValidatorInfo[validationID];
        Validator memory validator = $._manager.getValidator(validationID);

        if (uptime > validatorInfo.uptimeSeconds || currentEpoch > validatorInfo.currentEpoch) {
            if(currentEpoch > validatorInfo.currentEpoch){
                validatorInfo.currentEpoch = currentEpoch;
                validatorInfo.prevEpochUptimeSeconds = validatorInfo.uptimeSeconds;
            }
            validatorInfo.uptimeSeconds = uptime;
            emit UptimeUpdated(validationID, uptime, currentEpoch);

            _updateBalanceTracker(validationID);
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
    */
    function _calculateEffectiveWeight(
         uint256 weight,
         uint64 currentUptime,
         uint64 previousUptime
    ) internal view returns (uint256) {
        if(previousUptime > currentUptime || currentUptime == 0) {
            return 0;
        }
        // Calculate effective weight based on both weight and time period
        return (weight * (currentUptime - previousUptime)) / _getStakingManagerStorage()._epochDuration;
    }

}