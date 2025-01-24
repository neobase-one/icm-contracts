// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {PoSValidatorManager} from "./PoSValidatorManager.sol";
import {
    PoSValidatorManagerSettings
} from "./interfaces/IPoSValidatorManager.sol";
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
    DelegatorNFT,
    DelegatorStatus,
    IPoSValidatorManager,
    PoSValidatorInfo,
    PoSValidatorManagerSettings
} from "./interfaces/IPoSValidatorManager.sol";
import {
    ValidatorRegistrationInput
} from "./interfaces/IValidatorManager.sol";
import {IERC721TokenStakingManager} from "./interfaces/IERC721TokenStakingManager.sol";
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

/**
 * @dev Implementation of the {IERC721TokenStakingManager} interface.
 *
 * @custom:security-contact https://github.com/ava-labs/icm-contracts/blob/main/SECURITY.md
 */
contract ERC721TokenStakingManager is
    Initializable,
    PoSValidatorManager,
    IERC721TokenStakingManager,
    IERC721Receiver
{
    using Address for address payable;

    // solhint-disable private-vars-leading-underscore
    /// @custom:storage-location erc7201:avalanche-icm.storage.ERC721TokenStakingManager
    struct ERC721TokenStakingManagerStorage {
        IERC721 _token;
    }
    // solhint-enable private-vars-leading-underscore

    // keccak256(abi.encode(uint256(keccak256("avalanche-icm.storage.ERC721TokenStakingManager")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 public constant ERC721_STAKING_MANAGER_STORAGE_LOCATION =
        0xf2d79c30881febd0da8597832b5b1bf1f4d4b2209b19059420303eb8fcab8a00;

    error InvalidNFTAmount(uint256 nftAmount);
    error InvalidTokenAddress(address tokenAddress);


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
     * @param stakingToken The ERC721 token to be staked
     */
    function initialize(
        PoSValidatorManagerSettings calldata settings,
        IERC721 stakingToken
    ) external reinitializer(2) {
        __ERC721TokenStakingManager_init(settings, stakingToken);
    }

    /**
    * @notice Initializes both the PoS validator manager and the ERC721 token staking manager.
    * @dev This function initializes the parent contract (`PoSValidatorManager`) and then calls 
    *      the unchained initializer to set the ERC721 staking token. It ensures that the staking token 
    *      is properly initialized and ready for use in staking.
    * @param settings The settings for the PoS validator manager.
    * @param stakingToken The ERC721 token to be used for staking in the contract.
    */
    // solhint-disable-next-line func-name-mixedcase
    function __ERC721TokenStakingManager_init(
        PoSValidatorManagerSettings calldata settings,
        IERC721 stakingToken
    ) internal onlyInitializing {
        __POS_Validator_Manager_init(settings);
        __ERC721TokenStakingManager_init_unchained(stakingToken);
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
    function __ERC721TokenStakingManager_init_unchained(
        IERC721 stakingToken
    ) internal onlyInitializing {
        ERC721TokenStakingManagerStorage storage $ = _getERC721StakingManagerStorage();

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
        address rewardRecipient = $._rewardRecipients[validationID];
        delete $._rewardRecipients[validationID];

        // the reward-recipient should always be set, but just in case it isn't, we won't burn the reward
        if (rewardRecipient == address(0)) {
            rewardRecipient = owner;
        }

        // The validator can either be Completed or Invalidated here. We only grant rewards for Completed.
        if (validator.status == ValidatorStatus.Completed) {
            _withdrawValidationRewards(rewardRecipient, validationID);
        }

        _removeValidationFromAccount(owner, validationID);

        // The stake is unlocked whether the validation period is completed or invalidated.
        _unlock(owner, weightToValue(validator.startingWeight));
        _unlockNFTs(owner, $._posValidatorInfo[validationID].tokenIDs);

    }

    /**
    * @notice See {IERC721TokenStakingManager-registerNFTDelegation}.
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
    * @notice See {IERC721TokenStakingManager-initializeEndNFTDelegation}.
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
    * @notice See {IERC721TokenStakingManager-completeEndNFTDelegation}.
    *
    */
    function completeEndNFTDelegation(
        bytes32 delegationID
    ) external nonReentrant {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];

        // Ensure the delegator is pending removed. Since anybody can call this function once
        // end delegation has been initialized, we need to make sure that this function is only
        // callable after that has been done.
        if (delegator.status != DelegatorStatus.PendingRemoved) {
            revert InvalidDelegatorStatus(delegator.status);
        } 

        if(block.timestamp < delegator.endedAt + $._unlockDelegateDuration) {
            revert UnlockDelegateDurationNotPassed(uint64(block.timestamp));
        }

        uint256[] memory tokenIDs = _completeEndNFTDelegation(delegationID);
        _unlockNFTs(delegator.owner, tokenIDs);
    }

    /**
    * @notice See {IERC721TokenStakingManager-registerNFTRedelegation}.
    */
    function registerNFTRedelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex,
        bytes32 nextValidationID
    ) external nonReentrant {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];

        _initializeEndNFTDelegation(delegationID, includeUptimeProof, messageIndex);
        uint256[] memory tokenIDs = _completeEndNFTDelegation(delegationID);
        _registerNFTDelegation(nextValidationID, delegator.owner, tokenIDs);
    }

    /**
     * @notice See {IERC721TokenStakingManager-erc721}.
     */
    function erc721() external view returns (IERC721) {
        return _getERC721StakingManagerStorage()._token;
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
     * @notice See {PoSValidatorManager-_unlock}
     * Note: Must be guarded with reentrancy guard for safe transfer.
     */
    function _lockNFTs(uint256[] memory tokenIDs) internal returns (uint256) {
        for (uint256 i = 0; i < tokenIDs.length; i++) {
            _getERC721StakingManagerStorage()._token.safeTransferFrom(_msgSender(), address(this), tokenIDs[i]);
        }
        return tokenIDs.length;
    }

    /**
     * @notice See {PoSValidatorManager-_unlock}
     * Note: Must be guarded with reentrancy guard for safe transfer.
     */
    function _unlockNFTs(address to, uint256[] memory tokenIDs) internal virtual {
        for (uint256 i = 0; i < tokenIDs.length; i++) {
            _getERC721StakingManagerStorage()._token.safeTransferFrom(address(this), to, tokenIDs[i]);
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
     * @notice See {PoSValidatorManager-_reward}
     * @dev Distributes ERC20 rewards to stakers
     */
    function _reward(address account, uint256 amount) internal virtual override {
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
        if (tokenIDs.length < $._minimumNFTAmount || tokenIDs.length > $._maximumNFTAmount) {
            revert InvalidNFTAmount(tokenIDs.length);
        }
        // Lock the stake in the contract.
        
        uint64 weight = valueToWeight(_lock(stakeAmount));
        uint64 nftWeight = valueToWeightNFT(_lockNFTs(tokenIDs));

        bytes32 validationID = _initializeValidatorRegistration(registrationInput, weight);

        address owner = _msgSender();
        $._posValidatorInfo[validationID].owner = owner;
        $._posValidatorInfo[validationID].delegationFeeBips = delegationFeeBips;
        $._posValidatorInfo[validationID].minStakeDuration = minStakeDuration;
        $._posValidatorInfo[validationID].weight = weight;
        $._posValidatorInfo[validationID].tokenIDs = tokenIDs;
        $._posValidatorInfo[validationID].nftWeight = nftWeight;

        $._accountValidations[owner].push(validationID);

        return validationID;
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
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        uint64 weight = valueToWeightNFT(tokenIDs.length);

        // Ensure the validation period is active
        Validator memory validator = getValidator(validationID);
        if (!_isPoSValidator(validationID)) {
            revert ValidatorNotPoS(validationID);
        }
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
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];
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

        if (validator.status == ValidatorStatus.Active || validator.status == ValidatorStatus.Completed) {
            // Check that minimum stake duration has passed.
            if (validator.status != ValidatorStatus.Completed && block.timestamp < delegator.startedAt + $._minimumStakeDuration) {
                revert MinStakeDurationNotPassed(uint64(block.timestamp));
            }

            if (includeUptimeProof) {
                _updateUptime(validationID, messageIndex);
            }

            $._delegatorNFTStakes[delegationID].status = DelegatorStatus.PendingRemoved;
            $._delegatorNFTStakes[delegationID].endedAt = uint64(block.timestamp);
            emit DelegatorRemovalInitialized(delegationID, validationID);
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
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;

        _removeNFTDelegationFromValidator(validationID, delegationID);
        _removeNFTDelegationFromAccount(delegator.owner, delegationID);

        tokenIDs = $._delegatorNFTStakes[delegationID].tokenIDs;

        // Once this function completes, the delegation is completed so we can clear it from state now.
        delete $._delegatorStakes[delegationID];
        emit DelegationEnded(delegationID, validationID, 0, 0);

        return tokenIDs;
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

            if (validatorInfo.owner != address(0)) {
                (uint256 valWeight, uint256 valNftWeight) = _calculateAccountWeight(validatorInfo.owner);
                $._balanceTracker.balanceTrackerHook(validatorInfo.owner, valWeight, false);
                $._balanceTrackerNFT.balanceTrackerHook(validatorInfo.owner, valNftWeight, false);

                bytes32[] memory delegations = $._validatorDelegations[validationID];
                for (uint256 j = 0; j < delegations.length; j++) {
                    Delegator memory delegator = $._delegatorStakes[delegations[j]];
                    if (delegator.owner != address(0)) {
                        (uint256 weight, uint256 nftWeight) = _calculateAccountWeight(delegator.owner);
                        $._balanceTracker.balanceTrackerHook(delegator.owner, weight, false);
                    }
                }

                bytes32[] memory nftDelegations = $._validatorNFTDelegations[validationID];
                for (uint256 j = 0; j < nftDelegations.length; j++) {
                    DelegatorNFT memory delegator = $._delegatorNFTStakes[nftDelegations[j]];
                    if (delegator.owner != address(0)) {
                        (uint256 weight, uint256 nftWeight) = _calculateAccountWeight(delegator.owner);
                        $._balanceTrackerNFT.balanceTrackerHook(delegator.owner, nftWeight, false);
                    }
                }
            }
        } else {
            uptime = $._posValidatorInfo[validationID].uptimeSeconds;
        }
        return uptime;
    }

    /**
    * @notice Calculates the total weight and NFT weight for a given account based on its roles as a validator, delegator, and NFT delegator.
    * @dev This function aggregates the weight and NFT weight of an account by summing:
    *      - The account's weight as a validator.
    *      - Delegation fee weights from delegators for the account's validations.
    *      - The account's weight as a delegator and NFT delegator for other validators.
    * @param account The address of the account for which the weights are being calculated.
    * @return weight The total weight of the account, including its validator and delegator weights.
    * @return nftWeight The total NFT weight of the account, including its NFT validator and NFT delegator weights.
    */
    function _calculateAccountWeight(
        address account
    ) internal view returns (uint256, uint256) {
        uint256 weight;
        uint256 nftWeight;
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();

        // sum weights as validator
        for (uint256 i = 0; i < $._accountValidations[account].length; i++) {
            bytes32 validationID = $._accountValidations[account][i];
            weight += _calculateEffectiveWeight(
                $._posValidatorInfo[validationID].weight,
                $._posValidatorInfo[validationID].uptimeSeconds,
                $._posValidatorInfo[validationID].prevEpochUptimeSeconds
            );
            nftWeight += _calculateEffectiveWeight(
                $._posValidatorInfo[validationID].nftWeight,
                $._posValidatorInfo[validationID].uptimeSeconds,
                $._posValidatorInfo[validationID].prevEpochUptimeSeconds
            );
            // add the weight of all active delegation fees
            bytes32[] memory delegations = $._validatorDelegations[validationID];
            for (uint256 j = 0; j < delegations.length; j++) {
                Delegator memory delegator = $._delegatorStakes[delegations[j]];
                if (delegator.status == DelegatorStatus.Active) {
                    uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                        delegator.weight,
                        $._posValidatorInfo[validationID].uptimeSeconds,
                        $._posValidatorInfo[validationID].prevEpochUptimeSeconds
                    );
                    uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                    weight += delegatorFeeWeight;
                }
            }
            // add the weight of all active NFT delegation fees
            bytes32[] memory nftDelegations = $._validatorNFTDelegations[validationID];
            for (uint256 j = 0; j < nftDelegations.length; j++) {
                DelegatorNFT memory delegator = $._delegatorNFTStakes[nftDelegations[j]];
                if (delegator.status == DelegatorStatus.Active) {
                    uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                        delegator.weight,
                        $._posValidatorInfo[validationID].uptimeSeconds,
                        $._posValidatorInfo[validationID].prevEpochUptimeSeconds
                    );
                    uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                    nftWeight += delegatorFeeWeight;
                }
            }
        }

        // sum weights as delegator
        for (uint256 i = 0; i < $._accountDelegations[account].length; i++) {
            bytes32 delegationID = $._accountDelegations[account][i];
            Delegator memory delegator = $._delegatorStakes[delegationID];
            if (delegator.owner != address(0)) {
                uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                    delegator.weight,
                    $._posValidatorInfo[delegator.validationID].uptimeSeconds,
                    $._posValidatorInfo[delegator.validationID].prevEpochUptimeSeconds
                );
                uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[delegator.validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                weight += delegateEffectiveWeight - delegatorFeeWeight;
            }   
        }

        // sum weights as NFT delegator
        for (uint256 i = 0; i < $._accountNFTDelegations[account].length; i++) {
            bytes32 delegationID = $._accountNFTDelegations[account][i];
            DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];
            if (delegator.owner != address(0)) {
                uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                    delegator.weight,
                    $._posValidatorInfo[delegator.validationID].uptimeSeconds,
                    $._posValidatorInfo[delegator.validationID].prevEpochUptimeSeconds
                );
                uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[delegator.validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                nftWeight += delegateEffectiveWeight - delegatorFeeWeight;
            }   
        }
        return (weight, nftWeight);
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
        return (weight * (currentUptime - previousUptime)) / _getPoSValidatorManagerStorage()._epochDuration;
    }

    /**
     * @dev Removes a delegation ID from a validator's delegation list
     * @param account The validator's ID
     * @param delegationID The delegation ID to remove
     */
    function _removeNFTDelegationFromAccount(address account, bytes32 delegationID) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        bytes32[] storage delegations = $._accountNFTDelegations[account];

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
     * @dev Removes a delegation ID from a validator's delegation list
     * @param validationID The validator's ID
     * @param delegationID The delegation ID to remove
     */
    function _removeNFTDelegationFromValidator(bytes32 validationID, bytes32 delegationID) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
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
}
