// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {PoSValidatorManager} from "./PoSValidatorManager.sol";
import {
    PoSValidatorManagerSettings
    // PoSValidatorManagerStorage
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
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Address} from "@openzeppelin/contracts@5.0.2/utils/Address.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ICMInitializable} from "@utilities/ICMInitializable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable@5.0.2/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable@5.0.2/access/AccessControlUpgradeable.sol";

import {WarpMessage} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";

import {ValidatorMessages} from "./ValidatorMessages.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

/**
 * @dev Implementation of the {IERC721TokenStakingManager} interface.
 *
 * @custom:security-contact https://github.com/ava-labs/icm-contracts/blob/main/SECURITY.md
 */
contract ERC721TokenStakingManager is
    Initializable,
    AccessControlUpgradeable,
    PoSValidatorManager,
    IERC721TokenStakingManager,
    IERC721Receiver
{
    using Address for address payable;
    using SafeERC20 for IERC20;

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

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    modifier onlyOperator() {
        require(hasRole(OPERATOR_ROLE, msg.sender), "ERC721TokenStakingManager: caller is not an operator");
        _;
    }

    constructor(ICMInitializable init) {
        if (init == ICMInitializable.Disallowed) {
            _disableInitializers();
            _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
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

    // solhint-disable-next-line func-name-mixedcase
    function __ERC721TokenStakingManager_init(
        PoSValidatorManagerSettings calldata settings,
        IERC721 stakingToken
    ) internal onlyInitializing {
        __POS_Validator_Manager_init(settings);
        __ERC721TokenStakingManager_init_unchained(stakingToken);
    }

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
        // The stake is unlocked whether the validation period is completed or invalidated.
        _unlock(owner, weightToValue(validator.startingWeight));

        _unlockNFTs(owner, $._posValidatorInfo[validationID].tokenIDs);
    }

    function registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress,
        uint256[] memory tokenIDs
    ) external nonReentrant returns (bytes32) {
        _lockNFTs(tokenIDs);
        return _registerNFTDelegation(validationID, delegatorAddress, tokenIDs);
    }

    function endNFTDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external nonReentrant {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];

        if(block.timestamp < delegator.startedAt + $._unlockDelegateDuration) {
            revert UnlockDelegateDurationNotPassed(uint64(block.timestamp));
        }

        uint256[] memory tokenIDs = _endNFTDelegation(delegationID, includeUptimeProof, messageIndex);
        _unlockNFTs(delegator.owner, tokenIDs);
    }

    function registerNFTRedelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex,
        bytes32 nextValidationID
    ) external nonReentrant {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];

        uint256[] memory tokenIDs = _endNFTDelegation(delegationID, includeUptimeProof, messageIndex);
        _registerNFTDelegation(nextValidationID, delegator.owner, tokenIDs);
    }

    /**
     * @notice Returns the ERC721 token being staked
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
    function valueToWeightNFT(uint256 value) public view returns (uint64) {
        return uint64(value * (10**6));
    }


    /**
     * @notice See {PoSValidatorManager-_reward}
     * @dev Distributes ERC20 rewards to stakers
     */
    function _reward(address account, uint256 amount) internal virtual override {
    }

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
        uint256 lockedValue = _lock(stakeAmount);

        // Lock NFTs in the contract
        uint64 nftWeight = valueToWeightNFT(_lockNFTs(tokenIDs));

        uint64 weight = valueToWeight(lockedValue);
        bytes32 validationID = _initializeValidatorRegistration(registrationInput, weight);

        address owner = _msgSender();

        $._posValidatorInfo[validationID].owner = owner;
        $._posValidatorInfo[validationID].delegationFeeBips = delegationFeeBips;
        $._posValidatorInfo[validationID].minStakeDuration = minStakeDuration;
        $._posValidatorInfo[validationID].uptimeSeconds = 0;
        $._posValidatorInfo[validationID].tokenIDs = tokenIDs;
        $._posValidatorInfo[validationID].nftWeight = nftWeight;
        $._rewardRecipients[validationID] = owner;

        return validationID;
    }

    function _registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress,
        uint256[] memory tokenIDs
    ) internal returns (bytes32) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        uint64 weight = valueToWeightNFT(tokenIDs.length);

        // Ensure the validation period is active
        Validator memory validator = getValidator(validationID);
        // Check that the validation ID is a PoS validator
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

        _addNFTDelegationToValidator(validationID, delegationID);

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
     * @notice See {IPoSValidatorManager-completeEndDelegation}.
     */
    function _endNFTDelegation(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal returns (uint256[] memory tokenIDs) {
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
            if (block.timestamp < delegator.startedAt + $._minimumStakeDuration) {
                revert MinStakeDurationNotPassed(uint64(block.timestamp));
            }

            if (includeUptimeProof) {
                // Uptime proofs include the absolute number of seconds the validator has been active.
                _updateUptime(validationID, messageIndex);
            }

            $._delegatorNFTStakes[delegationID].status = DelegatorStatus.PendingRemoved;

            tokenIDs = $._delegatorNFTStakes[delegationID].tokenIDs;

            _removeNFTDelegationFromValidator(validationID, delegationID);

            // Once this function completes, the delegation is completed so we can clear it from state now.
            delete $._delegatorNFTStakes[delegationID];

            emit DelegationEnded(delegationID, validationID, 0, 0); 
        } else {
            revert InvalidValidatorStatus(validator.status);
        }
    }

    /**
     * @dev Helper function that extracts the uptime from a ValidationUptimeMessage Warp message
     * If the uptime is greater than the stored uptime, update the stored uptime.
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
            emit UptimeUpdated(validationID, uptime, 0);

            Validator memory validator = getValidator(validationID);

            // Update balance trackers for all active delegators
            if (validatorInfo.owner != address(0)) {
                uint256 totalDelegatorFeeWeight = _updateDelegatorBalances(validationID, uptime, validatorInfo.prevEpochUptimeSeconds);
                uint256 validatorEffectiveWeight = _calculateEffectiveWeight(
                    validator.startingWeight, 
                    uptime,
                    validatorInfo.prevEpochUptimeSeconds
                );
                $._balanceTracker.balanceTrackerHook(validatorInfo.owner, validatorEffectiveWeight + totalDelegatorFeeWeight, false);
            }

            // Update NFT balance trackers for all active delegators
            if (validatorInfo.owner != address(0)) {
                uint256 totalDelegatorFeeWeight = _updateDelegatorNFTBalances(validationID, uptime, validatorInfo.prevEpochUptimeSeconds);
                uint256 validatorEffectiveWeight = _calculateEffectiveWeight(
                    validatorInfo.nftWeight, 
                    uptime,
                    validatorInfo.prevEpochUptimeSeconds
                ); 
                $._balanceTrackerNFT.balanceTrackerHook(validatorInfo.owner, validatorEffectiveWeight + totalDelegatorFeeWeight, false);
            }
        } else {
            uptime = $._posValidatorInfo[validationID].uptimeSeconds;
        }

        return uptime;
    }

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

    function _calculateDelegatorFeeWeight(
        bytes32 validationID,
        uint256 delegateEffectiveWeight
    ) internal view returns (uint256) {
        return (delegateEffectiveWeight * _getPoSValidatorManagerStorage()._posValidatorInfo[validationID].delegationFeeBips)
            / BIPS_CONVERSION_FACTOR;
    }

    /**
     * @dev Returns array of active delegation IDs for a validator
     * @param validationID The validator's ID
     * @return Array of active delegation IDs
     */
    function _getActiveDelegations(bytes32 validationID) internal view returns (bytes32[] memory) {
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
     * @dev Returns array of active delegation IDs for a validator
     * @param validationID The validator's ID
     * @return Array of active delegation IDs
     */
    function _getActiveNFTDelegations(bytes32 validationID) internal view returns (bytes32[] memory) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        bytes32[] memory allDelegations = $._validatorNFTDelegations[validationID];

        // First pass to count active delegations
        uint256 activeCount = 0;
        for (uint256 i = 0; i < allDelegations.length; i++) {
            if ($._delegatorNFTStakes[allDelegations[i]].status == DelegatorStatus.Active) {
                activeCount++;
            }
        }
        // Second pass to fill active delegations array
        bytes32[] memory activeDelegations = new bytes32[](activeCount);
        uint256 activeIndex = 0;
        for (uint256 i = 0; i < allDelegations.length; i++) {
            if ($._delegatorNFTStakes[allDelegations[i]].status == DelegatorStatus.Active) {
                activeDelegations[activeIndex] = allDelegations[i];
                activeIndex++;
            }
        }
        return activeDelegations;
    }

    function _updateDelegatorBalances(bytes32 validationID, uint64 uptime, uint64 previousEpochUptime) internal returns(uint256){
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        bytes32[] memory activeDelegations = _getActiveDelegations(validationID);
        uint256 totalDelegatorFeeWeight;
            for (uint256 i = 0; i < activeDelegations.length; i++) {
                Delegator memory delegator = $._delegatorStakes[activeDelegations[i]];

                if (delegator.owner != address(0)) {
                    uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                        delegator.weight,
                        uptime,
                        previousEpochUptime
                    );
                    uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                    totalDelegatorFeeWeight += delegatorFeeWeight;
                    $._balanceTracker.balanceTrackerHook(delegator.owner, delegateEffectiveWeight - delegatorFeeWeight, false);
                }
            }
        return totalDelegatorFeeWeight;
    }

    function _updateDelegatorNFTBalances(bytes32 validationID, uint64 uptime, uint64 previousEpochUptime) internal returns(uint256){
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        bytes32[] memory activeDelegations = _getActiveNFTDelegations(validationID);
        uint256 totalDelegatorFeeWeight;
            for (uint256 i = 0; i < activeDelegations.length; i++) {
                DelegatorNFT memory delegator = $._delegatorNFTStakes[activeDelegations[i]];
                if (delegator.owner != address(0)) {
                    uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                        delegator.weight,
                        uptime,
                        previousEpochUptime
                    );
                    uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                    totalDelegatorFeeWeight += delegatorFeeWeight;
                    $._balanceTrackerNFT.balanceTrackerHook(delegator.owner, delegateEffectiveWeight - delegatorFeeWeight, false);
                }
            }
            return totalDelegatorFeeWeight;
    }

    /**
     * @dev Adds a delegation ID to a validator's delegation list
     * @param validationID The validator's ID
     * @param delegationID The delegation ID to add
     */
    function _addNFTDelegationToValidator(bytes32 validationID, bytes32 delegationID) internal {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        $._validatorNFTDelegations[validationID].push(delegationID);
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
