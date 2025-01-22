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
    ValidatorStatus
} from "./interfaces/IValidatorManager.sol";

import {
    Delegator,
    DelegatorNFT,
    ValidatorNFT,
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
import {console2} from "forge-std/console2.sol";

/**
 * @dev Implementation of the {IERC721TokenStakingManager} interface.
 *
 * @custom:security-contact https://github.com/ava-labs/icm-contracts/blob/main/SECURITY.md
 */
contract ERC721TokenStakingManager is
    Initializable,
    AccessControlUpgradeable,
    PoSValidatorManager,
    IERC721TokenStakingManager
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

        if(block.timestamp < delegator.endedAt + $._unlockDelegateDuration) {
            revert UnlockDelegateDurationNotPassed(uint64(block.timestamp));
        }

        uint256[] memory tokenIDs = _endNFTDelegation(delegationID, includeUptimeProof, messageIndex);
        _unlockNFTs(delegator.owner, tokenIDs);
    }

    function redelegateNFT(
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
    function _lockNFTs(uint256[] memory tokenIDs) internal virtual returns (uint256) {
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
        uint256[] memory nftTokenIDs
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
        if (nftTokenIDs.length < $._minimumNFTAmount || nftTokenIDs.length > $._maximumNFTAmount) {
            revert InvalidNFTAmount(nftTokenIDs.length);
        }
        // Lock the stake in the contract.
        uint256 lockedValue = _lock(stakeAmount);

        // Lock NFTs in the contract
        _lockNFTs(nftTokenIDs);

        uint64 weight = valueToWeight(lockedValue);
        bytes32 validationID = _initializeValidatorRegistration(registrationInput, weight);

        _addValidatorNft(validationID, stakeAmount);

        address owner = _msgSender();

        $._posValidatorInfo[validationID].owner = owner;
        $._posValidatorInfo[validationID].delegationFeeBips = delegationFeeBips;
        $._posValidatorInfo[validationID].minStakeDuration = minStakeDuration;
        $._posValidatorInfo[validationID].uptimeSeconds = 0;
        $._rewardRecipients[validationID] = owner;

        return validationID;
    }

    function _registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress,
        uint256[] memory tokenIDs
    ) internal returns (bytes32) {
        PoSValidatorManagerStorage storage $ = _getPoSValidatorManagerStorage();
        uint64 weight = valueToWeight(tokenIDs.length);

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
            $._delegatorNFTStakes[delegationID].endedAt = uint64(block.timestamp);

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

        if (uptime > $._validatorEpochUptime[validationID][currentEpoch]) {
            $._validatorEpochUptime[validationID][currentEpoch] = uptime;
            emit UptimeUpdated(validationID, uptime, currentEpoch);

            Validator memory validator = getValidator(validationID);
            address owner = $._posValidatorInfo[validationID].owner;
            uint64 previousEpochUptime = currentEpoch > 0 ? $._validatorEpochUptime[validationID][currentEpoch - 1] : 0;

            // Update balance trackers for all active delegators
            {
            uint256 totalDelegatorFeeWeight = _updateDelegatorBalances($, validationID, uptime, previousEpochUptime);

            if (owner != address(0)) {
                uint256 validatorEffectiveWeight = _calculateEffectiveWeight(
                    validator.startingWeight, 
                    uptime,
                    previousEpochUptime
            );
                $._balanceTracker.balanceTrackerHook(owner, validatorEffectiveWeight + totalDelegatorFeeWeight, false);
            }
            }

            // Update balance trackers for all active delegators
            {
            uint256 totalNFTDelegatorFeeWeight = _updateDelegatorNFTBalances($, validationID, uptime, previousEpochUptime);($, validationID, uptime, previousEpochUptime);

            if (owner != address(0)) {
                uint256 validatorEffectiveWeight = _calculateEffectiveWeight(
                    validator.startingWeight, 
                    uptime,
                    previousEpochUptime
            );
                $._balanceTrackerNFT.balanceTrackerHook(owner, validatorEffectiveWeight + totalNFTDelegatorFeeWeight, false);
            }
            }
        } else {
            uptime = $._validatorEpochUptime[validationID][currentEpoch]; 
        }

        return uptime;
    }
}