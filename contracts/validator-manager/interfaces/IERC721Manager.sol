// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {IValidatorManager, ValidatorManagerSettings} from "./IValidatorManager.sol";
import {DelegatorStatus} from "./IPoSValidatorManager.sol";
import {IERC721TokenStakingManager} from "./IERC721TokenStakingManager.sol";
import {IBalanceTracker} from "@euler-xyz/reward-streams@1.0.0/interfaces/IBalanceTracker.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";

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
struct ERC721ManagerSettings {
    IERC721 _token;
    IERC721TokenStakingManager _posManager;
    uint256 minimumNFTAmount;
    uint256 maximumNFTAmount;
    IBalanceTracker balanceTrackerNFT;
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
 * @notice Interface for Proof of Stake Validator Managers
 */
interface IERC721Manager {
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

    function registerValidator(
        bytes32 validationID,
        address validator,
        uint256[] memory tokenIDs
    ) external returns (bytes32);

    function unregisterValidator(
        bytes32 validationID,
        address validator
    ) external returns (bytes32);
}
