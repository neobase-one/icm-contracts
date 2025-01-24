// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {Test} from "@forge-std/Test.sol";
import {PoSValidatorManagerTest} from "./PoSValidatorManagerTests.t.sol";
import {ERC721TokenStakingManager} from "../ERC721TokenStakingManager.sol";
import {PoSValidatorManager, PoSValidatorManagerSettings} from "../PoSValidatorManager.sol";
import {ValidatorRegistrationInput, IValidatorManager, ValidatorStatus, Validator} from "../interfaces/IValidatorManager.sol";
import {ExampleRewardCalculator} from "../ExampleRewardCalculator.sol";
import {ICMInitializable} from "../../utilities/ICMInitializable.sol";
import {INativeMinter} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/INativeMinter.sol";
import {ValidatorManagerTest} from "./ValidatorManagerTests.t.sol";
import {Initializable} from "@openzeppelin/contracts@5.0.2/proxy/utils/Initializable.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {ITrackingRewardStreams} from "@euler-xyz/reward-streams@1.0.0/interfaces/IRewardStreams.sol";
import {ExampleERC721} from "@mocks/ExampleERC721.sol";
import {ExampleERC20} from "@mocks/ExampleERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/IERC20.sol";
import {EthereumVaultConnector} from "evc/EthereumVaultConnector.sol";
import {TrackingRewardStreams} from "@euler-xyz/reward-streams@1.0.0/TrackingRewardStreams.sol";
import {ValidatorMessages} from "../ValidatorMessages.sol";
import {ValidatorManager} from "../ValidatorManager.sol";

contract ERC721TokenStakingManagerTest is PoSValidatorManagerTest, IERC721Receiver {
    using SafeERC20 for IERC20;

    ERC721TokenStakingManager public app;

    IERC721 public stakingToken;
    IERC20 public rewardToken;
    EthereumVaultConnector public evc;
    TrackingRewardStreams public balanceTracker;
    TrackingRewardStreams public balanceTrackerNFT;

    uint128 public constant REWARD_PER_EPOCH = 100e18;


    uint256 testTokenID = 0;

    function setUp() public override {
        ValidatorManagerTest.setUp();

        _setUp();
        _mockGetBlockchainID();
        _mockInitializeValidatorSet();

        app.initializeValidatorSet(_defaultConversionData(), 0);
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public virtual returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function testDisableInitialization() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Disallowed);
        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));

        app.initialize(_defaultPoSSettings(), stakingToken);
    }

    function testZeroStakingTokenAddress() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC721TokenStakingManager.InvalidTokenAddress.selector, address(0)
            )
        );
        app.initialize(_defaultPoSSettings(), IERC721(address(0)));
    }

    function testZeroMinimumDelegationFee() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(PoSValidatorManager.InvalidDelegationFee.selector, 0)
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.minimumDelegationFeeBips = 0;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testMaxMinimumDelegationFee() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        uint16 minimumDelegationFeeBips = app.MAXIMUM_DELEGATION_FEE_BIPS() + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                PoSValidatorManager.InvalidDelegationFee.selector, minimumDelegationFeeBips
            )
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.minimumDelegationFeeBips = minimumDelegationFeeBips;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testInvalidStakeAmountRange() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(
                PoSValidatorManager.InvalidStakeAmount.selector, DEFAULT_MAXIMUM_STAKE_AMOUNT
            )
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.minimumStakeAmount = DEFAULT_MAXIMUM_STAKE_AMOUNT;
        defaultPoSSettings.maximumStakeAmount = DEFAULT_MINIMUM_STAKE_AMOUNT;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testZeroMaxStakeMultiplier() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(PoSValidatorManager.InvalidStakeMultiplier.selector, 0)
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.maximumStakeMultiplier = 0;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testMaxStakeMultiplierOverLimit() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        uint8 maximumStakeMultiplier = app.MAXIMUM_STAKE_MULTIPLIER_LIMIT() + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                PoSValidatorManager.InvalidStakeMultiplier.selector, maximumStakeMultiplier
            )
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.maximumStakeMultiplier = maximumStakeMultiplier;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testZeroWeightToValueFactor() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(PoSValidatorManager.ZeroWeightToValueFactor.selector)
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.weightToValueFactor = 0;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testMinStakeDurationTooLow() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        uint64 minStakeDuration = DEFAULT_CHURN_PERIOD - 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                PoSValidatorManager.InvalidMinStakeDuration.selector, minStakeDuration
            )
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.minimumStakeDuration = minStakeDuration;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testDelegationRewards() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerDefaultDelegator(validationID);
 
        address rewardRecipient = address(42);
        
        _endValidationWithChecks({
            validationID: validationID,
            validatorOwner: address(this),
            completeRegistrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP,
            completionTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION,
            validatorWeight: DEFAULT_WEIGHT,
            expectedNonce: 2,
            rewardRecipient: address(this)
        });

        // Validator is Completed, so this will also complete the delegation.
        _initializeEndDelegation({
            sender: DEFAULT_DELEGATOR_ADDRESS,
            delegationID: delegationID,
            endDelegationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION + 1,
            includeUptime: true,
            force: true,
            rewardRecipient: rewardRecipient
        });

        vm.warp(block.timestamp + DEFAULT_EPOCH_DURATION);

        (uint256 validatorReward, uint256 delegatorReward) = _calculateExpectedRewards(
            DEFAULT_WEIGHT, DEFAULT_DELEGATOR_WEIGHT, DEFAULT_DELEGATION_FEE_BIPS);

        assertApproxEqRel(validatorReward, _claimReward(address(this)), 0.01e18);
        assertApproxEqRel(delegatorReward, _claimReward(DEFAULT_DELEGATOR_ADDRESS), 0.01e18);
    }

    function testNFTDelegationRewards() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);

        _endValidationWithChecks({
            validationID: validationID,
            validatorOwner: address(this),
            completeRegistrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP,
            completionTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION,
            validatorWeight: DEFAULT_WEIGHT,
            expectedNonce: 2,
            rewardRecipient: address(this)
        });

        uint64 uptime = DEFAULT_COMPLETION_TIMESTAMP - DEFAULT_REGISTRATION_TIMESTAMP;
        bytes memory uptimeMessage =
            ValidatorMessages.packValidationUptimeMessage(validationID, uptime);
        _mockGetUptimeWarpMessage(uptimeMessage, true);

        _endNFTDelegation(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );
        _expectNFTStakeUnlock(DEFAULT_DELEGATOR_ADDRESS, 1);
        
        vm.warp(block.timestamp + DEFAULT_EPOCH_DURATION);

        (uint256 validatorReward, uint256 delegatorReward) = _calculateExpectedRewards(
            1e6, 1e6, DEFAULT_DELEGATION_FEE_BIPS);

        assertApproxEqRel(validatorReward, _claimRewardNFT(address(this)), 0.01e18);
        assertApproxEqRel(delegatorReward, _claimRewardNFT(DEFAULT_DELEGATOR_ADDRESS), 0.01e18);
    }

    function testEndNFTDelegationRevertBeforeUnlock() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);
       
        vm.expectRevert(
            abi.encodeWithSelector(
                PoSValidatorManager.UnlockDelegateDurationNotPassed.selector, block.timestamp
            )
        );
        _endNFTDelegation(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );
    }

    function testValidationRegistrationWithInvalidNFTAmount() public {
         vm.expectRevert(
            abi.encodeWithSelector(
                ERC721TokenStakingManager.InvalidNFTAmount.selector, 0
            )
        );
        _initializeValidatorRegistrationWithoutNFT( 
            defaultRegistrationInput,
            DEFAULT_MINIMUM_DELEGATION_FEE_BIPS,
            DEFAULT_MINIMUM_STAKE_DURATION,
            DEFAULT_MINIMUM_STAKE_AMOUNT);
    }

    function testRevertEndDelgationForNonActive() public {
       bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);

        _endValidationWithChecks({
            validationID: validationID,
            validatorOwner: address(this),
            completeRegistrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP,
            completionTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION,
            validatorWeight: DEFAULT_WEIGHT,
            expectedNonce: 2,
            rewardRecipient: address(this)
        });

        uint64 uptime = DEFAULT_COMPLETION_TIMESTAMP - DEFAULT_REGISTRATION_TIMESTAMP;
        bytes memory uptimeMessage =
            ValidatorMessages.packValidationUptimeMessage(validationID, uptime);
        _mockGetUptimeWarpMessage(uptimeMessage, true);

        _endNFTDelegation(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );

         vm.expectRevert(
            abi.encodeWithSelector(
                PoSValidatorManager.InvalidDelegatorStatus.selector, 0
            )
        );

        _endNFTDelegation(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );
    }

     function testRevertEndDelgationForNonOwner() public {
       bytes32 validationID = _registerDefaultValidator();
       bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);

        _endValidationWithChecks({
            validationID: validationID,
            validatorOwner: address(this),
            completeRegistrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP,
            completionTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION,
            validatorWeight: DEFAULT_WEIGHT,
            expectedNonce: 2,
            rewardRecipient: address(this)
        });

        
         vm.expectRevert(
            abi.encodeWithSelector(
                PoSValidatorManager.UnauthorizedOwner.selector, address(app)
            )
        );
        _endNFTDelegationNonOwner(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );
        
    }

    function testRevertEndDelegationNFTForInvalidWarpSourceChainID() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);
        vm.warp(block.timestamp + DEFAULT_UNLOCK_DELEGATE_DURATION + 1);
        
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidatorManager.InvalidWarpSourceChainID.selector, address(0)
            )
        );
        _endNFTDelegation(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );
    }

    function testGetNFTStakingToken() public {
        address token = address(app.erc721());
        assertEq(token, address(stakingToken));
    }


    // Helpers
    function _calculateExpectedRewards(
        uint256 validatorStake,
        uint256 delegatorStake,
        uint256 delegationFeeBips
    ) internal returns (uint256 validatorReward, uint256 delegatorReward) {
        uint256 feeWeight = delegatorStake * delegationFeeBips / 10000;
        delegatorReward = (REWARD_PER_EPOCH * (delegatorStake - feeWeight)) / (delegatorStake + validatorStake);
        validatorReward = (REWARD_PER_EPOCH * (validatorStake + feeWeight)) / (delegatorStake + validatorStake);
    }

    function _initializeValidatorRegistration(
        ValidatorRegistrationInput memory registrationInput,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 stakeAmount
    ) internal virtual override returns (bytes32) {
        uint256[] memory tokens = new uint256[](1);
        tokens[0] = ++testTokenID;
        return app.initializeValidatorRegistration{value: stakeAmount}(
            registrationInput, delegationFeeBips, minStakeDuration, tokens
        );
    }

    function _initializeValidatorRegistrationWithoutNFT(
        ValidatorRegistrationInput memory registrationInput,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 stakeAmount
    ) internal returns (bytes32) {
        uint256[] memory tokens = new uint256[](0);
        return app.initializeValidatorRegistration{value: stakeAmount}(
            registrationInput, delegationFeeBips, minStakeDuration, tokens
        );
    }

    function testNFTRedelegation() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);
        
        address rewardRecipient = address(42);

        bytes32 nextValidationID = _registerValidator({
            nodeID: _newNodeID(),
            l1ID: DEFAULT_L1_ID,
            weight: DEFAULT_WEIGHT,
            registrationExpiry: DEFAULT_EXPIRY,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP
        });

        vm.warp(block.timestamp + DEFAULT_MINIMUM_STAKE_DURATION + 1);

        app.registerNFTRedelegation(delegationID, false, 0, nextValidationID);
    }

    function _initializeValidatorRegistration(
        ValidatorRegistrationInput memory input,
        uint64 weight
    ) internal virtual override returns (bytes32) {
        uint256[] memory tokens = new uint256[](1);
        tokens[0] = ++testTokenID;
        return app.initializeValidatorRegistration{value: _weightToValue(weight)}(
            input, DEFAULT_DELEGATION_FEE_BIPS, DEFAULT_MINIMUM_STAKE_DURATION, tokens
        );
    }

    function _initializeDelegatorRegistration(
        bytes32 validationID,
        address delegatorAddress,
        uint64 weight
    ) internal virtual override returns (bytes32) {
        uint256 value = _weightToValue(weight);
        vm.prank(delegatorAddress);
        vm.deal(delegatorAddress, value);
        return app.initializeDelegatorRegistration{value: value}(validationID);
    }

    function _registerNFTDelegation(
        bytes32 validationID,
        address delegatorAddress
    ) internal virtual returns (bytes32) {
        uint256[] memory tokens = new uint256[](1);
        tokens[0] = ++testTokenID;

        _beforeSendNFT(tokens[0], delegatorAddress);

        vm.prank(delegatorAddress);
        return app.registerNFTDelegation(validationID, delegatorAddress, tokens);
    }

    function _endNFTDelegation(
        address delegatorAddress,
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal virtual returns (bytes32) {
        vm.prank(delegatorAddress);
        app.endNFTDelegation(delegationID, includeUptimeProof, messageIndex);
    }
    function _endNFTDelegationNonOwner(
        address delegatorAddress,
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal virtual returns (bytes32) {
        vm.prank(address(app));
        app.endNFTDelegation(delegationID, includeUptimeProof, messageIndex);
    }

    // solhint-disable no-empty-blocks
    function _beforeSend(uint256 amount, address spender) internal override {
        // Native tokens no need pre approve
    }

    function _beforeSendNFT(uint256 tokenId, address spender) internal {
        stakingToken.transferFrom(address(this), spender, tokenId);

        vm.prank(spender);
        stakingToken.approve(address(app), tokenId);
    }

    function _expectStakeUnlock(address account, uint256 amount) internal override {
        // empty calldata implies the receive function will be called
        vm.expectCall(account, amount, "");
    }

    function _expectNFTStakeUnlock(address account, uint256 amount) internal {
        assertEq(stakingToken.balanceOf(account), amount);
    }

    function _expectRewardIssuance(address account, uint256 amount) internal override {
    }

    function _claimReward(address account) internal returns(uint256) {
        vm.prank(account);
        return balanceTracker.claimReward(address(app), address(rewardToken), account, false);
    }

    function _claimRewardNFT(address account) internal returns(uint256) {
        vm.prank(account);
        return balanceTrackerNFT.claimReward(address(app), address(rewardToken), account, false);
    }

    function _setUp() internal override returns (IValidatorManager) {
        // Construct the object under test
        app = new TestableERC721TokenStakingManager(ICMInitializable.Allowed);

        rewardCalculator = new ExampleRewardCalculator(DEFAULT_REWARD_RATE);
        stakingToken = new ExampleERC721();
        rewardToken = new ExampleERC20();        

        stakingToken.setApprovalForAll(address(app), true);

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.rewardCalculator = rewardCalculator;

        evc = new EthereumVaultConnector();
        balanceTracker = new TrackingRewardStreams(address(evc), DEFAULT_EPOCH_DURATION);
        balanceTrackerNFT = new TrackingRewardStreams(address(evc), DEFAULT_EPOCH_DURATION);
        defaultPoSSettings.balanceTracker = balanceTracker;
        defaultPoSSettings.balanceTrackerNFT = balanceTrackerNFT;

        rewardToken.approve(address(balanceTracker), REWARD_PER_EPOCH * 3);
        rewardToken.approve(address(balanceTrackerNFT), REWARD_PER_EPOCH * 3);
        uint128[] memory amounts = new uint128[](3);
        amounts[0] = REWARD_PER_EPOCH;
        amounts[1] = REWARD_PER_EPOCH;
        amounts[1] = REWARD_PER_EPOCH;

        balanceTracker.registerReward(address(app), address(rewardToken), 0, amounts);
        balanceTracker.enableReward(address(app), address(rewardToken));

        balanceTrackerNFT.registerReward(address(app), address(rewardToken), 0, amounts);
        balanceTrackerNFT.enableReward(address(app), address(rewardToken));

        vm.startPrank(DEFAULT_DELEGATOR_ADDRESS);
        balanceTracker.enableReward(address(app), address(rewardToken));
        balanceTrackerNFT.enableReward(address(app), address(rewardToken));
        vm.stopPrank();

        app.initialize(defaultPoSSettings, stakingToken);

        validatorManager = app;
        posValidatorManager = app;
        return app;
    }

    function _getStakeAssetBalance(address account) internal view override returns (uint256) {
        return account.balance;
    }
}

contract TestableERC721TokenStakingManager is ERC721TokenStakingManager, Test {
    constructor(ICMInitializable init) ERC721TokenStakingManager(init) {}

    function _reward(address account, uint256 amount) internal virtual override {
        super._reward(account, amount);
        // Units tests don't have access to the native minter precompile, so use vm.deal instead.
        vm.deal(account, account.balance + amount);
    }
}
