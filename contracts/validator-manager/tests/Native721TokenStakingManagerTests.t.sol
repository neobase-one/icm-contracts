// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {Test} from "@forge-std/Test.sol";
import {StakingManagerTest} from "./StakingManagerTests.t.sol";
import {Native721TokenStakingManager} from "../Native721TokenStakingManager.sol";
import {StakingManager, StakingManagerSettings} from "../StakingManager.sol";
import {ExampleRewardCalculator} from "../ExampleRewardCalculator.sol";
import {ICMInitializable} from "../../utilities/ICMInitializable.sol";
import {INativeMinter} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/INativeMinter.sol";
import {ValidatorManagerTest} from "./ValidatorManagerTests.t.sol";
import {Initializable} from "@openzeppelin/contracts@5.0.2/proxy/utils/Initializable.sol";
import {ACP99Manager, PChainOwner, ConversionData} from "../ACP99Manager.sol";
import {ValidatorManager} from "../ValidatorManager.sol";
import {ValidatorMessages} from "../ValidatorMessages.sol";

import {IERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/IERC20.sol";
import {ExampleERC721} from "@mocks/ExampleERC721.sol";
import {ExampleERC20} from "@mocks/ExampleERC20.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {IERC721Receiver} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721Receiver.sol";


contract Native721TokenStakingManagerTest is StakingManagerTest, IERC721Receiver {
    Native721TokenStakingManager public app;

    IERC721 public stakingToken;
    IERC20 public rewardToken;

    uint128 public constant REWARD_PER_EPOCH = 100e18;

    uint256 testTokenID = 0;

    function setUp() public override {
        ValidatorManagerTest.setUp();

        _setUp();
        _mockGetBlockchainID();

        ConversionData memory conversion = _defaultConversionData();
        bytes32 conversionID = sha256(ValidatorMessages.packConversionData(conversion));
        _mockInitializeValidatorSet(conversionID);
        validatorManager.initializeValidatorSet(conversion, 0);
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public virtual returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    //
    // Initialization unit tests
    // The pattern in these tests requires that only non-admin validator manager functions are called,
    // as each test re-deploys the Native721TokenStakingManager contract.
    //
    function testDisableInitialization() public {
        app = new Native721TokenStakingManager(ICMInitializable.Disallowed);
        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));

        StakingManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.manager = validatorManager;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testZeroMinimumDelegationFee() public {
        app = new Native721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(abi.encodeWithSelector(StakingManager.InvalidDelegationFee.selector, 0));

        StakingManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.manager = validatorManager;
        defaultPoSSettings.minimumDelegationFeeBips = 0;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testMaxMinimumDelegationFee() public {
        app = new Native721TokenStakingManager(ICMInitializable.Allowed);
        uint16 minimumDelegationFeeBips = app.MAXIMUM_DELEGATION_FEE_BIPS() + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                StakingManager.InvalidDelegationFee.selector, minimumDelegationFeeBips
            )
        );

        StakingManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.manager = validatorManager;
        defaultPoSSettings.minimumDelegationFeeBips = minimumDelegationFeeBips;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testInvalidStakeAmountRange() public {
        app = new Native721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(
                StakingManager.InvalidStakeAmount.selector, DEFAULT_MAXIMUM_STAKE_AMOUNT
            )
        );

        StakingManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.manager = validatorManager;
        defaultPoSSettings.minimumStakeAmount = DEFAULT_MAXIMUM_STAKE_AMOUNT;
        defaultPoSSettings.maximumStakeAmount = DEFAULT_MINIMUM_STAKE_AMOUNT;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testZeroWeightToValueFactor() public {
        app = new Native721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(abi.encodeWithSelector(StakingManager.ZeroWeightToValueFactor.selector));

        StakingManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.manager = validatorManager;
        defaultPoSSettings.weightToValueFactor = 0;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testMinStakeDurationTooLow() public {
        app = new Native721TokenStakingManager(ICMInitializable.Allowed);
        uint64 minStakeDuration = DEFAULT_CHURN_PERIOD - 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                StakingManager.InvalidMinStakeDuration.selector, minStakeDuration
            )
        );

        StakingManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.manager = validatorManager;
        defaultPoSSettings.minimumStakeDuration = minStakeDuration;
        app.initialize(defaultPoSSettings, stakingToken);
    }

    function testInvalidValidatorManager() public {
        app = new Native721TokenStakingManager(ICMInitializable.Allowed);
        Native721TokenStakingManager invalidManager =
            new Native721TokenStakingManager(ICMInitializable.Allowed); // the contract type is arbitrary

        vm.expectRevert();

        StakingManagerSettings memory settings = _defaultPoSSettings();
        settings.manager = ValidatorManager(address(invalidManager));
        app.initialize(settings, stakingToken);
    }

    function testUnsetValidatorManager() public {
        app = new Native721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert();

        app.initialize(_defaultPoSSettings(), stakingToken); // settings.manager is not set
    }

    function testNFTDelegationOverWeightLimit() public {
        bytes32 validationID = _registerDefaultValidator();

        uint256[] memory tokens = new uint256[](DEFAULT_MAXIMUM_NFT_AMOUNT);


        vm.expectRevert(
            abi.encodeWithSelector(
                Native721TokenStakingManager.InvalidNFTAmount.selector, DEFAULT_MAXIMUM_NFT_AMOUNT + 1
            )
        );

        vm.prank(DEFAULT_DELEGATOR_ADDRESS);
        app.registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS, tokens);
    }

    function testK() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerDefaultDelegator(validationID);

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
        _initiateDelegatorRemoval({
            sender: DEFAULT_DELEGATOR_ADDRESS,
            delegationID: delegationID,
            endDelegationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION + 1,
            includeUptime: true,
            force: true,
            rewardRecipient: DEFAULT_DELEGATOR_ADDRESS
        });

        uint64 uptime = DEFAULT_COMPLETION_TIMESTAMP - DEFAULT_REGISTRATION_TIMESTAMP;
        bytes memory uptimeMessage =
            ValidatorMessages.packValidationUptimeMessage(validationID, uptime);
        _mockGetUptimeWarpMessage(uptimeMessage, true);

        vm.warp(DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION + 1);
        app.submitUptimeProof(validationID, 0);

        (uint256 validatorReward, uint256 delegatorReward) = _calculateExpectedRewards(
            DEFAULT_WEIGHT, DEFAULT_DELEGATOR_WEIGHT, DEFAULT_DELEGATION_FEE_BIPS);


        uint256 balanceBefore = rewardToken.balanceOf(address(this));
        _claimReward(true, address(this));
        assertApproxEqRel(validatorReward, rewardToken.balanceOf(address(this)) - balanceBefore, 0.1e18);


        // balanceBefore = rewardToken.balanceOf(DEFAULT_DELEGATOR_ADDRESS);
        // _claimReward(DEFAULT_DELEGATOR_ADDRESS);
        // assertApproxEqRel(validatorReward, rewardToken.balanceOf(DEFAULT_DELEGATOR_ADDRESS) - balanceBefore, 0.1e18);
    }

    function testDelegationRewardsForSameValidatorAndDelegator() public {
        bytes32 validationID = _registerDefaultValidator();

        bytes32 delegationID = _registerDelegator({
            validationID: validationID,
            delegatorAddress: address(this),
            weight: DEFAULT_DELEGATOR_WEIGHT,
            initRegistrationTimestamp: DEFAULT_DELEGATOR_INIT_REGISTRATION_TIMESTAMP,
            completeRegistrationTimestamp: DEFAULT_DELEGATOR_COMPLETE_REGISTRATION_TIMESTAMP,
            expectedValidatorWeight: DEFAULT_DELEGATOR_WEIGHT + DEFAULT_WEIGHT,
            expectedNonce: 1
        });

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
        _initiateDelegatorRemoval({
            sender: address(this),
            delegationID: delegationID,
            endDelegationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION + 1,
            includeUptime: true,
            force: true,
            rewardRecipient: DEFAULT_DELEGATOR_ADDRESS
        });

        vm.warp(block.timestamp + DEFAULT_EPOCH_DURATION);

        (uint256 validatorReward, uint256 delegatorReward) = _calculateExpectedRewards(
            DEFAULT_WEIGHT, DEFAULT_DELEGATOR_WEIGHT, DEFAULT_DELEGATION_FEE_BIPS);

        // assertApproxEqRel(validatorReward + delegatorReward, _claimReward(address(this)), 0.1e18);
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
            expectedNonce: 1,
            rewardRecipient: address(this)
        });

        uint64 uptime = DEFAULT_COMPLETION_TIMESTAMP - DEFAULT_REGISTRATION_TIMESTAMP;
        bytes memory uptimeMessage =
            ValidatorMessages.packValidationUptimeMessage(validationID, uptime);
        _mockGetUptimeWarpMessage(uptimeMessage, true);

        // Validator is Completed, so this will also complete the delegation.
        _initiateNFTDelegatorRemoval(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );

        _expectNFTStakeUnlock(DEFAULT_DELEGATOR_ADDRESS, 1);

        vm.warp(block.timestamp + DEFAULT_EPOCH_DURATION);

        (uint256 validatorReward, uint256 delegatorReward) = _calculateExpectedRewards(
            1e6, 1e6, DEFAULT_DELEGATION_FEE_BIPS);

        // assertApproxEqRel(validatorReward, _claimRewardNFT(address(this)), 0.1e18);
        // assertApproxEqRel(delegatorReward, _claimRewardNFT(DEFAULT_DELEGATOR_ADDRESS), 0.1e18);
    }

    function testDoubleDelegationRewards() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerDefaultDelegator(validationID);
        bytes32 newDelegationID = _registerDelegator({
            validationID: validationID,
            delegatorAddress: DEFAULT_DELEGATOR_ADDRESS,
            weight: DEFAULT_DELEGATOR_WEIGHT,
            initRegistrationTimestamp: DEFAULT_DELEGATOR_INIT_REGISTRATION_TIMESTAMP+1,
            completeRegistrationTimestamp: DEFAULT_DELEGATOR_COMPLETE_REGISTRATION_TIMESTAMP+1,
            expectedValidatorWeight: 2*DEFAULT_DELEGATOR_WEIGHT + DEFAULT_WEIGHT,
            expectedNonce: 2
        });

        _endValidationWithChecks({
            validationID: validationID,
            validatorOwner: address(this),
            completeRegistrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP,
            completionTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION,
            validatorWeight: DEFAULT_WEIGHT,
            expectedNonce: 3,
            rewardRecipient: address(this)
        });

        // Validator is Completed, so this will also complete the delegation.
        _initiateDelegatorRemoval({
            sender: DEFAULT_DELEGATOR_ADDRESS,
            delegationID: delegationID,
            endDelegationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION + 1,
            includeUptime: true,
            force: true,
            rewardRecipient: DEFAULT_DELEGATOR_ADDRESS
        });

        _initiateDelegatorRemoval({
            sender: DEFAULT_DELEGATOR_ADDRESS,
            delegationID: newDelegationID,
            endDelegationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION + 2,
            includeUptime: true,
            force: true,
            rewardRecipient: DEFAULT_DELEGATOR_ADDRESS
        });
        vm.warp(block.timestamp + DEFAULT_EPOCH_DURATION);

        (uint256 validatorReward,uint256 delegatorReward) = _calculateExpectedRewards(
            DEFAULT_WEIGHT, DEFAULT_DELEGATOR_WEIGHT, DEFAULT_DELEGATION_FEE_BIPS);
        // assertApproxEqRel(validatorReward, _claimReward(address(this)), 0.1e18);
        // assertApproxEqRel(2*delegatorReward, _claimReward(DEFAULT_DELEGATOR_ADDRESS), 0.1e18);
    }

    function testDefaultAndNFTDelegationRewards() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerDefaultDelegator(validationID);
        bytes32 nftDelegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);

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

        _initiateNFTDelegatorRemoval(
            DEFAULT_DELEGATOR_ADDRESS,
            nftDelegationID,
            true,
            0
        );
        _expectNFTStakeUnlock(DEFAULT_DELEGATOR_ADDRESS, 1);

        // Validator is Completed, so this will also complete the delegation.
        _initiateDelegatorRemoval({
            sender: DEFAULT_DELEGATOR_ADDRESS,
            delegationID: delegationID,
            endDelegationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION + 1,
            includeUptime: true,
            force: true,
            rewardRecipient: DEFAULT_DELEGATOR_ADDRESS
        });

        vm.warp(block.timestamp + DEFAULT_EPOCH_DURATION);

        (uint256 validatorReward, uint256 delegatorReward) = _calculateExpectedRewards(
            1e6, 1e6, DEFAULT_DELEGATION_FEE_BIPS);

        // assertApproxEqRel(validatorReward, _claimRewardNFT(address(this)), 0.1e18);
        // assertApproxEqRel(delegatorReward, _claimRewardNFT(DEFAULT_DELEGATOR_ADDRESS), 0.1e18);

        (validatorReward,delegatorReward) = _calculateExpectedRewards(
            DEFAULT_WEIGHT, DEFAULT_DELEGATOR_WEIGHT, DEFAULT_DELEGATION_FEE_BIPS);
        // assertApproxEqRel(validatorReward, _claimReward(address(this)), 0.1e18);
        // assertApproxEqRel(delegatorReward, _claimReward(DEFAULT_DELEGATOR_ADDRESS), 0.1e18);
    }

    function testNFTRedelegation() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);

        address rewardRecipient = address(42);

        bytes32 nextValidationID = _registerValidator({
            nodeID: _newNodeID(),
            subnetID: DEFAULT_SUBNET_ID,
            weight: DEFAULT_WEIGHT,
            registrationExpiry: DEFAULT_EXPIRY,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP
        });

        vm.warp(block.timestamp + DEFAULT_MINIMUM_STAKE_DURATION + 1);

        vm.prank(DEFAULT_DELEGATOR_ADDRESS);
        app.registerNFTRedelegation(delegationID, false, 0, nextValidationID);
    }

    function testEndDelegationNFTBeforeUnlock() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);

        // _endValidationWithChecks({
        //     validationID: validationID,
        //     validatorOwner: address(this),
        //     completeRegistrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP,
        //     completionTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION,
        //     validatorWeight: DEFAULT_WEIGHT,
        //     expectedNonce: 2,
        //     rewardRecipient: address(this)
        // });

        uint64 uptime = DEFAULT_COMPLETION_TIMESTAMP - DEFAULT_REGISTRATION_TIMESTAMP;
        bytes memory uptimeMessage =
            ValidatorMessages.packValidationUptimeMessage(validationID, uptime);
        _mockGetUptimeWarpMessage(uptimeMessage, true);

        vm.warp(block.timestamp + DEFAULT_MINIMUM_STAKE_DURATION + 1);

        _initiateNFTDelegatorRemoval(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                StakingManager.UnlockDurationNotPassed.selector, 87401
            )
        );
        vm.prank(DEFAULT_DELEGATOR_ADDRESS);
        app.completeNFTDelegatorRemoval(delegationID); 
    }

    function testEndNFTDelegationRevertBeforeMinStakeDuration() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);

        vm.expectRevert(
            abi.encodeWithSelector(
                StakingManager.MinStakeDurationNotPassed.selector, block.timestamp
            )
        );
        _initiateNFTDelegatorRemoval(
            DEFAULT_DELEGATOR_ADDRESS,
            delegationID,
            true,
            0
        );
    }

    function testValidationRegistrationWithoutNFT() public {
         vm.expectRevert(
            abi.encodeWithSelector(
                Native721TokenStakingManager.InvalidNFTAmount.selector, 0
            )
        );
        uint256[] memory tokens = new uint256[](0);
        app.initiateValidatorRegistration{value: DEFAULT_MINIMUM_STAKE_AMOUNT}({
            nodeID: DEFAULT_NODE_ID,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationExpiry: DEFAULT_EXPIRY,
            remainingBalanceOwner: DEFAULT_P_CHAIN_OWNER,
            disableOwner: DEFAULT_P_CHAIN_OWNER,
            delegationFeeBips: DEFAULT_DELEGATION_FEE_BIPS,
            minStakeDuration: DEFAULT_MINIMUM_STAKE_DURATION,
            tokenIDs: tokens
        });
    }

    function testRevertRemovalDelgationNFTForNonOwner() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);

        _endValidationWithChecks({
            validationID: validationID,
            validatorOwner: address(this),
            completeRegistrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP,
            completionTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + DEFAULT_EPOCH_DURATION,
            validatorWeight: DEFAULT_WEIGHT,
            expectedNonce: 1,
            rewardRecipient: address(this)
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                StakingManager.UnauthorizedOwner.selector, address(42)
            )
        );
        _initiateNFTDelegatorRemoval(
            address(42),
            delegationID,
            true,
            0
        );
    }
 
    // Helpers
    function _calculateExpectedRewards(
        uint256 validatorStake,
        uint256 delegatorStake,
        uint256 delegationFeeBips
    ) internal pure returns (uint256 validatorReward, uint256 delegatorReward) {
        uint256 feeWeight = delegatorStake * delegationFeeBips / 10000;
        delegatorReward = (REWARD_PER_EPOCH * (delegatorStake - feeWeight)) / (delegatorStake + validatorStake);
        validatorReward = (REWARD_PER_EPOCH * (validatorStake + feeWeight)) / (delegatorStake + validatorStake);
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

    function _initiateNFTDelegatorRemoval(
        address delegatorAddress,
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal virtual returns (bytes32) {
        vm.prank(delegatorAddress);
        app.initiateNFTDelegatorRemoval(delegationID, includeUptimeProof, messageIndex);
    }

    function _completeNFTDelegatorRemoval(
        address delegatorAddress,
        bytes32 delegationID
    ) internal virtual returns (bytes32) {
        vm.warp(block.timestamp + DEFAULT_UNLOCK_DURATION);
        vm.prank(delegatorAddress);
        app.completeNFTDelegatorRemoval(delegationID);
    }

    function _initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        uint64 registrationExpiry,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 stakeAmount
    ) internal virtual override returns (bytes32) {
        uint256[] memory tokens = new uint256[](1);
        tokens[0] = ++testTokenID;
        return app.initiateValidatorRegistration{value: stakeAmount}({
            nodeID: nodeID,
            blsPublicKey: blsPublicKey,
            registrationExpiry: registrationExpiry,
            remainingBalanceOwner: remainingBalanceOwner,
            disableOwner: disableOwner,
            delegationFeeBips: delegationFeeBips,
            minStakeDuration: minStakeDuration,
            tokenIDs: tokens
        });
    }

    function _initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        uint64 registrationExpiry,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint64 weight
    ) internal virtual override returns (bytes32) {
        uint256[] memory tokens = new uint256[](1);
        tokens[0] = ++testTokenID;
        return app.initiateValidatorRegistration{value: _weightToValue(weight)}({
            nodeID: nodeID,
            blsPublicKey: blsPublicKey,
            registrationExpiry: registrationExpiry,
            remainingBalanceOwner: remainingBalanceOwner,
            disableOwner: disableOwner,
            delegationFeeBips: DEFAULT_DELEGATION_FEE_BIPS,
            minStakeDuration: DEFAULT_MINIMUM_STAKE_DURATION,
            tokenIDs: tokens
        });
    }

    function _initiateDelegatorRegistration(
        bytes32 validationID,
        address delegatorAddress,
        uint64 weight
    ) internal virtual override returns (bytes32) {
        uint256 value = _weightToValue(weight);
        vm.prank(delegatorAddress);
        vm.deal(delegatorAddress, value);
        return app.initiateDelegatorRegistration{value: value}(validationID);
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
    // solhint-enable no-empty-blocks

    function _expectStakeUnlock(address account, uint256 amount) internal override {
        // empty calldata implies the receive function will be called
        vm.expectCall(account, amount, "");
    }

    function _expectNFTStakeUnlock(address account, uint256 amount) internal view {
        assertEq(stakingToken.balanceOf(account), amount);
    }

    function _expectRewardIssuance(address account, uint256 amount) internal override {
    }

    function _claimReward(bool primary, address account) internal returns(uint256) {
        vm.prank(account);
        address[] memory tokens = new address[](1);
        tokens[0] = address(rewardToken);

        app.claimRewards(primary, 0, tokens, account);
    }

    function _setUp() internal override returns (ACP99Manager) {
        // Construct the object under test
        app = new Native721TokenStakingManager(ICMInitializable.Allowed);
        validatorManager = new ValidatorManager(ICMInitializable.Allowed);

        rewardToken = new ExampleERC20();
        stakingToken = new ExampleERC721();
        rewardCalculator = new ExampleRewardCalculator(DEFAULT_REWARD_RATE);

        stakingToken.setApprovalForAll(address(app), true);

        StakingManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.manager = validatorManager;

        validatorManager.initialize(_defaultSettings(address(app)));
        app.initialize(defaultPoSSettings, stakingToken);

        rewardToken.approve(address(app), REWARD_PER_EPOCH * 2);

        app.registerRewards(true, 0, address(rewardToken), REWARD_PER_EPOCH);
        app.registerRewards(false, 0, address(rewardToken), REWARD_PER_EPOCH);

        stakingManager = app;

        return validatorManager;
    }

    function _getStakeAssetBalance(address account) internal view override returns (uint256) {
        return account.balance;
    }
}