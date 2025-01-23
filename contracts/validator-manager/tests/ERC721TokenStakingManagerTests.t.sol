// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {Test} from "@forge-std/Test.sol";
import {PoSValidatorManagerTest} from "./PoSValidatorManagerTests.t.sol";
import {ERC721TokenStakingManager} from "../ERC721TokenStakingManager.sol";
import {PoSValidatorManager, PoSValidatorManagerSettings} from "../PoSValidatorManager.sol";
import {ValidatorRegistrationInput, IValidatorManager} from "../interfaces/IValidatorManager.sol";
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
import {console} from "forge-std/console.sol";
import {ValidatorMessages} from "../ValidatorMessages.sol";


contract ERC721TokenStakingManagerTest is PoSValidatorManagerTest, IERC721Receiver {
    using SafeERC20 for IERC20;

    ERC721TokenStakingManager public app;

    IERC721 public stakingToken;
    IERC20 public rewardToken;
    EthereumVaultConnector public evc;
    ITrackingRewardStreams public balanceTracker;
    ITrackingRewardStreams public balanceTrackerNFT;

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

    // Helpers
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

    // solhint-disable no-empty-blocks
    function _beforeSend(uint256 amount, address spender) internal override {
        // Native tokens no need pre approve
    }
    // solhint-enable no-empty-blocks

    function _beforeSendNFT(uint256 tokenId, address spender) internal {
        stakingToken.transferFrom(address(this), spender, tokenId);

        vm.prank(spender);
        stakingToken.approve(address(app), tokenId);
    }

    function _expectStakeUnlock(address account, uint256 amount) internal override {
        // empty calldata implies the receive function will be called
        vm.expectCall(account, amount, "");
    }

    function _expectRewardIssuance(address account, uint256 amount) internal override {
        // address nativeMinter = address(app.NATIVE_MINTER());
        // bytes memory callData = abi.encodeCall(INativeMinter.mintNativeCoin, (account, amount));
        // vm.mockCall(nativeMinter, callData, "");
        // vm.expectCall(nativeMinter, callData);
    }

    function testClaimNFTDelegationFees() public {
        bytes32 validationID = _registerDefaultValidator();
        bytes32 delegationID = _registerNFTDelegation(validationID, DEFAULT_DELEGATOR_ADDRESS);
        
        address rewardRecipient = address(42);
        vm.warp(block.timestamp + DEFAULT_EPOCH_DURATION * 1);

        uint64 uptimePercentage1 = 80;
        uint64 uptime1 = (
            (DEFAULT_COMPLETION_TIMESTAMP - DEFAULT_REGISTRATION_TIMESTAMP) * uptimePercentage1
        ) / 100;
        bytes memory uptimeMsg1 =
            ValidatorMessages.packValidationUptimeMessage(validationID, uptime1);
        _mockGetUptimeWarpMessage(uptimeMsg1, true);
        // _update();

        app.submitUptimeProof(validationID, 0);

        vm.warp(block.timestamp + DEFAULT_EPOCH_DURATION * 2);
        // _update();

        _endDefaultValidatorWithChecks(validationID, 2);

        vm.warp(DEFAULT_DELEGATOR_END_DELEGATION_TIMESTAMP + DEFAULT_UNLOCK_DELEGATE_DURATION + 1);
        // Validator is Completed, so this will also complete the delegation.
        _initializeEndDelegationNFT({
            sender: DEFAULT_DELEGATOR_ADDRESS,
            delegationID: delegationID,
            endDelegationTimestamp: DEFAULT_DELEGATOR_END_DELEGATION_TIMESTAMP,
            includeUptime: true,
            force: false,
            rewardRecipient: rewardRecipient
        });
        // _update();
        console.log("NFT reward");
        console.log(_getRewardNFT());
        console.log("NFT delegator reward");
        console.log(_getDelegatorReward());
        _claimNFTReward();
        vm.prank(DEFAULT_DELEGATOR_ADDRESS);
        _claimNFTReward();
    } 

    function _update() internal {
        balanceTracker.updateReward(address(app),address(rewardToken),address(0));
        balanceTrackerNFT.updateReward(address(app),address(rewardToken),address(0));
    }
    function _claimDelFees(address validator) internal {
        uint256 reward = balanceTrackerNFT.claimReward(address(app),address(rewardToken), validator, false);
        console.log(reward);
    }

    function _claimReward(address delegatorAddress) internal {
        uint256 reward = balanceTrackerNFT.claimReward(address(app),address(rewardToken), delegatorAddress, false);
        console.log(reward);
    }

    function _getReward() internal view returns(uint256) {
        return balanceTracker.earnedReward(address(this),address(app),address(rewardToken), false);
    }

    function _getRewardNFT() internal view returns(uint256) {
        return balanceTrackerNFT.earnedReward(address(this),address(app),address(rewardToken), false);
    }

    function _getDelegatorReward() internal view returns(uint256) {
        return balanceTrackerNFT.earnedReward(DEFAULT_DELEGATOR_ADDRESS,address(app),address(rewardToken), false);
    }

    function _claim(address rewardRecipient) internal {
        balanceTracker.claimReward(address(app), address(rewardToken), rewardRecipient, false);
    }

    function _claimNFTReward() internal {
        uint256 reward = balanceTrackerNFT.claimReward(address(app), address(rewardToken), address(this), false);

    }

    function _initializeEndDelegationNFT(
        address sender,
        bytes32 delegationID,
        uint64 endDelegationTimestamp,
        bool includeUptime,
        bool force,
        address rewardRecipient
    ) internal {
        //vm.warp(endDelegationTimestamp);
        vm.prank(sender);
            app.endNFTDelegation(
                delegationID, false, 0
            );
    }

    function _registerDelegatorNFT(bytes32 validationID)
        internal
        returns (bytes32 delegationID)
    {

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

        uint128 rewardAmount = 50e18;
        rewardToken.approve(address(balanceTracker), rewardAmount * 2);
        rewardToken.approve(address(balanceTrackerNFT), rewardAmount * 2);
        uint128[] memory amounts = new uint128[](2);
        amounts[0] = rewardAmount;
        amounts[1] = rewardAmount;

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