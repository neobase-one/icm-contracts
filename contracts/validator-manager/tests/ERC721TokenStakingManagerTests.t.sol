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


contract ERC721TokenStakingManagerTest is PoSValidatorManagerTest, IERC721Receiver {
    using SafeERC20 for IERC20;

    ERC721TokenStakingManager public app;

    IERC721 public stakingToken;
    IERC20 public rewardToken;
    EthereumVaultConnector public evc;
    ITrackingRewardStreams public balanceTracker;
    ITrackingRewardStreams public balanceTrackerNFT;

    uint256[] TEST_TOKENS = [uint256(0)];

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
        return this.onERC721Received.selector;
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
        return app.initializeValidatorRegistration{value: stakeAmount}(
            registrationInput, delegationFeeBips, minStakeDuration, TEST_TOKENS
        );
    }

    function _initializeValidatorRegistration(
        ValidatorRegistrationInput memory input,
        uint64 weight
    ) internal virtual override returns (bytes32) {
        return app.initializeValidatorRegistration{value: _weightToValue(weight)}(
            input, DEFAULT_DELEGATION_FEE_BIPS, DEFAULT_MINIMUM_STAKE_DURATION, TEST_TOKENS
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

    // solhint-disable no-empty-blocks
    function _beforeSend(uint256 amount, address spender) internal override {
        // Native tokens no need pre approve
    }
    // solhint-enable no-empty-blocks

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

    function _setUp() internal override returns (IValidatorManager) {
        // Construct the object under test
        app = new TestableERC721TokenStakingManager(ICMInitializable.Allowed);

        rewardCalculator = new ExampleRewardCalculator(DEFAULT_REWARD_RATE);
        stakingToken = new ExampleERC721();
        rewardToken = new ExampleERC20();        

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