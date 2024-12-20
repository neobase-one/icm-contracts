// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {ERC721PoSValidatorManagerTest} from "./ERC721PoSValidatorManagerTests.t.sol";
import {ERC721TokenStakingManager} from "../../ERC721/ERC721TokenStakingManager.sol";
import {
    ERC721PoSValidatorManager,
    PoSValidatorManagerSettings
} from "../../ERC721/ERC721PoSValidatorManager.sol";
import {ExampleRewardCalculator} from "../../ExampleRewardCalculator.sol";
import {
    ValidatorRegistrationInput, IValidatorManager
} from "../../interfaces/IValidatorManager.sol";
import {ICMInitializable} from "../../../utilities/ICMInitializable.sol";
import {ExampleERC721} from "@mocks/ExampleERC721.sol";
import {ExampleERC20} from "@mocks/ExampleERC20.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {IERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts@5.0.2/proxy/utils/Initializable.sol";
import {ERC721ValidatorManagerTest} from "./ERC721ValidatorManagerTests.t.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract ERC721TokenStakingManagerTest is ERC721PoSValidatorManagerTest, IERC721Receiver {
    using SafeERC20 for IERC20;

    ERC721TokenStakingManager public app;
    IERC721 public stakingToken;
    IERC20 public rewardToken;
    uint256 public constant TEST_TOKEN_ID = 1;

    function setUp() public override {
        ERC721ValidatorManagerTest.setUp();
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
        app.initialize(_defaultPoSSettings(), stakingToken, rewardToken);
    }

    function testZeroStakingTokenAddress() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC721TokenStakingManager.InvalidTokenAddress.selector, address(0)
            )
        );
        app.initialize(_defaultPoSSettings(), IERC721(address(0)), rewardToken);
    }

    function testZeroRewardTokenAddress() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC721TokenStakingManager.InvalidRewardTokenAddress.selector, address(0)
            )
        );
        app.initialize(_defaultPoSSettings(), stakingToken, IERC20(address(0)));
    }

    function testZeroMinimumDelegationFee() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(ERC721PoSValidatorManager.InvalidDelegationFee.selector, 0)
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.minimumDelegationFeeBips = 0;
        app.initialize(defaultPoSSettings, stakingToken, rewardToken);
    }

    function testMaxMinimumDelegationFee() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        uint16 minimumDelegationFeeBips = app.MAXIMUM_DELEGATION_FEE_BIPS() + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC721PoSValidatorManager.InvalidDelegationFee.selector, minimumDelegationFeeBips
            )
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.minimumDelegationFeeBips = minimumDelegationFeeBips;
        app.initialize(defaultPoSSettings, stakingToken, rewardToken);
    }

    function testInvalidStakeAmountRange() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC721PoSValidatorManager.InvalidStakeAmount.selector, DEFAULT_MAXIMUM_STAKE_AMOUNT
            )
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.minimumStakeAmount = DEFAULT_MAXIMUM_STAKE_AMOUNT;
        defaultPoSSettings.maximumStakeAmount = DEFAULT_MINIMUM_STAKE_AMOUNT;
        app.initialize(defaultPoSSettings, stakingToken, rewardToken);
    }

    function testZeroMaxStakeMultiplier() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(ERC721PoSValidatorManager.InvalidStakeMultiplier.selector, 0)
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.maximumStakeMultiplier = 0;
        app.initialize(defaultPoSSettings, stakingToken, rewardToken);
    }

    function testMinStakeDurationTooLow() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        uint64 minimumStakeDuration = DEFAULT_CHURN_PERIOD - 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC721PoSValidatorManager.InvalidMinStakeDuration.selector, minimumStakeDuration
            )
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.minimumStakeDuration = minimumStakeDuration;
        app.initialize(defaultPoSSettings, stakingToken, rewardToken);
    }

    function testMaxStakeMultiplierOverLimit() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        uint8 maximumStakeMultiplier = app.MAXIMUM_STAKE_MULTIPLIER_LIMIT() + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC721PoSValidatorManager.InvalidStakeMultiplier.selector, maximumStakeMultiplier
            )
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.maximumStakeMultiplier = maximumStakeMultiplier;
        app.initialize(defaultPoSSettings, stakingToken, rewardToken);
    }

    function testZeroWeightToValueFactor() public {
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        vm.expectRevert(
            abi.encodeWithSelector(ERC721PoSValidatorManager.ZeroWeightToValueFactor.selector)
        );

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.weightToValueFactor = 0;
        app.initialize(defaultPoSSettings, stakingToken, rewardToken);
    }

    function testInvalidValidatorMinStakeDuration() public {
        ValidatorRegistrationInput memory input = ValidatorRegistrationInput({
            nodeID: DEFAULT_NODE_ID,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationExpiry: DEFAULT_EXPIRY,
            remainingBalanceOwner: DEFAULT_P_CHAIN_OWNER,
            disableOwner: DEFAULT_P_CHAIN_OWNER
        });
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC721PoSValidatorManager.InvalidMinStakeDuration.selector,
                DEFAULT_MINIMUM_STAKE_DURATION - 1
            )
        );
        app.initializeValidatorRegistration(
            input, DEFAULT_DELEGATION_FEE_BIPS, DEFAULT_MINIMUM_STAKE_DURATION - 1, TEST_TOKEN_ID
        );
    }

    function testERC721TokenStakingManagerStorageSlot() public view {
        assertEq(
            _erc7201StorageSlot("ERC721TokenStakingManager"),
            app.ERC721_STAKING_MANAGER_STORAGE_LOCATION()
        );
    }

    function _initializeValidatorRegistration(
        ValidatorRegistrationInput memory registrationInput,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 tokenId
    ) internal virtual override returns (bytes32) {
        return app.initializeValidatorRegistration(
            registrationInput, delegationFeeBips, minStakeDuration, tokenId
        );
    }

    function _initializeValidatorRegistration(
        ValidatorRegistrationInput memory input,
        uint64 weight
    ) internal virtual override returns (bytes32) {
        return app.initializeValidatorRegistration(
            input, DEFAULT_DELEGATION_FEE_BIPS, DEFAULT_MINIMUM_STAKE_DURATION, weight
        );
    }

    function _initializeDelegatorRegistration(
        bytes32 validationID,
        address delegatorAddress,
        uint64 weight
    ) internal virtual override returns (bytes32) {
        uint256 value = _weightToValue(weight);

        vm.startPrank(delegatorAddress);
        //stakingToken.approve(address(app), TEST_TOKEN_ID);
        bytes32 delegationID = app.initializeDelegatorRegistration(validationID, value);
        vm.stopPrank();

        return delegationID;
    }

    function _beforeSend(uint256 tokenId, address spender) internal override {
        stakingToken.approve(spender, tokenId);
        ExampleERC721(address(stakingToken)).transferFrom(address(this), spender, tokenId);

        vm.startPrank(spender);

        stakingToken.approve(address(app), tokenId);
        vm.stopPrank();
    }

    function _expectStakeUnlock(address account, uint256 tokenId) internal override {
        vm.expectCall(
            address(stakingToken),
            abi.encodeWithSelector(
                0x42842e0e, //safeTransferFrom(address,address,uint256)
                address(app),
                account,
                tokenId
            )
        );
    }

    function _expectRewardIssuance(address account, uint256 amount) internal override {
        vm.expectCall(address(rewardToken), abi.encodeCall(IERC20.transfer, (account, amount)));
    }

    function _setUp() internal override returns (IValidatorManager) {
        // Construct the object under test
        app = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        stakingToken = new ExampleERC721();
        rewardToken = new ExampleERC20();
        rewardToken.transfer(address(app), 100000 ether);

        rewardCalculator = new ExampleRewardCalculator(DEFAULT_REWARD_RATE, 18);

        PoSValidatorManagerSettings memory defaultPoSSettings = _defaultPoSSettings();
        defaultPoSSettings.rewardCalculator = rewardCalculator;
        app.initialize(defaultPoSSettings, stakingToken, rewardToken);

        validatorManager = app;
        posValidatorManager = app;

        return app;
    }

    function _getStakeAssetBalance(
        address account
    ) internal view override returns (uint256) {
        return stakingToken.balanceOf(account);
    }

    function _getRewardAssetBalance(
        address account
    ) internal view override returns (uint256) {
        return rewardToken.balanceOf(account);
    }
}
