// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {Test} from "@forge-std/Test.sol";
import {ValidatorManager, ValidatorManagerSettings} from "../ValidatorManager.sol";
import {ValidatorMessages} from "../ValidatorMessages.sol";
import {
    WarpMessage,
    IWarpMessenger
} from "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";
import {ACP99Manager, ConversionData, InitialValidator, PChainOwner} from "../ACP99Manager.sol";
import {OwnableUpgradeable} from
    "@openzeppelin/contracts-upgradeable@5.0.2/access/OwnableUpgradeable.sol";

// TODO: Remove this once all unit tests implemented
// solhint-disable no-empty-blocks
abstract contract ValidatorManagerTest is Test {
    bytes32 public constant DEFAULT_SUBNET_ID =
        bytes32(hex"1234567812345678123456781234567812345678123456781234567812345678");
    bytes public constant DEFAULT_NODE_ID = bytes(hex"1234123412341234123412341234123412341234");
    bytes public constant DEFAULT_INITIAL_VALIDATOR_NODE_ID_1 =
        bytes(hex"2341234123412341234123412341234123412341");
    bytes public constant DEFAULT_INITIAL_VALIDATOR_NODE_ID_2 =
        bytes(hex"3412341234123412341234123412341234123412");
    bytes public constant DEFAULT_BLS_PUBLIC_KEY = bytes(
        hex"123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678"
    );
    bytes32 public constant DEFAULT_SOURCE_BLOCKCHAIN_ID =
        bytes32(hex"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd");
    bytes32 public constant DEFAULT_SUBNET_CONVERSION_ID =
        bytes32(hex"67e8531265d8e97bd5c23534a37f4ea42d41934ddf8fe2c77c27fac9ef89f973");
    address public constant WARP_PRECOMPILE_ADDRESS = 0x0200000000000000000000000000000000000005;

    address public constant DEFAULT_VALIDATOR_REMOVAL_ADMIN = address(0x123);

    uint64 public constant DEFAULT_WEIGHT = 1e6;
    // Set the default weight to 1e10 to avoid churn issues
    uint64 public constant DEFAULT_INITIAL_VALIDATOR_WEIGHT = DEFAULT_WEIGHT * 1e4;
    uint64 public constant DEFAULT_INITIAL_TOTAL_WEIGHT =
        DEFAULT_INITIAL_VALIDATOR_WEIGHT + DEFAULT_WEIGHT;
    uint256 public constant DEFAULT_MINIMUM_STAKE_AMOUNT = 20e12;
    uint256 public constant DEFAULT_MAXIMUM_STAKE_AMOUNT = 1e22;
    uint64 public constant DEFAULT_CHURN_PERIOD = 1 hours;
    uint8 public constant DEFAULT_MAXIMUM_CHURN_PERCENTAGE = 20;
    uint64 public constant DEFAULT_EXPIRY = 1000;
    uint8 public constant DEFAULT_MAXIMUM_HOURLY_CHURN = 0;
    uint64 public constant DEFAULT_REGISTRATION_TIMESTAMP = 1000;
    uint256 public constant DEFAULT_STARTING_TOTAL_WEIGHT = 1e10 + DEFAULT_WEIGHT;
    uint64 public constant DEFAULT_MINIMUM_VALIDATION_DURATION = 24 hours;
    uint64 public constant DEFAULT_COMPLETION_TIMESTAMP = 100_000;
    uint64 public constant DEFAULT_UNLOCK_DURATION = 1 days;
    // solhint-disable-next-line var-name-mixedcase
    PChainOwner public DEFAULT_P_CHAIN_OWNER;

    ValidatorManager public validatorManager;

    // Used to create unique validator IDs in {_newNodeID}
    uint64 public nodeIDCounter = 0;

    event RegisteredInitialValidator(
        bytes32 indexed validationID, bytes20 indexed nodeID, uint64 weight
    );

    event InitiatedValidatorRegistration(
        bytes32 indexed validationID,
        bytes20 indexed nodeID,
        bytes32 registrationMessageID,
        uint64 registrationExpiry,
        uint64 weight
    );

    event CompletedValidatorRegistration(bytes32 indexed validationID, uint64 weight);

    event InitiatedValidatorRemoval(
        bytes32 indexed validationID,
        bytes32 validatorWeightMessageID,
        uint64 weight,
        uint64 endTime
    );

    event CompletedValidatorRemoval(bytes32 indexed validationID);

    event InitiatedValidatorWeightUpdate(
        bytes32 indexed validationID, uint64 nonce, bytes32 weightUpdateMessageID, uint64 weight
    );

    event CompletedValidatorWeightUpdate(bytes32 indexed validationID, uint64 nonce, uint64 weight);

    event ValidatorWeightUpdate(
        bytes32 indexed validationID,
        uint64 indexed nonce,
        uint64 weight,
        bytes32 setWeightMessageID
    );

    receive() external payable {}
    fallback() external payable {}

    function setUp() public virtual {
        address[] memory addresses = new address[](1);
        addresses[0] = 0x1234567812345678123456781234567812345678;
        DEFAULT_P_CHAIN_OWNER = PChainOwner({threshold: 1, addresses: addresses});
    }

    function testInitializeValidatorRegistrationSuccess() public {
        _setUpInitializeValidatorRegistration(
            DEFAULT_NODE_ID,
            DEFAULT_SUBNET_ID,
            DEFAULT_WEIGHT,
            DEFAULT_EXPIRY,
            DEFAULT_BLS_PUBLIC_KEY
        );
    }

    function testInitializeValidatorRegistrationExcessiveChurn() public {
        // TODO: implement
    }

    function testInitializeValidatorRegistrationInsufficientStake() public {
        // TODO: implement
    }

    function testInitializeValidatorRegistrationExcessiveStake() public {
        // TODO: implement
    }

    function testInitializeValidatorRegistrationInsufficientDuration() public {
        // TODO: implement
    }

    function testInitializeValidatorRegistrationPChainOwnerThresholdTooLarge() public {
        // Threshold too large
        address[] memory addresses = new address[](1);
        addresses[0] = 0x1234567812345678123456781234567812345678;
        PChainOwner memory invalidPChainOwner1 = PChainOwner({threshold: 2, addresses: addresses});
        _beforeSend(_weightToValue(DEFAULT_WEIGHT), address(this));
        vm.expectRevert(
            abi.encodeWithSelector(ValidatorManager.InvalidPChainOwnerThreshold.selector, 2, 1)
        );
        _initiateValidatorRegistration({
            nodeID: DEFAULT_NODE_ID,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            remainingBalanceOwner: invalidPChainOwner1,
            disableOwner: DEFAULT_P_CHAIN_OWNER,
            registrationExpiry: DEFAULT_EXPIRY,
            weight: DEFAULT_WEIGHT
        });
    }

    function testInitializeValidatorRegistrationZeroPChainOwnerThreshold() public {
        // Zero threshold for non-zero address
        address[] memory addresses = new address[](1);
        addresses[0] = 0x1234567812345678123456781234567812345678;
        PChainOwner memory invalidPChainOwner1 = PChainOwner({threshold: 0, addresses: addresses});
        _beforeSend(_weightToValue(DEFAULT_WEIGHT), address(this));
        vm.expectRevert(
            abi.encodeWithSelector(ValidatorManager.InvalidPChainOwnerThreshold.selector, 0, 1)
        );
        _initiateValidatorRegistration({
            nodeID: DEFAULT_NODE_ID,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            remainingBalanceOwner: invalidPChainOwner1,
            disableOwner: DEFAULT_P_CHAIN_OWNER,
            registrationExpiry: DEFAULT_EXPIRY,
            weight: DEFAULT_WEIGHT
        });
    }

    function testInitializeValidatorRegistrationPChainOwnerAddressesUnsorted() public {
        // Addresses not sorted
        address[] memory addresses = new address[](2);
        addresses[0] = 0x1234567812345678123456781234567812345678;
        addresses[1] = 0x0123456781234567812345678123456781234567;
        PChainOwner memory invalidPChainOwner1 = PChainOwner({threshold: 1, addresses: addresses});

        _beforeSend(_weightToValue(DEFAULT_WEIGHT), address(this));
        vm.expectRevert(
            abi.encodeWithSelector(ValidatorManager.PChainOwnerAddressesNotSorted.selector)
        );
        _initiateValidatorRegistration({
            nodeID: DEFAULT_NODE_ID,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            remainingBalanceOwner: invalidPChainOwner1,
            disableOwner: DEFAULT_P_CHAIN_OWNER,
            registrationExpiry: DEFAULT_EXPIRY,
            weight: DEFAULT_WEIGHT
        });
    }

    // The following tests call functions that are  implemented in ValidatorManager, but access state that's
    // only set in NativeTokenValidatorManager. Therefore we call them via the concrete type, rather than a
    // reference to the abstract type.
    function testResendRegisterValidatorMessage() public {
        bytes32 validationID = _setUpInitializeValidatorRegistration(
            DEFAULT_NODE_ID,
            DEFAULT_SUBNET_ID,
            DEFAULT_WEIGHT,
            DEFAULT_EXPIRY,
            DEFAULT_BLS_PUBLIC_KEY
        );
        (, bytes memory registerL1ValidatorMessage) = ValidatorMessages
            .packRegisterL1ValidatorMessage(
            ValidatorMessages.ValidationPeriod({
                subnetID: DEFAULT_SUBNET_ID,
                nodeID: DEFAULT_NODE_ID,
                blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
                registrationExpiry: DEFAULT_EXPIRY,
                remainingBalanceOwner: DEFAULT_P_CHAIN_OWNER,
                disableOwner: DEFAULT_P_CHAIN_OWNER,
                weight: DEFAULT_WEIGHT
            })
        );
        _mockSendWarpMessage(registerL1ValidatorMessage, bytes32(0));
        validatorManager.resendRegisterValidatorMessage(validationID);
    }

    function testCompleteValidatorRegistration() public {
        _registerDefaultValidator();
    }

    function testInitializeEndValidation() public virtual {
        bytes32 validationID = _registerDefaultValidator();
        bytes memory setWeightMessage =
            ValidatorMessages.packL1ValidatorWeightMessage(validationID, 1, 0);
        bytes memory uptimeMessage;
        _initiateValidatorRemoval({
            validationID: validationID,
            completionTimestamp: DEFAULT_COMPLETION_TIMESTAMP,
            setWeightMessage: setWeightMessage,
            includeUptime: false,
            uptimeMessage: uptimeMessage,
            force: false
        });
    }

    function testResendEndValidation() public virtual {
        bytes32 validationID = _registerDefaultValidator();
        bytes memory setWeightMessage =
            ValidatorMessages.packL1ValidatorWeightMessage(validationID, 1, 0);
        bytes memory uptimeMessage;
        _initiateValidatorRemoval({
            validationID: validationID,
            completionTimestamp: DEFAULT_COMPLETION_TIMESTAMP,
            setWeightMessage: setWeightMessage,
            includeUptime: false,
            uptimeMessage: uptimeMessage,
            force: false
        });

        bytes memory setValidatorWeightPayload =
            ValidatorMessages.packL1ValidatorWeightMessage(validationID, 1, 0);
        _mockSendWarpMessage(setValidatorWeightPayload, bytes32(0));
        validatorManager.resendEndValidatorMessage(validationID);
    }

    function testCompleteEndValidation() public virtual {
        bytes32 validationID = _registerDefaultValidator();
        bytes memory setWeightMessage =
            ValidatorMessages.packL1ValidatorWeightMessage(validationID, 1, 0);
        bytes memory uptimeMessage;
        _initiateValidatorRemoval({
            validationID: validationID,
            completionTimestamp: DEFAULT_COMPLETION_TIMESTAMP,
            setWeightMessage: setWeightMessage,
            includeUptime: false,
            uptimeMessage: uptimeMessage,
            force: false
        });

        bytes memory l1ValidatorRegistrationMessage =
            ValidatorMessages.packL1ValidatorRegistrationMessage(validationID, false);

        _mockGetPChainWarpMessage(l1ValidatorRegistrationMessage, true);

        vm.expectEmit(true, true, true, true, address(validatorManager));
        emit CompletedValidatorRemoval(validationID);

        _completeValidatorRemoval(0);
    }

    function testCompleteInvalidatedValidation() public {
        bytes32 validationID = _setUpInitializeValidatorRegistration(
            DEFAULT_NODE_ID,
            DEFAULT_SUBNET_ID,
            DEFAULT_WEIGHT,
            DEFAULT_EXPIRY,
            DEFAULT_BLS_PUBLIC_KEY
        );
        bytes memory l1ValidatorRegistrationMessage =
            ValidatorMessages.packL1ValidatorRegistrationMessage(validationID, false);

        _mockGetPChainWarpMessage(l1ValidatorRegistrationMessage, true);

        vm.expectEmit(true, true, true, true, address(validatorManager));
        emit CompletedValidatorRemoval(validationID);

        vm.warp(block.timestamp + DEFAULT_UNLOCK_DURATION);
        _completeValidatorRemoval(0);
    }

    function testInitialWeightsTooLow() public {
        vm.prank(address(0x123));
        ACP99Manager manager = _setUp();

        _mockGetBlockchainID();
        vm.expectRevert(abi.encodeWithSelector(ValidatorManager.InvalidTotalWeight.selector, 4));
        manager.initializeValidatorSet(_defaultConversionDataWeightsTooLow(), 0);
    }

    function testRemoveValidatorTotalWeight5() public {
        // Use prank here, because otherwise each test will end up with a different contract address, leading to a different subnet conversion hash.
        vm.prank(address(0x123));
        ACP99Manager manager = _setUp();

        _mockGetBlockchainID();

        ConversionData memory conversion = _defaultConversionDataTotalWeight5();
        bytes32 id = sha256(ValidatorMessages.packConversionData(conversion));
        _mockGetPChainWarpMessage(ValidatorMessages.packSubnetToL1ConversionMessage(id), true);
        manager.initializeValidatorSet(conversion, 0);

        bytes32 validationID = sha256(abi.encodePacked(DEFAULT_SUBNET_ID, uint32(0)));
        vm.expectRevert(abi.encodeWithSelector(ValidatorManager.InvalidTotalWeight.selector, 4));
        _forceInitiateValidatorRemoval(validationID, false, address(0));
    }

    function testCumulativeChurnRegistration() public {
        uint64 churnThreshold =
            uint64(DEFAULT_STARTING_TOTAL_WEIGHT) * DEFAULT_MAXIMUM_CHURN_PERCENTAGE / 100;
        _beforeSend(_weightToValue(churnThreshold), address(this));

        // First registration should succeed
        _registerValidator({
            nodeID: _newNodeID(),
            subnetID: DEFAULT_SUBNET_ID,
            weight: churnThreshold,
            registrationExpiry: DEFAULT_EXPIRY,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP
        });

        _beforeSend(DEFAULT_MINIMUM_STAKE_AMOUNT, address(this));

        // Second call should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidatorManager.MaxChurnRateExceeded.selector,
                churnThreshold + _valueToWeight(DEFAULT_MINIMUM_STAKE_AMOUNT)
            )
        );
        _initiateValidatorRegistration({
            nodeID: DEFAULT_NODE_ID,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            remainingBalanceOwner: DEFAULT_P_CHAIN_OWNER,
            disableOwner: DEFAULT_P_CHAIN_OWNER,
            registrationExpiry: DEFAULT_REGISTRATION_TIMESTAMP + 1,
            weight: _valueToWeight(DEFAULT_MINIMUM_STAKE_AMOUNT)
        });
    }

    function testCumulativeChurnRegistrationAndEndValidation() public {
        // Registration should succeed
        bytes32 validationID = _registerValidator({
            nodeID: DEFAULT_NODE_ID,
            subnetID: DEFAULT_SUBNET_ID,
            weight: _valueToWeight(DEFAULT_MINIMUM_STAKE_AMOUNT),
            registrationExpiry: DEFAULT_EXPIRY,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP
        });

        uint64 churnThreshold =
            uint64(DEFAULT_STARTING_TOTAL_WEIGHT) * DEFAULT_MAXIMUM_CHURN_PERCENTAGE / 100;
        _beforeSend(_weightToValue(churnThreshold), address(this));

        // Registration should succeed
        _registerValidator({
            nodeID: _newNodeID(),
            subnetID: DEFAULT_SUBNET_ID,
            weight: churnThreshold,
            registrationExpiry: DEFAULT_EXPIRY + 25 hours,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP + 25 hours
        });

        // Second call should fail
        // The first registration churn amount is not part of the new churn amount since
        // a new churn period has started.
        vm.expectRevert(
            abi.encodeWithSelector(
                ValidatorManager.MaxChurnRateExceeded.selector,
                _valueToWeight(DEFAULT_MINIMUM_STAKE_AMOUNT) + churnThreshold
            )
        );

        _initiateValidatorRemoval(validationID, false, address(0));
    }

    function testInitiateValidatorRegistrationUnauthorizedCaller() public {
        vm.prank(address(0x123));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)
            )
        );
        validatorManager.initiateValidatorRegistration({
            nodeID: DEFAULT_NODE_ID,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationExpiry: DEFAULT_EXPIRY,
            remainingBalanceOwner: DEFAULT_P_CHAIN_OWNER,
            disableOwner: DEFAULT_P_CHAIN_OWNER,
            weight: DEFAULT_WEIGHT
        });
    }

    function testCompleteValidatorRegistrationUnauthorizedCaller() public {
        vm.prank(address(0x123));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)
            )
        );
        validatorManager.completeValidatorRegistration(0);
    }

    function testInitiateValidatorWeightUpdateUnauthorizedCaller() public {
        vm.prank(address(0x123));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)
            )
        );
        validatorManager.initiateValidatorWeightUpdate(bytes32(0), 0);
    }

    function testCompleteValidatorWeightUpdateUnauthorizedCaller() public {
        vm.prank(address(0x123));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)
            )
        );
        validatorManager.completeValidatorWeightUpdate(0);
    }

    function testInitiateValidatorRemovalUnauthorizedCaller() public {
        vm.prank(address(0x123));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)
            )
        );
        validatorManager.initiateValidatorRemoval(bytes32(0));
    }

    function testCompleteValidatorRemovalUnauthorizedCaller() public {
        vm.prank(address(0x123));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0x123)
            )
        );
        validatorManager.completeValidatorRemoval(0);
    }

    function testValidatorManagerStorageSlot() public view {
        assertEq(
            _erc7201StorageSlot("ValidatorManager"),
            validatorManager.VALIDATOR_MANAGER_STORAGE_LOCATION()
        );
    }

    // Returns a 20-byte node ID
    function _newNodeID() internal returns (bytes memory) {
        nodeIDCounter++;
        return abi.encodePacked(bytes20(sha256(new bytes(nodeIDCounter))));
    }

    function _setUpInitializeValidatorRegistration(
        bytes memory nodeID,
        bytes32 subnetID,
        uint64 weight,
        uint64 registrationExpiry,
        bytes memory blsPublicKey
    ) internal returns (bytes32 validationID) {
        (validationID,) = ValidatorMessages.packRegisterL1ValidatorMessage(
            ValidatorMessages.ValidationPeriod({
                nodeID: nodeID,
                subnetID: subnetID,
                blsPublicKey: blsPublicKey,
                registrationExpiry: registrationExpiry,
                remainingBalanceOwner: DEFAULT_P_CHAIN_OWNER,
                disableOwner: DEFAULT_P_CHAIN_OWNER,
                weight: weight
            })
        );
        bytes20 fixedID = _fixedNodeID(nodeID);
        (, bytes memory registerL1ValidatorMessage) = ValidatorMessages
            .packRegisterL1ValidatorMessage(
            ValidatorMessages.ValidationPeriod({
                subnetID: subnetID,
                nodeID: nodeID,
                blsPublicKey: blsPublicKey,
                registrationExpiry: registrationExpiry,
                remainingBalanceOwner: DEFAULT_P_CHAIN_OWNER,
                disableOwner: DEFAULT_P_CHAIN_OWNER,
                weight: weight
            })
        );
        vm.warp(registrationExpiry - 1);
        _mockSendWarpMessage(registerL1ValidatorMessage, bytes32(0));

        _beforeSend(_weightToValue(weight), address(this));
        vm.expectEmit(true, true, true, true, address(validatorManager));
        emit InitiatedValidatorRegistration(
            validationID, fixedID, bytes32(0), registrationExpiry, weight
        );

        _initiateValidatorRegistration({
            nodeID: nodeID,
            blsPublicKey: blsPublicKey,
            remainingBalanceOwner: DEFAULT_P_CHAIN_OWNER,
            disableOwner: DEFAULT_P_CHAIN_OWNER,
            registrationExpiry: registrationExpiry,
            weight: weight
        });
    }

    function _registerValidator(
        bytes memory nodeID,
        bytes32 subnetID,
        uint64 weight,
        uint64 registrationExpiry,
        bytes memory blsPublicKey,
        uint64 registrationTimestamp
    ) internal returns (bytes32 validationID) {
        validationID = _setUpInitializeValidatorRegistration(
            nodeID, subnetID, weight, registrationExpiry, blsPublicKey
        );
        bytes memory l1ValidatorRegistrationMessage =
            ValidatorMessages.packL1ValidatorRegistrationMessage(validationID, true);

        _mockGetPChainWarpMessage(l1ValidatorRegistrationMessage, true);

        vm.warp(registrationTimestamp);
        vm.expectEmit(true, true, true, true, address(validatorManager));
        emit CompletedValidatorRegistration(validationID, weight);

        _completeValidatorRegistration(0);
    }

    function _initiateValidatorRemoval(
        bytes32 validationID,
        uint64 completionTimestamp,
        bytes memory setWeightMessage,
        bool includeUptime,
        bytes memory uptimeMessage,
        bool force
    ) internal {
        _mockSendWarpMessage(setWeightMessage, bytes32(0));

        vm.warp(completionTimestamp);
        if (force) {
            _forceInitiateValidatorRemoval(validationID, includeUptime, address(0));
        } else {
            _initiateValidatorRemoval(validationID, includeUptime, address(0));
        }
    }

    function _initiateValidatorRemoval(
        bytes32 validationID,
        uint64 completionTimestamp,
        bytes memory setWeightMessage,
        bool includeUptime,
        bytes memory uptimeMessage,
        bool force,
        address recipientAddress
    ) internal {
        _mockSendWarpMessage(setWeightMessage, bytes32(0));

        vm.warp(completionTimestamp);
        if (force) {
            _forceInitiateValidatorRemoval(validationID, includeUptime, recipientAddress);
        } else {
            _initiateValidatorRemoval(validationID, includeUptime, recipientAddress);
        }
    }

    function _registerDefaultValidator() internal returns (bytes32 validationID) {
        return _registerValidator({
            nodeID: DEFAULT_NODE_ID,
            subnetID: DEFAULT_SUBNET_ID,
            weight: DEFAULT_WEIGHT,
            registrationExpiry: DEFAULT_EXPIRY,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY,
            registrationTimestamp: DEFAULT_REGISTRATION_TIMESTAMP
        });
    }

    function _mockSendWarpMessage(bytes memory payload, bytes32 expectedMessageID) internal {
        vm.mockCall(
            WARP_PRECOMPILE_ADDRESS,
            abi.encode(IWarpMessenger.sendWarpMessage.selector),
            abi.encode(expectedMessageID)
        );
        vm.expectCall(
            WARP_PRECOMPILE_ADDRESS, abi.encodeCall(IWarpMessenger.sendWarpMessage, payload)
        );
    }

    function _mockGetPChainWarpMessage(bytes memory expectedPayload, bool valid) internal {
        vm.mockCall(
            WARP_PRECOMPILE_ADDRESS,
            abi.encodeWithSelector(IWarpMessenger.getVerifiedWarpMessage.selector, uint32(0)),
            abi.encode(
                WarpMessage({
                    sourceChainID: validatorManager.P_CHAIN_BLOCKCHAIN_ID(),
                    originSenderAddress: address(0),
                    payload: expectedPayload
                }),
                valid
            )
        );
        vm.expectCall(
            WARP_PRECOMPILE_ADDRESS, abi.encodeCall(IWarpMessenger.getVerifiedWarpMessage, 0)
        );
    }

    function _mockGetUptimeWarpMessage(bytes memory expectedPayload, bool valid) internal {
        vm.mockCall(
            WARP_PRECOMPILE_ADDRESS,
            abi.encodeWithSelector(IWarpMessenger.getVerifiedWarpMessage.selector, uint32(0)),
            abi.encode(
                WarpMessage({
                    sourceChainID: DEFAULT_SOURCE_BLOCKCHAIN_ID,
                    originSenderAddress: address(0),
                    payload: expectedPayload
                }),
                valid
            )
        );
        vm.expectCall(
            WARP_PRECOMPILE_ADDRESS, abi.encodeCall(IWarpMessenger.getVerifiedWarpMessage, 0)
        );
    }

    function _mockGetBlockchainID() internal {
        _mockGetBlockchainID(DEFAULT_SOURCE_BLOCKCHAIN_ID);
    }

    function _mockGetBlockchainID(bytes32 blockchainID) internal {
        vm.mockCall(
            WARP_PRECOMPILE_ADDRESS,
            abi.encodeWithSelector(IWarpMessenger.getBlockchainID.selector),
            abi.encode(blockchainID)
        );
        vm.expectCall(
            WARP_PRECOMPILE_ADDRESS, abi.encodeWithSelector(IWarpMessenger.getBlockchainID.selector)
        );
    }

    function _mockInitializeValidatorSet(bytes32 conversionID) internal {
        _mockGetPChainWarpMessage(
            ValidatorMessages.packSubnetToL1ConversionMessage(conversionID), true
        );
    }

    function _initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        uint64 registrationExpiry,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint64 weight
    ) internal virtual returns (bytes32);

    function _completeValidatorRegistration(uint32 messageIndex)
        internal
        virtual
        returns (bytes32);

    function _initiateValidatorRemoval(
        bytes32 validationID,
        bool includeUptime,
        address rewardRecipient
    ) internal virtual;

    function _forceInitiateValidatorRemoval(
        bytes32 validationID,
        bool includeUptime,
        address rewardRecipient
    ) internal virtual;

    function _completeValidatorRemoval(uint32 messageIndex) internal virtual returns (bytes32);

    function _setUp() internal virtual returns (ACP99Manager);

    function _beforeSend(uint256 amount, address spender) internal virtual;

    function _defaultConversionData() internal view returns (ConversionData memory) {
        InitialValidator[] memory initialValidators = new InitialValidator[](2);
        // The first initial validator has a high weight relative to the default PoS validator weight
        // to avoid churn issues
        initialValidators[0] = InitialValidator({
            nodeID: DEFAULT_INITIAL_VALIDATOR_NODE_ID_1,
            weight: DEFAULT_INITIAL_VALIDATOR_WEIGHT,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY
        });
        // The second initial validator has a low weight so that it can be safely removed in tests
        initialValidators[1] = InitialValidator({
            nodeID: DEFAULT_INITIAL_VALIDATOR_NODE_ID_2,
            weight: DEFAULT_WEIGHT,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY
        });

        // Confirm the total initial weight
        uint64 initialWeight;
        for (uint256 i = 0; i < initialValidators.length; i++) {
            initialWeight += initialValidators[i].weight;
        }
        assertEq(initialWeight, DEFAULT_INITIAL_TOTAL_WEIGHT);

        return ConversionData({
            subnetID: DEFAULT_SUBNET_ID,
            validatorManagerBlockchainID: DEFAULT_SOURCE_BLOCKCHAIN_ID,
            validatorManagerAddress: address(validatorManager),
            initialValidators: initialValidators
        });
    }

    function _defaultConversionDataWeightsTooLow() internal view returns (ConversionData memory) {
        InitialValidator[] memory initialValidators = new InitialValidator[](2);

        initialValidators[0] = InitialValidator({
            nodeID: DEFAULT_INITIAL_VALIDATOR_NODE_ID_1,
            weight: 1,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY
        });
        initialValidators[1] = InitialValidator({
            nodeID: DEFAULT_INITIAL_VALIDATOR_NODE_ID_2,
            weight: 3,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY
        });

        return ConversionData({
            subnetID: DEFAULT_SUBNET_ID,
            validatorManagerBlockchainID: DEFAULT_SOURCE_BLOCKCHAIN_ID,
            validatorManagerAddress: address(validatorManager),
            initialValidators: initialValidators
        });
    }

    function _defaultConversionDataTotalWeight5() internal view returns (ConversionData memory) {
        InitialValidator[] memory initialValidators = new InitialValidator[](2);

        initialValidators[0] = InitialValidator({
            nodeID: DEFAULT_INITIAL_VALIDATOR_NODE_ID_1,
            weight: 1,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY
        });
        initialValidators[1] = InitialValidator({
            nodeID: DEFAULT_INITIAL_VALIDATOR_NODE_ID_2,
            weight: 4,
            blsPublicKey: DEFAULT_BLS_PUBLIC_KEY
        });

        return ConversionData({
            subnetID: DEFAULT_SUBNET_ID,
            validatorManagerBlockchainID: DEFAULT_SOURCE_BLOCKCHAIN_ID,
            validatorManagerAddress: address(validatorManager),
            initialValidators: initialValidators
        });
    }

    // This needs to be kept in line with the contract conversions, but we can't make external calls
    // to the contract and use vm.expectRevert at the same time.
    // These are okay to use for PoA as well, because they're just used for conversions inside the tests.
    function _valueToWeight(uint256 value) internal pure returns (uint64) {
        return uint64(value / 1e12);
    }

    // This needs to be kept in line with the contract conversions, but we can't make external calls
    // to the contract and use vm.expectRevert at the same time.
    // These are okay to use for PoA as well, because they're just used for conversions inside the tests.
    function _weightToValue(uint64 weight) internal pure returns (uint256) {
        return uint256(weight) * 1e12;
    }

    function _defaultSettings(address admin)
        internal
        pure
        returns (ValidatorManagerSettings memory)
    {
        return ValidatorManagerSettings({
            admin: admin,
            subnetID: DEFAULT_SUBNET_ID,
            churnPeriodSeconds: DEFAULT_CHURN_PERIOD,
            maximumChurnPercentage: DEFAULT_MAXIMUM_CHURN_PERCENTAGE
        });
    }

    function _erc7201StorageSlot(bytes memory storageName) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                uint256(keccak256(abi.encodePacked("avalanche-icm.storage.", storageName))) - 1
            )
        ) & ~bytes32(uint256(0xff));
    }

    function _fixedNodeID(bytes memory nodeID) internal pure returns (bytes20) {
        bytes20 fixedID;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            fixedID := mload(add(nodeID, 32))
        }
        return fixedID;
    }
}
// solhint-enable no-empty-blocks
