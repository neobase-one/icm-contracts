// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {Test} from "@forge-std/Test.sol";
import {StakingManagerTest} from "./StakingManagerTests.t.sol";
import {NativeTokenStakingManager} from "../NativeTokenStakingManager.sol";
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
import {Native721TokenStakingManager} from "../Native721TokenStakingManager.sol";
import {console} from "forge-std/console.sol";
import {WarpMessage, IWarpMessenger} from
    "@avalabs/subnet-evm-contracts@1.2.0/contracts/interfaces/IWarpMessenger.sol";

import {ExampleERC20} from "@mocks/ExampleERC20.sol";

contract ForkTest is Test {
    Native721TokenStakingManager public app;
    ExampleERC20 public rewardToken;

    uint256 mainnetFork;
    // string MAINNET_RPC_URL = "https://build.onbeam.com/rpc/testnet";
    string MAINNET_RPC_URL = "https://build.onbeam.com/rpc";
    
    address public constant WARP_PRECOMPILE_ADDRESS = 0x0200000000000000000000000000000000000005;

    function setUp() public {
        mainnetFork = vm.createFork(MAINNET_RPC_URL);
        vm.selectFork(mainnetFork);

        vm.etch(
            address(0x2FD428A5484d113294b44E69Cb9f269abC1d5B54),
            address(new Native721TokenStakingManager(ICMInitializable.Disallowed)).code
        );

        // app = Native721TokenStakingManager(0xF4B5869AabE19a106C0df25E1537d855b54EEcBD);
        app = Native721TokenStakingManager(0x2FD428A5484d113294b44E69Cb9f269abC1d5B54);

        rewardToken = new ExampleERC20();
        rewardToken.mint(0x277280e8337E64a3A8E8b795D4E8E5e00BF6e203, 100000e18);
        
        vm.prank(0x277280e8337E64a3A8E8b795D4E8E5e00BF6e203);
        rewardToken.approve(address(app), 100000e18);

        vm.prank(0x277280e8337E64a3A8E8b795D4E8E5e00BF6e203);
        app.registerRewards(false, 673, address(rewardToken), 100000e18);
        // app.registerRewards(true, 673, address(rewardToken), 100000e18);

        vm.warp(1748803326);
    }

    function testFork() public {
        bytes32 validationID = 0x3320d740f6bf69a6f2fe6306231f9bdf1d8b6f4a60023c7343744e53a46139c5;

        bytes memory uptimeMessage =
            ValidatorMessages.packValidationUptimeMessage(validationID, 1000000);

        vm.mockCall(
            WARP_PRECOMPILE_ADDRESS,
            abi.encodeWithSelector(IWarpMessenger.getVerifiedWarpMessage.selector, uint32(0)),
            abi.encode(
                WarpMessage({
                    sourceChainID: bytes32(hex"f94107902c8418dfcdf51d3f95429688abc7109e0f5b0e806c7e204d542e0761"),
                    originSenderAddress: address(0),
                    payload: uptimeMessage
                }),
                true
            )
        );
        vm.expectCall(
            WARP_PRECOMPILE_ADDRESS, abi.encodeCall(IWarpMessenger.getVerifiedWarpMessage, 0)
        );

        vm.prank(0x277280e8337E64a3A8E8b795D4E8E5e00BF6e203);
        app.submitUptimeProof(validationID, 0);

        address[] memory tokens = new address[](1);
        tokens[0] = address(rewardToken);

        vm.prank(0xbC2aC150FA9459aEda7a4773bd209b57bE2b3fF1);
        app.claimRewards(false, 673, tokens, 0xbC2aC150FA9459aEda7a4773bd209b57bE2b3fF1);
        // console.log(app.getRewards(false, 673, tokens)[0]);

        vm.prank(0xF607A84D55Ba18B80C72b259283E9EC3EF0B49cD);
        app.claimRewards(false, 673, tokens, 0xF607A84D55Ba18B80C72b259283E9EC3EF0B49cD);

        vm.prank(0x9F1576651cd40D1eA5542622DAad4B95f779E023);
        app.claimRewards(false, 673, tokens, 0xF607A84D55Ba18B80C72b259283E9EC3EF0B49cD);
        vm.prank(0xDE0eD312c2a3F9A105A00A2c65D4487Be7249e18);
        app.claimRewards(false, 673, tokens, 0xDE0eD312c2a3F9A105A00A2c65D4487Be7249e18);
        vm.prank(0xc00667d8B00f35B3565A5c4458Dff1Cd718E3527);
        app.claimRewards(false, 673, tokens, 0xc00667d8B00f35B3565A5c4458Dff1Cd718E3527);
        vm.prank(0xbBA6Bc5c6eAfC06b5640C1cdD731e86811910a20);
        app.claimRewards(false, 673, tokens, 0xbBA6Bc5c6eAfC06b5640C1cdD731e86811910a20);
    }
}
