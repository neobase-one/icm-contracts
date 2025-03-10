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

contract ForkTest is Test {
    Native721TokenStakingManager public app;
    uint256 mainnetFork;
    string MAINNET_RPC_URL = "https://build.onbeam.com/rpc/testnet";
    
    address public constant WARP_PRECOMPILE_ADDRESS = 0x0200000000000000000000000000000000000005;

    function setUp() public {
        mainnetFork = vm.createFork(MAINNET_RPC_URL);
        vm.selectFork(mainnetFork);

        app = Native721TokenStakingManager(0xF4B5869AabE19a106C0df25E1537d855b54EEcBD);
    }

    function testFork() public {
        bytes32 validationID = 0x5f53702ebf9e5702affadf341d85760d899af644851087ffa364a8887137be77;

        bytes memory uptimeMessage =
            ValidatorMessages.packValidationUptimeMessage(validationID, 10000);

        vm.mockCall(
            WARP_PRECOMPILE_ADDRESS,
            abi.encodeWithSelector(IWarpMessenger.getVerifiedWarpMessage.selector, uint32(0)),
            abi.encode(
                WarpMessage({
                    sourceChainID: bytes32(hex"7f78fe8ca06cefa186ef29c15231e45e1056cd8319ceca0695ca61099e610355"),
                    originSenderAddress: address(0),
                    payload: uptimeMessage
                }),
                true
            )
        );
        vm.expectCall(
            WARP_PRECOMPILE_ADDRESS, abi.encodeCall(IWarpMessenger.getVerifiedWarpMessage, 0)
        );

        // console.log(app.validateUptime(validationID, 0));
        // console.log(address(app.erc721()));

        vm.prank(0xd68F802fD0B6f56524F379805DD8FcC152DB9d5c);
        app.submitUptimeProof(validationID, 0);
    }
}
