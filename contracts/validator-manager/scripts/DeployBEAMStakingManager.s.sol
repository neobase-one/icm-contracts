// SPDX-License-Identifier: Ecosystem
pragma solidity 0.8.25;

import {ICMInitializable} from "@utilities/ICMInitializable.sol";
import {Script} from "forge-std/Script.sol";
import {
    StakingManagerSettings,
    Native721TokenStakingManager
} from "../Native721TokenStakingManager.sol";
import {ValidatorManager} from "../ValidatorManager.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {console} from "forge-std/console.sol";
import {ProxyAdmin} from "@openzeppelin/contracts@5.0.2/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts@5.0.2/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts@5.0.2/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @notice Script to deploy and initialize Native721TokenStakingManager with a new proxy
 * 
 * @dev To run this script:
 * 1. Update the initialization parameters below
 * 2. Run the script with forge:
 *    ```bash
 *    # Dry run (simulation)
 *    forge script contracts/validator-manager/scripts/DeployBEAMStakingManager.s.sol --slow --optimize --optimizer-runs 200 -vvv --rpc-url <your-rpc-url> --private-key <your-private-key>
 *
 *    # Live run
 *    forge script contracts/validator-manager/scripts/DeployBEAMStakingManager.s.sol --slow --optimize --optimizer-runs 200 -vvv --broadcast --verify --rpc-url <your-rpc-url>  --private-key <your-private-key>
 *    ```
 */
contract DeployBEAMStakingManager is Script {
    // Initialization parameters
    address constant NFT_TOKEN_ADDRESS = address(0xA74e49F3fB56b2Eaa61AC74FBe300b8ff2003098);
    address constant ADMIN_ADDRESS = address(0xa02d3B70696a4c0dB5DE93eF6C68eFf37a6A7eE1);
    address constant VALIDATOR_MANAGER_ADDRESS = address(0xfAcadE0000000000000000000000000000000000); // Replace with actual address
    uint64 constant MINIMUM_STAKE_DURATION = 1 hours;
    uint256 constant MINIMUM_STAKE_AMOUNT = 20e18;
    uint256 constant MAXIMUM_STAKE_AMOUNT = 50e24;
    uint64 constant UNLOCK_PERIOD = 1 hours;
    uint16 constant MINIMUM_DELEGATION_FEE = 100; // 0.1% in basis points
    uint64 constant EPOCH_DURATION = 7 days;
    uint256 constant MAXIMUM_NFT_AMOUNT = 1000;
    uint256 constant MINIMUM_DELEGATION_AMOUNT = 1e18;
    bytes32 constant UPTIME_BLOCKCHAIN_ID = bytes32(hex"0d5c3cfbccc694b3d5490a2de71d43d391f6c73dac86ed5169572d7646c7ece2");

    function run() external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Deploy implementation
        Native721TokenStakingManager implementation = new Native721TokenStakingManager(ICMInitializable.Disallowed);
        console.log("Deployed implementation at:", address(implementation));

        // Prepare initialization data
        StakingManagerSettings memory settings = StakingManagerSettings({
            manager: ValidatorManager(VALIDATOR_MANAGER_ADDRESS),
            minimumStakeAmount: MINIMUM_STAKE_AMOUNT,
            maximumStakeAmount: MAXIMUM_STAKE_AMOUNT,
            maximumNFTAmount: MAXIMUM_NFT_AMOUNT,
            minimumStakeDuration: MINIMUM_STAKE_DURATION,
            minimumDelegationAmount: MINIMUM_DELEGATION_AMOUNT,
            minimumDelegationFeeBips: MINIMUM_DELEGATION_FEE,
            weightToValueFactor: 1,
            validatorRemovalAdmin: ADMIN_ADDRESS,
            uptimeBlockchainID: UPTIME_BLOCKCHAIN_ID,
            epochDuration: EPOCH_DURATION,
            unlockDuration: UNLOCK_PERIOD
        });

        bytes memory initData = abi.encodeWithSelector(
            Native721TokenStakingManager.initialize.selector,
            settings,
            IERC721(NFT_TOKEN_ADDRESS)
        );

        // Deploy proxy with initialization
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(implementation),
            msg.sender,
            initData
        );
        console.log("Deployed and initialized proxy at:", address(proxy));

        bytes32 ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        address proxyAdmin = address(uint160(uint256(vm.load(address(proxy), ADMIN_SLOT))));
        console.log("ProxyAdmin contract deployed at:", proxyAdmin);

        vm.stopBroadcast();
    }
}
