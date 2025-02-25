// SPDX-License-Identifier: Ecosystem
pragma solidity 0.8.25;

import {ICMInitializable} from "@utilities/ICMInitializable.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {Script} from "forge-std/Script.sol";
import {
    ValidatorManagerSettings, ValidatorManager
} from "../ValidatorManager.sol";
import {console} from "forge-std/console.sol";

/**
 * @notice Script to upgrade ValidatorManager implementation and initialize it
 * 
 * @dev IMPORTANT: Before running this script:
 * 1. Ensure ValidatorManager.initialize() is decorated with initializer(2)
 * 2. Ensure foundry.toml has evm_version = "cancun"
 * 
 * To run this script:
 * 1. Update the hardcoded addresses and initialization parameters below
 * 2. Run the script with forge:
 *    ```bash
 *    # Dry run (simulation)
 *    forge script contracts/validator-manager/scripts/UpgradeValidatorManager.s.sol --slow --optimize --optimizer-runs 200 -vvv --rpc-url <your-rpc-url> --private-key <your-private-key>
 *
 *    # Live run
 *    forge script contracts/validator-manager/scripts/UpgradeValidatorManager.s.sol --slow --optimize --optimizer-runs 200 -vvv --broadcast --verify --rpc-url <your-rpc-url>  --private-key <your-private-key>
 *    ```
 */
contract UpgradeValidatorManager is Script {
    // Hardcoded addresses
    address private constant _PROXY_ADDRESS = address(0xfAcadE0000000000000000000000000000000000); // Replace with actual proxy address
    
    // Example initialization parameters - adjust as needed
    address private constant _ADMIN_ADDRESS = address(0xa02d3B70696a4c0dB5DE93eF6C68eFf37a6A7eE1); // Replace with admin address
    bytes32 private constant _SUBNET_ID = bytes32(hex"398f2502fdf00ea7aa2756ebce5f608d4b59b9af3cd577c4910d3bfce1fdf1b5"); // convert your SubnetID to hex using avatools.io
    uint64 private constant _CHURN_PERIOD = 0 days;
    uint8 private constant _MAX_CHURN_PERCENTAGE = 20;

    function run() external {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Deploy new implementation
        ValidatorManager newImplementation = new ValidatorManager(ICMInitializable.Disallowed);
        console.log("New ValidatorManager implementation deployed at:", address(newImplementation));
        // Prepare initialization data
        ValidatorManagerSettings memory settings = ValidatorManagerSettings({
            admin: _ADMIN_ADDRESS,
            subnetID: _SUBNET_ID,
            churnPeriodSeconds: _CHURN_PERIOD,
            maximumChurnPercentage: _MAX_CHURN_PERCENTAGE
        });

        // Encode the initialization call
        bytes memory initData = abi.encodeWithSelector(
            ValidatorManager.initialize.selector,
            settings
        );

        // Get ProxyAdmin interface and perform upgrade + initialization in one transaction
        bytes32 adminSlot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        address proxyAdmin = address(uint160(uint256(vm.load(address(_PROXY_ADDRESS), adminSlot))));
        console.log("ProxyAdmin contract deployed at:", proxyAdmin);
        ProxyAdmin(proxyAdmin).upgradeAndCall(
            ITransparentUpgradeableProxy(_PROXY_ADDRESS),
            address(newImplementation),
            initData
        );

        vm.stopBroadcast();
    }
} 