// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {ValidatorManager} from "../ValidatorManager.sol";
import {Native721TokenStakingManager} from "../Native721TokenStakingManager.sol";

/**
 * @notice Script to transfer ownership of ValidatorManager to StakingManager
 * 
 * @dev To run this script:
 * 1. Update the hardcoded addresses below
 * 2. Run the script with forge:
 *    ```bash
 *    # Dry run (simulation)
 *    forge script contracts/validator-manager/scripts/TransferOwner.s.sol --slow --optimize --optimizer-runs 200 -vvv --rpc-url <your-rpc-url> --private-key <your-private-key>
 *
 *    # Live run
 *    forge script contracts/validator-manager/scripts/TransferOwner.s.sol --slow --optimize --optimizer-runs 200 -vvv --broadcast --verify --rpc-url <your-rpc-url>  --private-key <your-private-key>
 *    ```
 */
contract TransferOwnerScript is Script {
    // Environment variables
    address constant VALIDATOR_MANAGER = address(0xfAcadE0000000000000000000000000000000000); // TODO: Replace with actual address
    address constant STAKING_MANAGER = address(0x5aFf8556344baDbAF3a48a7e75eF89990b00a60e);   // TODO: Replace with actual address

    function run() external {
        
        // Start broadcasting transactions
        vm.startBroadcast();

        // Get ValidatorManager instance
        ValidatorManager validatorManager = ValidatorManager(VALIDATOR_MANAGER);

        // Transfer ownership to StakingManager
        validatorManager.transferOwnership(STAKING_MANAGER);

        vm.stopBroadcast();
    }
}
