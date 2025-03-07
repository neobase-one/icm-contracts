// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {ValidatorManager} from "../ValidatorManager.sol";
import {Native721TokenStakingManager} from "../Native721TokenStakingManager.sol";
import {ProxyAdmin} from "@openzeppelin/contracts@5.0.2/proxy/transparent/ProxyAdmin.sol";

/**
 * @notice Script to transfer ownership of ValidatorManager to StakingManager
 */
contract TransferProxyAdminOwnerScript is Script {
    // Environment variables
    address constant PROXY_ADMIN = address(0x779F6FFAaeaB220fe43d28D954b4f652EB1dae5d);
    address constant NEW_OWNER = address(0x277280e8337E64a3A8E8b795D4E8E5e00BF6e203);

    function run() external {
        
        // Start broadcasting transactions
        vm.startBroadcast();

        // Get ProxyAdmin instance
        ProxyAdmin proxyAdmin = ProxyAdmin(PROXY_ADMIN);

        // Transfer ownership to new owner
        proxyAdmin.transferOwnership(NEW_OWNER);

        vm.stopBroadcast();
    }
}
