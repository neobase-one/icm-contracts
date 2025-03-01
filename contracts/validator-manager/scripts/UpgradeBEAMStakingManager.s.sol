// SPDX-License-Identifier: Ecosystem
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {ProxyAdmin} from "openzeppelin-contracts/proxy/transparent/ProxyAdmin.sol";
import {Native721TokenStakingManager} from "../Native721TokenStakingManager.sol";
import {ICMInitializable} from "@utilities/ICMInitializable.sol";
import {console} from "forge-std/console.sol";
import {StakingManagerSettings} from "../Native721TokenStakingManager.sol";
import {ValidatorManager} from "../ValidatorManager.sol";
import {IERC721} from "openzeppelin-contracts/token/ERC721/IERC721.sol";
import {TrackingRewardStreams} from "@euler-xyz/reward-streams@1.0.0/TrackingRewardStreams.sol";
import {ITransparentUpgradeableProxy} from "openzeppelin-contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @notice Script to upgrade the Native721TokenStakingManager implementation
 * 
 * @dev To run this script:
 * 1. Make sure the Native721TokenStakingManager contract has reinitializer(3) or higher
 *    (update from reinitializer(2) if needed)
 * 2. Update the proxy and proxy admin addresses below
 * 3. Run the script with forge:
 *    ```bash
 *    # Dry run (simulation)
 *    forge script contracts/validator-manager/scripts/UpgradeBEAMStakingManager.s.sol --slow --optimize --optimizer-runs 200 -vvv --rpc-url <your-rpc-url> --private-key <your-private-key>
 *
 *    # Live run
 *    forge script contracts/validator-manager/scripts/UpgradeBEAMStakingManager.s.sol --slow --optimize --optimizer-runs 200 -vvv --broadcast --verify --rpc-url <your-rpc-url> --private-key <your-private-key>
 *    ```
 */
contract UpgradeBEAMStakingManager is Script {
    // Update these addresses with your deployed contract addresses
    address constant _PROXY_ADDRESS = address(0x27791E2Df9aB9e6D4Fb34972634724A45131C2aa);
    address constant _PROXY_ADMIN_ADDRESS = address(0x06f373D6298398697d359ab5aA93DA24FB5D3cd0);

    // Add necessary constants
    address constant _NFT_TOKEN_ADDRESS = address(0xA74e49F3fB56b2Eaa61AC74FBe300b8ff2003098);
    address constant _ADMIN_ADDRESS = address(0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC);
    address constant _VALIDATOR_MANAGER_ADDRESS = address(0xfAcadE0000000000000000000000000000000000);
    uint64 constant _MINIMUM_STAKE_DURATION = 1 hours;
    uint256 constant _MINIMUM_STAKE_AMOUNT = 20e18;
    uint256 constant _MAXIMUM_STAKE_AMOUNT = 50e24;
    uint64 constant _UNLOCK_PERIOD = 1 hours;
    uint16 constant _MINIMUM_DELEGATION_FEE = 100;
    uint64 constant _EPOCH_DURATION = 7 days;
    uint256 constant _MAXIMUM_NFT_AMOUNT = 1000;
    uint256 constant _MINIMUM_DELEGATION_AMOUNT = 1e18;
    bytes32 constant _UPTIME_BLOCKCHAIN_ID = bytes32(hex"0d5c3cfbccc694b3d5490a2de71d43d391f6c73dac86ed5169572d7646c7ece2");

    function run() external {
        vm.startBroadcast();

        // Deploy new implementation
        Native721TokenStakingManager newImplementation = new Native721TokenStakingManager(
            ICMInitializable.Disallowed
        );
        console.log("Deployed new implementation at:", address(newImplementation));

        // Add settings struct for initialization
        StakingManagerSettings memory settings = StakingManagerSettings({
            manager: ValidatorManager(_VALIDATOR_MANAGER_ADDRESS),
            minimumStakeAmount: _MINIMUM_STAKE_AMOUNT,
            maximumStakeAmount: _MAXIMUM_STAKE_AMOUNT,
            maximumNFTAmount: _MAXIMUM_NFT_AMOUNT,
            minimumStakeDuration: _MINIMUM_STAKE_DURATION,
            minimumDelegationAmount: _MINIMUM_DELEGATION_AMOUNT,
            minimumDelegationFeeBips: _MINIMUM_DELEGATION_FEE,
            weightToValueFactor: 1,
            validatorRemovalAdmin: _ADMIN_ADDRESS,
            uptimeBlockchainID: _UPTIME_BLOCKCHAIN_ID,
            epochDuration: _EPOCH_DURATION,
            unlockDuration: _UNLOCK_PERIOD
        });

       // Get ProxyAdmin instance
        ProxyAdmin proxyAdmin = ProxyAdmin(_PROXY_ADMIN_ADDRESS);

        // Upgrade proxy to new implementation
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(_PROXY_ADDRESS),
            address(newImplementation),
            abi.encodeWithSelector(Native721TokenStakingManager.initialize.selector, settings, address(_NFT_TOKEN_ADDRESS))
        );
        console.log("Upgraded proxy to new implementation");

        vm.stopBroadcast();

        console.log("Upgrade verified successfully");
    }
}
