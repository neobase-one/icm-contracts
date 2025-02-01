pragma solidity 0.8.25;

import "forge-std/Script.sol";
import { ERC721TokenStakingManager } from "../contracts/validator-manager/ERC721TokenStakingManager.sol";
import { NativeTokenStakingManager } from "../contracts/validator-manager/NativeTokenStakingManager.sol";

import {
    PoSValidatorManagerSettings
} from "../contracts/validator-manager/interfaces/IPoSValidatorManager.sol";

import {
    ValidatorManagerSettings
} from "../contracts/validator-manager/interfaces/IValidatorManager.sol";

import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

import {IRewardCalculator} from "../contracts/validator-manager/interfaces/IRewardCalculator.sol";
import {IBalanceTracker} from "@euler-xyz/reward-streams@1.0.0/interfaces/IBalanceTracker.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {ICMInitializable} from "../contracts/utilities/ICMInitializable.sol";


contract DeploymentScript is Script {
    function setUp() public {}

    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        PoSValidatorManagerSettings memory settings = PoSValidatorManagerSettings({
            baseSettings: ValidatorManagerSettings({
                l1ID: 0xa10e2e09c4dc6244329dee519c42b6a9b3dc534509c61f04ba337abf787bc6de,
                churnPeriodSeconds: 1 minutes,
                maximumChurnPercentage: 20
            }),
            minimumStakeAmount: 1e18,
            maximumStakeAmount: 1e24,
            minimumNFTAmount: 0,
            maximumNFTAmount: 100,
            minimumStakeDuration: 5 minutes,
            minimumDelegationFeeBips: 100,
            maximumStakeMultiplier: 10,
            weightToValueFactor: 1e12,
            unlockDelegateDuration: 5 minutes,
            rewardCalculator: IRewardCalculator(address(0)),
            balanceTracker: IBalanceTracker(address(0)),
            balanceTrackerNFT: IBalanceTracker(address(0)),
            epochDuration: 1 hours,
            uptimeBlockchainID: 0x0000000000000000000000000000000000000000000000000000000000000001
        });
        
        vm.startBroadcast(privateKey);
        
        ERC721TokenStakingManager impl = new ERC721TokenStakingManager(ICMInitializable.Allowed);
        // impl.initialize(settings);

        // address proxy = UnsafeUpgrades.deployUUPSProxy(
            // address(impl),
            // abi.encodeCall(ERC721TokenStakingManager.initialize,(settings, IERC721(address(1))))
            // abi.encodeCall(NativeTokenStakingManager.initialize,(settings))
        // );

        vm.stopBroadcast();
    }
}
