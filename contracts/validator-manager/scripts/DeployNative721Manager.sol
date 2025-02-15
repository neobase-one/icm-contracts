pragma solidity 0.8.25;

import "forge-std/Script.sol";
import { Native721TokenStakingManager } from "../Native721TokenStakingManager.sol";

import {
    StakingManagerSettings
} from "../interfaces/IStakingManager.sol";

import {
    ValidatorManagerSettings, ValidatorManager
} from "../ValidatorManager.sol";

import {UnsafeUpgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

import {IBalanceTracker} from "@euler-xyz/reward-streams@1.0.0/interfaces/IBalanceTracker.sol";
import {IERC721} from "@openzeppelin/contracts@5.0.2/token/ERC721/IERC721.sol";
import {ICMInitializable} from "../../utilities/ICMInitializable.sol";
import {TrackingRewardStreams} from "@euler-xyz/reward-streams@1.0.0/TrackingRewardStreams.sol";
import {ExampleERC721} from "@mocks/ExampleERC721.sol";
import {ExampleERC20} from "@mocks/ExampleERC20.sol";
import {EthereumVaultConnector} from "evc/EthereumVaultConnector.sol";
import {IRewardCalculator} from "../interfaces/IRewardCalculator.sol";


// to run the script, populate .env with PRIVATE_KEY and run
// `forge script contracts/validator-manager/scripts/DeployNative721Manager.sol --rpc-url <rpc-url> --slow --optimize --optimizer-runs 200 -vvv`
// add `--broadcast` to broadcast the transactions

contract DeploymentScript is Script {
    function setUp() public {}

    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = 0xd68F802fD0B6f56524F379805DD8FcC152DB9d5c;

        vm.startBroadcast(privateKey);

        // deploy peripherals
        ExampleERC20 rewardToken = new ExampleERC20();
        ExampleERC721 stakingToken = new ExampleERC721();

        EthereumVaultConnector evc = new EthereumVaultConnector();
        TrackingRewardStreams balanceTracker = new TrackingRewardStreams(address(evc), 7 days);
        TrackingRewardStreams balanceTrackerNFT = new TrackingRewardStreams(address(evc),  7 days);

        // deploy validator manager
        ValidatorManager validatorManager = new ValidatorManager(ICMInitializable.Allowed);
        validatorManager.initialize(ValidatorManagerSettings({
            admin: deployer,
            subnetID: bytes32(hex"1234567812345678123456781234567812345678123456781234567812345678"),
            churnPeriodSeconds: 1 hours,
            maximumChurnPercentage: 20
        }));
        
        // deploy native721 token staking manager with proxy
        StakingManagerSettings memory settings = StakingManagerSettings({
            manager: validatorManager,
            minimumStakeAmount: 1e18,
            maximumStakeAmount: 50e24,
            maximumNFTAmount: 1000,
            minimumStakeDuration: 1 hours,
            minimumDelegationAmount: 1e18,
            minimumDelegationFeeBips: 100,
            maximumStakeMultiplier: 4,
            weightToValueFactor: 1e12,
            validatorRemovalAdmin: deployer,
            rewardCalculator: IRewardCalculator(address(0)),
            uptimeBlockchainID: bytes32(hex"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
            epochDuration: 7 days,
            balanceTracker: balanceTracker,
            balanceTrackerNFT: balanceTrackerNFT,
            unlockDuration: 1 hours
        });
        
        Native721TokenStakingManager impl = new Native721TokenStakingManager(ICMInitializable.Allowed);

        address proxy = UnsafeUpgrades.deployTransparentProxy(
            address(impl),
            deployer,
            abi.encodeCall(Native721TokenStakingManager.initialize,(settings, stakingToken))
        );

        vm.stopBroadcast();
    }
}