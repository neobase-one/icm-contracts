# Validator Manager Contract

> [!CAUTION]
> The contracts in this directory are still under active development, are unaudited, and should not be used in production.

The contracts in this directory define the Validator Manager used to manage Subnet-only Validators, as defined in [ACP-77](https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/77-reinventing-subnets). `ValidatorManager.sol` is the top-level abstract contract that provides the basic functionality. The other contracts are related as follows:

```mermaid
classDiagram
class ValidatorManager {
    initializeValidatorSet()
    completeValidatorRegistration()
    completeEndValidation()
    
}
<<Abstract>> ValidatorManager
class PoSValidatorManager {
    initializeEndValidation()
    completeDelegatorRegistration()
    initializeEndDelegation()
    completeEndDelegation()
}
<<Abstract>> PoSValidatorManager
class ERC20TokenStakingManager {
    initializeValidatorRegistration()
    initializeDelegatorRegistration()
}
class NativeTokenStakingManager {
    initializeValidatorRegistration() payable
    initializeDelegatorRegistration() payable
}
class PoAValidatorManager {
    initializeValidatorRegistration()
    initializeEndValidation()
}

ValidatorManager <|-- PoSValidatorManager
ValidatorManager <|-- PoAValidatorManager
PoSValidatorManager <|-- ERC20TokenStakingManager
PoSValidatorManager <|-- NativeTokenStakingManager
```

## Deploying

Three concrete `ValidatorManager` contracts are provided - `PoAValidatorManager`, `NativeTokenStakingManager`, and `ERC20TokenStakingManager`. `NativeTokenStakingManager`, and `ERC20TokenStakingManager` implement `PoSValidatorManager`, which itself implements `ValidatorManager`. These are implemented as [upgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/main/contracts/proxy/utils/Initializable.sol#L56) contracts. There are numerous [guides](https://blog.chain.link/upgradable-smart-contracts/) for deploying upgradeable smart contracts, but the general steps are as follows:
1. Deploy the implementation contract
2. Deploy the proxy contract
3. Call the implementation contract's `initialize` function
  - Each flavor of `ValidatorManager` requires different settings. For example, `ValidatorManagerSettings` specifies the churn parameters, while `PoSValidatorManagerSettings` specifies the staking and rewards parameters.
4. Initialize the Validator set by calling `initializeValidatorSet`
  - When a Subnet is first created on the P-Chain, it must be explicitly converted to a Subnet-only Validator compatible Subnet via [`ConvertSubnetTx`](https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/77-reinventing-subnets#setting-a-subnet-manager). The resulting `SubnetConversionMessage` Warp message is provided in the call to `initializeValidatorSet` to specify the starting Validator set in the `ValidatorManager`. Regardless of the implementation, these initial Validators are treated as PoA and are not eligible for staking rewards.

### PoAValidatorManager

Proof-of-Authority Validator management is provided via `PoAValidatorManager`, which restricts modification of the Validator set to an owner address. After deploying `PoAValidatorManager.sol` and a proxy, the `initialize` function takes the owner address, in addition to standard `ValidatorManagerSettings`.

### PoSValidatorManager

Proof-of-Stake Validator management is provided by the abstract contract `PoSValidatorManager`, which has two concrete implementations: `NativeTokenStakingManager` and `ERC20TokenStakingManager`. In addition to basic Validator management provided in `ValidatorManager`, `PoSValidatorManager` supports uptime-based Validation rewards, as well as Delegation to a Validator. This [state transition diagram](./StateTransition.md) illustrates the relationship between Validators and Delegators.

> [!NOTE]
> The `weightToValueFactor` fields of the `PoSValidatorManagerSettings` passed to `PoSValidatorManager`'s `initialize` function sets the factor used to convert between the weight that the Validator is registered with on the P-Chain, and the value transferred to the contract as stake. This involves integer division, which may result in loss of precision. When selecting `weightToValueFactor`, it's important to make the following considerations:
> 1. If `weightToValueFactor` is near the denomination of the asset, then staking amounts on the order of 1 unit of the asset may cause the converted weight to round down to 0. This may impose a larger-than-expected minimum stake amount.
>     - Ex: If USDC (denomination of 6) is used as the staking token and `weightToValueFactor` is 1e9, then any amount less than 1,000 USDC will round down to 0 and therefore be invalid.
> 2. Staked amounts up to `weightValueFactor - 1` may be lost in the contract as dust, as the Validator's registered weight is used to calculate the original staked amount.
>     - Ex: `value=1001` and `weightToValueFactor=1e3`. The resulting weight will be `1`. Converting the weight back to a value results in `value=1000`.
> 3. The Validator's weight is represented on the P-Chain as a `uint64`. `PoSValidatorManager` restricts values such that the calculated weight does not exceed the maximum value for that type.

#### NativeTokenStakingManager

`NativeTokenStakingManager` allows permissionless addition and removal of Validators that post the Subnet's native token as stake. Staking rewards are minted via the Native Minter Precompile, which is configured with a set of addresses with minting privileges. As such, the address that `NativeTokenStakingManager` is deployed to must be added as an admin to the precompile. This can be done by either calling the precompile's `setAdmin` method from an admin address, or setting the address in the Native Minter precompile settings in the chain's genesis (`config.contractNativeMinterConfig.adminAddresses`). There are a couple of methods to get this address: one is to calculate the resulting deployed address based on the deployer's address and account nonce: `keccak256(rlp.encode(address, nonce))`. The second method involves manually placing the `NativeTokenStakingManager` bytecode at a particular address in the genesis, then setting that address as an admin.

```
{
    "config" : {
        ...
        "contractNativeMinterConfig": {
            "blockTimestamp": 0,
            "adminAddresses": [
                "0xffffffffffffffffffffffffffffffffffffffff"
            ]
        }
    },
    "alloc": {
        "0xffffffffffffffffffffffffffffffffffffffff": {
            "balance": "0x0",
            "code": "<NativeTokenStakingManagerByteCode>",
            "nonce": 1
        }
    }
}
```

#### ERC20TokenStakingManager
`ERC20TokenStakingManager` allows permissionless addition and removal of Validators that post the an ERC20 token as stake. The ERC20 is specified in the call to `initialize`, and must implement [`IERC20Mintable`](./interfaces/IERC20Mintable.sol). Care should be taken to enforce that only authorized users are able to call `mint`.

### Convert PoA to PoS

A `PoAValidatorManager` can later be converted to a `PoSValidatorManager` by upgrading the implementation contract pointed to by the proxy. After performing the upgrade, the `PoSValidatorManager` contract should be initialized by calling `initialize` as described above. The Validator set contained in the `PoAValidatorManager` will be tracked by the `PoSValidatorManager` after the upgrade, but will not be eligible to earn staking rewards, nor are they able to be delegated to.

## Usage
### Register a Validator
Validator registration is initiated with a call to `initializeValidatorRegistration`. The sender of this transaction is registered as the Validator owner. Churn limitations are checked - only a certain (configurable) percentage of the total weight is allowed to be added or removed in a (configurable) period of time. The `ValidatorManager` then constructs a [`RegisterSubnetValidatorMessage`](./MessageSpec.md#registersubnetvalidatormessage) Warp message to be sent to the P-Chain. Each Validator registration request includes all of the information needed to identify the Validator and its stake weight, as well as an `expiry` timestamp before which the `RegisterSubnetValidatorMessage` must be delivered to the P-Chain. If the Validator is not registered on the P-Chain before the `expiry`, then the Validator may be removed from the contract state by calling `completeEndValidation`.

The `RegisterSubnetValidatorMessage` is delivered to the P-Chain as the Warp message payload of a [`RegisterSubnetValidatorTx`](https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/77-reinventing-subnets#registersubnetvalidatortx). Please see the transaction [specification](https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/77-reinventing-subnets#step-2-issue-a-registersubnetvalidatortx-on-the-p-chain) for validity requirements. The P-Chain then signs a [`SubnetValidatorRegistrationMessage`](./MessageSpec.md#subnetvalidatorregistrationmessage) Warp message indicating that the specified Validator was successfully registered on the P-Chain.

The `SubnetValidatorRegistrationMessage` is delivered to the `ValidatorManager` via a call to `completeValidatorRegistration`. For PoS Validator Managers, staking rewards begin accruing at this time.

### Remove a Validator
Validator exit is initiated with a call to `initializeEndValidation` on the `ValidatorManager`. Only the Validator owner may initiate exit. For `PoSValidatorManagers` a [`ValidationUptimeMessage`](./MessageSpec.md#validationuptimemessage) Warp message may optionally be provided in order to calculate the staking rewards; otherwise the latest received uptime will be used (see [(PoS only) Submit and Uptime Proof](#pos-only-submit-an-uptime-proof)). This proof may be requested directly from the Subnet Validators, which will provide it in a `ValidationUptimeMessage` Warp message. If the uptime is not sufficient to earn Validation rewards, the call to `initializeEndValidation` will fail. `forceInitializeEndValidation` acts the same as `initializeEndValidation`, but bypasses the uptime-based rewards check. Once `initializeEndValidation` or `forceInitializeEndValidation` is called, staking rewards cease accruing for `PoSValidatorManagers`. 

The `ValidatorManager` contructs a [`SetSubnetValidatorWeightMessage`](./MessageSpec.md#setsubnetvalidatorweightmessage) Warp message with the weight set to `0`. This is delivered to the P-Chain as the payload of a [`SetSubnetValidatorWeightTx`](https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/77-reinventing-subnets#setsubnetvalidatorweighttx). The P-Chain acknowledges Validator exit by signing a `SubnetValidatorRegistrationMessage` with `valid=0`, which is delivered to the `ValidatorManager` by calling `completeEndValidation`. The Validation is removed from the contract's state, and for `PoSValidatorManagers`, staking rewards are disbursed and stake is returned.

#### Disable a Validator Directly on the P-Chain

ACP-77 also provides a method to disable a Validator without interacting with the Subnet directly. The P-Chain transaction [`DisableValidatorTx`](https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/77-reinventing-subnets#disablevalidatortx) disables the Validator on the P-Chain. The disabled Validator's weight will still count towards the Subnet's total weight. 

Disabled Subnet Validators can re-activate at any time by increasing their balance with an `IncreaseBalanceTx`. Anyone can call `IncreaseBalanceTx` for any Validator on the P-Chain. A disabled Validator can only be totally removed from the Validator set by a call to `initializeEndValidation`.

### (PoS only) Register a Delegator

`PoSValidatorManager` supports Delegation to an active Validator as a way for users to earn staking rewards without having to validate the chain. Delegators pay a configurable percentage fee on any earned staking rewards to the host Validator. A Delegator may be registered by calling `initializeDelegatorRegistration` and providing an amount to stake. The sender of this transaction is registered as the Delegator owner. The Delegator will be registered as long as churn restrictions are not violated. The Delegator is reflected on the P-Chain by adjusting the Validator's registered weight via a [`SetSubnetValidatorWeightTx`](https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/77-reinventing-subnets#setsubnetvalidatorweighttx). The weight change acknowledgement is delivered to the `PoSValidatorManager` via a [`SubnetValidatorWeightUpdateMessage`](./MessageSpec.md#subnetvalidatorweightupdatemessage), which is provided by calling `completeDelegatorRegistration`.

> [!NOTE]
> The P-Chain is only willing to sign a `SubnetValidatorWeightUpdateMessage` for an active Validator. Once Validator exit has been initiated (via a call to `initializeEndValidation`), the `PoSValidatorManager` must assume that the Validator has been deactivated on the P-Chain, and will therefore not sign any further weight updates. Therefore, it is invalid to _initiate_ adding or removing a Delegator when the Validator is in this state, though it _may be_ valid to _complete_ an already initiated Delegator action, depending on the order of delivery to the P-Chain. If the Delegator weight change was submitted (and a Warp signature on the acknowledgement retrieved) before the Validator was removed, then the Delegator action may be completed. Otherwise, the acknowledgement of the Validation end must first be delivered before completing the Delegator action. 

### (PoS only) Remove a Delegator

Delegators removal may be initiated by calling `initializeEndDelegation`, as long as churn restrictions are not violated. Similar to `initializeEndValidation`, an uptime proof may be provided to be used to determine Delegator rewards eligibility. If no proof is provided, the latest known uptime will be used (see [(PoS only) Submit and Uptime Proof](#pos-only-submit-an-uptime-proof)). The Validator's weight is updated on the P-Chain by the same mechanism used to register a Delegator. The `SubnetValidatorWeightUpdateMessage` from the P-Chain is delivered to the `PoSValidatorManager` in the call to `completeEndDelegation`.

Either the Delegator owner or the Validator owner may initiate removing a Delegator. This is to prevent the Validator from being unable to remove itself due to churn limitations if it is has too high a proportion of the Subnet's total weight due to Delegator additions. The Validator owner may only remove Delegators after the minimum stake duration has elapsed.

### (PoS only) Submit an Uptime Proof

The [rewards calculater](./interfaces/IRewardCalculator.sol) is a function of uptime seconds since the Validator's start time. In addition to doing so in the calls to `initializeEndValidation` and `initializeEndDelegation` as described above, uptime proofs may also be supplied by calling `submitUptimeProof`. Unlike `initializeEndValidation` and `initializeEndDelegation`, `submitUptimeProof` may be called by anyone, decreasing the likelihood of a Validation or Delegation not being able to claim rewards that it deserved based on its actual uptime.

### (PoS only) Collect Staking Rewards
#### Validation Rewards

Validation rewards are distributed in the call to `completeEndValidation`.

#### Delegation Rewards

Delegation rewards are distributed in the call to `completeEndDelegation`.

#### Delegation Fees

Delegation fees owed to Validators are _not_ distributed when the Validation ends as to bound the amount of gas consumed in the call to `completeEndValidation`. Instead, `claimDelegationFees` may be called after the Validation is completed.