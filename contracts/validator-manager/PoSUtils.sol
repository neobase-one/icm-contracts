// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

import {
    PoSValidatorManager
} from "./PoSValidatorManager.sol";

import {
    Delegator,
    DelegatorNFT,
    DelegatorStatus,
    PoSValidatorInfo
} from "./interfaces/IPoSValidatorManager.sol";

library PoSUtils {
    uint16 public constant BIPS_CONVERSION_FACTOR = 10000;

    function removeFromBytes32Array(bytes32[] storage array, bytes32 item) public {
        for (uint256 i = 0; i < array.length; i++) {
            if (array[i] == item) {
                // Move the last element to this position and pop
                array[i] = array[array.length - 1];
                array.pop();
                break;
            }
        }
    }    
     
    /**
    * @notice Calculates the effective weight of a delegator's stake based on the change in uptime over an epoch.
    * @dev This function computes the effective weight by considering the delegator's stake (`weight`) and the
    *      difference between the current uptime and the previous epoch's uptime, normalized by the epoch duration.
    *      If the current uptime is zero or less than the previous uptime, the effective weight is zero.
    * @param weight The original weight of the delegator's stake.
    * @param currentUptime The validator's current uptime for the epoch.
    * @param previousUptime The validator's uptime for the previous epoch.
    * @return effectiveWeight The effective weight of the delegator's stake based on uptime and epoch duration.
    */
    function _calculateEffectiveWeight(
         uint256 weight,
         uint64 currentUptime,
         uint64 previousUptime,
         uint64 epochDuration
    ) internal view returns (uint256) {
        if(previousUptime > currentUptime || currentUptime == 0) {
            return 0;
        }
        // Calculate effective weight based on both weight and time period
        return (weight * (currentUptime - previousUptime)) / epochDuration;
    }

    /**
    * @notice Calculates the total weight and NFT weight for a given account based on its roles as a validator, delegator, and NFT delegator.
    * @dev This function aggregates the weight and NFT weight of an account by summing:
    *      - The account's weight as a validator.
    *      - Delegation fee weights from delegators for the account's validations.
    *      - The account's weight as a delegator and NFT delegator for other validators.
    * @param account The address of the account for which the weights are being calculated.
    * @return weight The total weight of the account, including its validator and delegator weights.
    * @return nftWeight The total NFT weight of the account, including its NFT validator and NFT delegator weights.
    */
    function calculateAccountWeight(
        address account,
        PoSValidatorManager.PoSValidatorManagerStorage storage $
    ) public view returns (uint256, uint256) {
        uint256 weight;
        uint256 nftWeight;

        // sum weights as validator
        for (uint256 i = 0; i < $._accountValidations[account].length; i++) {
            bytes32 validationID = $._accountValidations[account][i];
            weight += _calculateEffectiveWeight(
                $._posValidatorInfo[validationID].weight,
                $._posValidatorInfo[validationID].uptimeSeconds,
                $._posValidatorInfo[validationID].prevEpochUptimeSeconds,
                $._epochDuration
            );
            nftWeight += _calculateEffectiveWeight(
                $._posValidatorInfo[validationID].nftWeight,
                $._posValidatorInfo[validationID].uptimeSeconds,
                $._posValidatorInfo[validationID].prevEpochUptimeSeconds,
                $._epochDuration
            );
            // add the weight of all active delegation fees
            bytes32[] memory delegations = $._validatorDelegations[validationID];
            for (uint256 j = 0; j < delegations.length; j++) {
                Delegator memory delegator = $._delegatorStakes[delegations[j]];
                if (delegator.status == DelegatorStatus.Active) {
                    uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                        delegator.weight,
                        $._posValidatorInfo[validationID].uptimeSeconds,
                        $._posValidatorInfo[validationID].prevEpochUptimeSeconds,
                        $._epochDuration
                    );
                    uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                    weight += delegatorFeeWeight;
                }
            }
            // add the weight of all active NFT delegation fees
            bytes32[] memory nftDelegations = $._validatorNFTDelegations[validationID];
            for (uint256 j = 0; j < nftDelegations.length; j++) {
                DelegatorNFT memory delegator = $._delegatorNFTStakes[nftDelegations[j]];
                if (delegator.status == DelegatorStatus.Active) {
                    uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                        delegator.weight,
                        $._posValidatorInfo[validationID].uptimeSeconds,
                        $._posValidatorInfo[validationID].prevEpochUptimeSeconds,
                        $._epochDuration
                    );
                    uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                    nftWeight += delegatorFeeWeight;
                }
            }
        }

        // sum weights as delegator
        for (uint256 i = 0; i < $._accountDelegations[account].length; i++) {
            bytes32 delegationID = $._accountDelegations[account][i];
            Delegator memory delegator = $._delegatorStakes[delegationID];
            if (delegator.owner != address(0)) {
                uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                    delegator.weight,
                    $._posValidatorInfo[delegator.validationID].uptimeSeconds,
                    $._posValidatorInfo[delegator.validationID].prevEpochUptimeSeconds,
                    $._epochDuration
                );
                uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[delegator.validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                weight += delegateEffectiveWeight - delegatorFeeWeight;
            }   
        }

        // sum weights as NFT delegator
        for (uint256 i = 0; i < $._accountNFTDelegations[account].length; i++) {
            bytes32 delegationID = $._accountNFTDelegations[account][i];
            DelegatorNFT memory delegator = $._delegatorNFTStakes[delegationID];
            if (delegator.owner != address(0)) {
                uint256 delegateEffectiveWeight = _calculateEffectiveWeight(
                    delegator.weight,
                    $._posValidatorInfo[delegator.validationID].uptimeSeconds,
                    $._posValidatorInfo[delegator.validationID].prevEpochUptimeSeconds,
                    $._epochDuration
                );
                uint256 delegatorFeeWeight = (delegateEffectiveWeight * $._posValidatorInfo[delegator.validationID].delegationFeeBips)
                / BIPS_CONVERSION_FACTOR;
                nftWeight += delegateEffectiveWeight - delegatorFeeWeight;
            }   
        }
        return (weight, nftWeight);
    }
}