// SPDX-License-Identifier: Ecosystem

pragma solidity 0.8.25;

library PoSUtils {
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
}