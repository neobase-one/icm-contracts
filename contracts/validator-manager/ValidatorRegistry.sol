pragma solidity 0.8.25;

import {INativeTokenStakingManager} from "./interfaces/INativeTokenStakingManager.sol";
import {IERC721TokenStakingManager} from "./interfaces/IERC721TokenStakingManager.sol";
import {ValidatorRegistrationInput} from "./interfaces/IValidatorManager.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract ValidatorRegistry is Ownable {
    INativeTokenStakingManager public nativeTokenStakingManager;
    IERC721TokenStakingManager public erc721TokenStakingManager;
    uint256 public minAmount;

    constructor(address _nativeTokenStakingManager, address _erc721TokenStakingManager, uint256 _minAmount) Ownable(msg.sender) {
        nativeTokenStakingManager = INativeTokenStakingManager(_nativeTokenStakingManager);
        erc721TokenStakingManager = IERC721TokenStakingManager(_erc721TokenStakingManager);
        minAmount = _minAmount;
    }

     function registerValidator(
        ValidatorRegistrationInput calldata registrationInput,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 tokenId
    ) external payable{

        nativeTokenStakingManager.initializeValidatorRegistration{value: msg.value}(registrationInput, delegationFeeBips, minStakeDuration);
        erc721TokenStakingManager.initializeValidatorRegistration(registrationInput, delegationFeeBips, minStakeDuration, tokenId);
    }

    function setMinAmount(uint256 _minAmount) public onlyOwner {
        minAmount = _minAmount;
    }
}