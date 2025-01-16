// SPDX-License-Identifier: Ecosystem
pragma solidity 0.8.25;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract ExampleERC721 is ERC721 {
    constructor() ERC721("Example NFT", "ENFT") {
        _mint(msg.sender, 1);
        _mint(msg.sender, 2);
        _mint(msg.sender, 3);
        _mint(msg.sender, 4);
        _mint(msg.sender, 5);
        _mint(msg.sender, 6);
    }

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }

}
