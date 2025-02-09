// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract PaymentToken is ERC20, ERC20Permit {
    constructor() ERC20("PaymentToken", "PTK") ERC20Permit("PaymentToken") {}
}
