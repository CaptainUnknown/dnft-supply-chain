// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../String.sol";

contract StringTest {
    function uintToString(uint256 value) public pure returns (string memory) {
        return String.toString(value);
    }

    function memcmp(bytes memory a, bytes memory b) public pure returns (bool) {
        return String.memcmp(a, b);
    }

    function strcmp(string memory a, string memory b) public pure returns (bool) {
        return String.strcmp(a, b);
    }
}