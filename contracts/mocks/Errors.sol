// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @custom:security-contact @captainunknown7@gmail.com
library Errors {
    error InvalidActorType(uint8 given, uint8 max);
    error InvalidBatchStatus(uint8 given, uint8 max);
    error OutOfBounds(uint256 given, uint256 max);
    error UnAuthorized(string expectedRole);
    error DoubleRegistrationNotAllowed();
    error SoulBoundTransferNotAllowed();
    error UnexpectedRequestID();
    error UnexpectedAgent(address calledBy, address expected);
    error FulfillmentFailed();
    error InvalidTokenId();
}