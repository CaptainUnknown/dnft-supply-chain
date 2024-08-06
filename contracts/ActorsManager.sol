// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Actor } from "./Actor.sol";
import { AccessManager } from "./AccessManager.sol";
import { String } from "./String.sol";
import { Errors } from "./Errors.sol";

import { FunctionsClient } from "@chainlink/contracts@1.2.0/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import { FunctionsRequest } from "@chainlink/contracts@1.2.0/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";

/// @custom:security-contact @captainunknown7@gmail.com
contract ActorsManager is FunctionsClient {
    using FunctionsRequest for FunctionsRequest.Request;
    AccessManager public acl;
    bytes32 immutable AUTHORIZED_CONTRACT_ROLE;

    modifier onlyAuthorizedContract() {
        if (!acl.hasRole(AUTHORIZED_CONTRACT_ROLE, msg.sender))
            revert Errors.UnAuthorized("AUTHORIZED_CONTRACT_ROLE");
        _;
    }

    uint8 public constant ACTOR_TYPE_COUNT = 6;
    enum ActorType {
        Farmer,
        Processor,
        Bottler,
        Distributor,
        Retailer,
        Consumer
    }
    mapping(uint8 => Actor) public actors;

    // Chainlink config
    struct RequestInfo {
        uint256 actorId;
        address account;
        bool isNewRegistration;
        ActorType actorType;
        string hash;
    }
    mapping(bytes32 => RequestInfo) private lastValidationRequest;
    string validationSource =
        "const actorType = args[0];"
        "const hash = args[1];"
        "const res = await Functions.makeHttpRequest("
        "{ url: `https://trustifyscm.com/api/validate-actor-meta?type=${actorType}&hash=${hash}`,"
        "timeout: 9000 });"
        "if (res.error || res.status !== 200) throw Error('Request Failed');"
        "const { data } = res;"
        "return Functions.encodeUint256(data.isValid);";
    address donRouter;
    bytes32 donId;
    uint64 donSubscriptionId;
    uint32 donCallbackGasLimit; // Might be redundant if deployed on Hyperledger

    event ActorRegistered(uint8 indexed actorType, uint256 indexed actorId, address indexed account, string hash);
    event ActorUpdated(uint8 indexed actorType, uint256 indexed actorId, string newHash);
    event ValidationFailed(uint8 indexed actorType, uint256 indexed actorId, string hash, bytes error);

    modifier onlyValidActorType(uint8 actorType) {
        if (!(actorType < ACTOR_TYPE_COUNT)) revert Errors.InvalidActorType(actorType, ACTOR_TYPE_COUNT);
        _;
    }

    constructor(address aclAddress, bytes32 _donId, address _donRouter, uint64 _donSubscriptionId)
        FunctionsClient(_donRouter)
    {
        actors[0] = new Actor(aclAddress, "Farmer", "FG");
        actors[1] = new Actor(aclAddress, "Processor", "PR");
        actors[2] = new Actor(aclAddress, "Bottler", "BT");
        actors[3] = new Actor(aclAddress, "Distributor", "DS");
        actors[4] = new Actor(aclAddress, "Retailer", "RT");
        actors[5] = new Actor(aclAddress, "Consumer", "CU");

        donId = _donId;
        donCallbackGasLimit = 600000;
        donSubscriptionId = _donSubscriptionId;

        acl = AccessManager(aclAddress);
        AUTHORIZED_CONTRACT_ROLE = acl.AUTHORIZED_CONTRACT_ROLE();
    }

    function registerActor(uint8 actorType, address account, string calldata hash)
        public
        onlyValidActorType(actorType)
        onlyAuthorizedContract
    {
        lastValidationRequest[validateMetadata(actorType, hash)] = RequestInfo({
            actorId: 0,
            account: account,
            isNewRegistration: true,
            actorType: ActorType(actorType),
            hash: hash
        });
    }

    function updateActor(uint8 actorType, uint256 actorId, string calldata hash)
        public
        onlyValidActorType(actorType)
        onlyAuthorizedContract
    {
        lastValidationRequest[validateMetadata(actorType, hash)] = RequestInfo({
            actorId: actorId,
            account: address(0),
            isNewRegistration: false,
            actorType: ActorType(actorType),
            hash: hash
        });
    }

    function getActorURI(uint8 actorType, uint256 actorId)
        public
        view
        onlyValidActorType(actorType)
        returns(string memory)
    {
        return actors[actorType].tokenURI(actorId);
    }

    function getActorsURIsInBatch(uint8 actorType, uint256 cursor, uint256 pageSize)
        public
        view
        onlyValidActorType(actorType)
        returns (string[] memory)
    {
        if (!(pageSize < 101)) revert Errors.OutOfBounds(pageSize, 100);
        Actor actorContract = actors[actorType];
        uint256 totalSupply = actorContract.totalSupply();
        if (!(cursor < totalSupply)) revert Errors.OutOfBounds(cursor, totalSupply);

        uint256 endIndex = cursor + pageSize;
        if (endIndex > totalSupply) endIndex = totalSupply;

        uint256 actualPageSize = endIndex - cursor;
        string[] memory actorURIs = new string[](actualPageSize);
        for (uint256 i = 0; i < actualPageSize; i++) {
            actorURIs[i] = actorContract.tokenURI(cursor + i);
        }
        return actorURIs;
    }

    // Chainlink Metadata Validation Function
    function validateMetadata(uint8 actorType, string calldata hash) internal returns(bytes32) {
        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(validationSource);
        string[] memory args = new string[](2);
        args[0] = String.toString(actorType);
        args[1] = hash;
        req.setArgs(args);
        return _sendRequest(
            req.encodeCBOR(),
            donSubscriptionId,
            donCallbackGasLimit,
            donId
        );
    }

    function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal override {
        // TODO: Request Id Check
        // if (s_lastRequestId != requestId) revert UnexpectedRequestID(requestId);
        RequestInfo memory info = lastValidationRequest[requestId];
        uint256 actorId = info.actorId;
        uint8 actorType = uint8(info.actorType);
        string memory hash = info.hash;

        if (err.length > 0) {
            emit ValidationFailed(actorType, actorId, hash, err);
            return;
        } else if (!String.strcmp(string(response), "true")) {
            emit ValidationFailed(actorType, actorId, hash, response);
            return;
        }

        if (info.isNewRegistration) {
            address account = info.account;
            actorId = actors[actorType].registerActor(account, hash);
            emit ActorRegistered(actorType, actorId, account, hash);
        } else {
            actors[actorType].updateActor(actorId, hash);
            emit ActorUpdated(actorType, actorId, hash);
        }

        delete lastValidationRequest[requestId];
    }
}