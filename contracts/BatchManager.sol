// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Batch } from "./Batch.sol";
import { String } from "./String.sol";
import { Errors } from "./Errors.sol";
import { BatchTypes } from "./BatchTypes.sol";
import { AccessManager } from "./AccessManager.sol";
import { BatchValidationMiddleware as Validate } from "./BatchValidationMiddleware.sol";

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { FunctionsClient } from "@chainlink/contracts@1.2.0/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import { FunctionsRequest } from "@chainlink/contracts@1.2.0/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";

/**
* @title Batch Manager.
* @dev Maintains the necessary on-chain batch state, keeping in sync with the underlying collection.
* @custom:security-contact @captainunknown7@gmail.com
*/
abstract contract BatchManager is Batch, FunctionsClient {
    using FunctionsRequest for FunctionsRequest.Request;
    using EnumerableSet for EnumerableSet.UintSet;

    uint256 internal _distributionEventId;
    uint256 internal _retailEventId;
    uint256 internal _internalBatchId;

    mapping(uint256 => EnumerableSet.UintSet) internal distributorsIdsForBatchId;
    mapping(uint256 => BatchTypes.DistributionEvent) public distributionEventForId;
    mapping(uint256 => EnumerableSet.UintSet) internal retailersIdsForBatchId;
    mapping(uint256 => BatchTypes.RetailEvent) public retailEventForId;

    // Mapping of InternalID to BatchID (corresponding to token Ids)
    mapping(uint256 => uint256) public internalIdForBatchId; // Make a getter or make a relayer
    mapping(uint256 => BatchTypes.BatchInfo) public batchInfoForInternalId;

    // Chainlink config
    struct RequestInfo {
        uint256 batchId;
        address registrar;
        bool isNewCreation;
        uint256 internalBatchId;
        string hash;
    }
    mapping(bytes32 => RequestInfo) private lastValidationRequest;
    // TODO: Desirably make config updateable
    string validationSource = "const hash = args[0];"
        "const res = await Functions.makeHttpRequest({ url: `https://trustifyscm.com/api/validate-batch-meta?hash=${hash}`,"
        "timeout: 9000 });"
        "if (res.error || res.status !== 200) throw Error('Request Failed');"
        "const { data } = res;"
        "return Functions.encodeUint256(data.isValid);";
    address donRouter;
    bytes32 donId;
    uint64 donSubscriptionId;
    uint32 donCallbackGasLimit;

    event DataCertified(uint256 indexed batchId, string hash, uint256 timestamp);
    event DataCertificationFailed(uint256 indexed batchId, string hash, bytes error);
    event BatchCreated(uint256 indexed batchId, string hash, uint256 timestamp);
    event BatchStatusUpdated(uint256 indexed batchId, BatchTypes.BatchState state, string hash, uint256 timestamp);

    /**
    * @dev Sets the ACL and determines the hash AUTHORIZED_CONTRACT_ROLE.
    * Along with the Chainlink Configuration & finally the address of the `SupplyChain` contract.
    */
    constructor(bytes32 _donId, address _donRouter, uint64 _donSubscriptionId)
        FunctionsClient(_donRouter) Batch("Batch", "B")
    {
        donId = _donId;
        donCallbackGasLimit = 600000;
        donSubscriptionId = _donSubscriptionId;
    }

    /**
    * @dev Creates the batch & updates the on-chain state if the metadata validation succeeds.
    * @param _farmerId - The ID of the farmer who created the batch.
    * @param hash - The hash of the metadata of the batch.
    */
    function createBatch(
        uint256 _farmerId,
        BatchTypes.HarvestEvent memory _harvestEvent,
        string calldata hash
    )
        internal
    {
        Validate.validateHarvestEvent(_harvestEvent);

        BatchTypes.BatchInfo memory _batch;
        _batch.farmerId = _farmerId;
        _batch.harvestEvent = _harvestEvent;
        uint256 currentInternalBatchId = _internalBatchId++;
        batchInfoForInternalId[currentInternalBatchId] = _batch;
        lastValidationRequest[validateMetadata(hash)] = RequestInfo({
            batchId: 0,
            registrar: msg.sender,
            isNewCreation: true,
            internalBatchId: currentInternalBatchId,
            hash: hash
        });
    }

    /**
    * @dev Updates the metadata of the batch if the metadata validation succeeds.
    * @param _batch - The new updated batch info itself.
    * @param hash - The hash of the new dynamically updated metadata.
    */
    function updateBatch(
        uint256 _batchId,
        BatchTypes.BatchInfo memory _batch,
        string calldata hash
    )
        internal
    {
        if (!(idExists(_batchId))) revert Errors.InvalidTokenId();
        Validate.validateBatchEvents(_batch);

        uint256 _newRequestInternalId = _internalBatchId++;
        batchInfoForInternalId[_newRequestInternalId] = _batch;
        lastValidationRequest[validateMetadata(hash)] = RequestInfo({
            batchId: _batchId,
            registrar: msg.sender,
            isNewCreation: false,
            internalBatchId: _newRequestInternalId,
            hash: hash
        });
    }

    /**
    * @dev To retrieve the batch URI.
    * @param batchId - The ID of the batch.
    * @return The hash of the batch.
    */
    function getBatchURI(uint256 batchId)
        public
        view
        returns(string memory)
    {
        return tokenURI(batchId);
    }

    /**
    * @dev To retrieve the batch URIs in a chunk, chunk size cannot exceed 100.
    * @param cursor - The starting index or the first BatchID.
    * @param pageSize - Total request size.
    * @return The hashes of the batches.
    */
    function getBatchURIsInBatch(uint256 cursor, uint256 pageSize)
        public
        view
        returns (string[] memory)
    {
        if (!(pageSize < 101)) revert Errors.OutOfBounds(pageSize, 100);
        uint256 totalSupply = totalSupply();
        if (!(cursor < totalSupply)) revert Errors.OutOfBounds(cursor, totalSupply);

        uint256 endIndex = cursor + pageSize;
        if (endIndex > totalSupply) endIndex = totalSupply;

        uint256 actualPageSize = endIndex - cursor;
        string[] memory batchURIs = new string[](actualPageSize);
        for (uint256 i = 0; i < actualPageSize; i++) {
            batchURIs[i] = tokenURI(cursor + i);
        }
        return batchURIs;
    }

    /**
    * @dev To get the actors involved in a particular batch, a read-only external function.
    */
    function getUpdatedBatchActors(uint256 _batchId)
        public
        view
        returns (
            BatchTypes.BatchState,
            uint256,
            uint256,
            uint256,
            uint256[] memory,
            uint256[] memory
        )
    {
        BatchTypes.BatchInfo storage batch = batchInfoForInternalId[internalIdForBatchId[_batchId]];
        return (
            batch.state,
            batch.farmerId,
            batch.processorId,
            batch.packagerId,
            distributorsIdsForBatchId[_batchId].values(),
            retailersIdsForBatchId[_batchId].values()
        );
    }

    /**
    * @dev An internal function to be called to send a validation request.
    * @param hash - The hash of the metadata to be validated.
    * @return The DON Function request ID.
    */
    function validateMetadata(string calldata hash) internal returns(bytes32) {
        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(validationSource);
        string[] memory args = new string[](1);
        args[0] = hash;
        req.setArgs(args);
        return _sendRequest(
            req.encodeCBOR(),
            donSubscriptionId,
            donCallbackGasLimit,
            donId
        );
    }

    /**
    * @dev An internal function to be called by the donRouter.
    * @param requestId - The validation request ID.
    * @param response - The response from the DON Function.
    * @param err - The error from the DON Function (if any).
    */
    function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal override {
        RequestInfo memory info = lastValidationRequest[requestId];
        uint256 _batchId = info.batchId;
        string memory hash = info.hash;

        if (bytes(info.hash).length == 0)
            revert Errors.UnexpectedRequestID();
        if (err.length > 0) {
            emit DataCertificationFailed(_batchId, hash, err);
            return;
        } else if (!String.strcmp(string(response), "true")) {
            emit DataCertificationFailed(_batchId, hash, response);
            return;
        }

        BatchTypes.BatchInfo storage _batch = batchInfoForInternalId[info.internalBatchId];
        if (info.isNewCreation) {
            _batch.isCertified = true;
            // Assumption: The Contract creates the batches on behalf of the farmers
            _batchId = _createBatch(info.registrar, hash);
            if (!performBatchCreation(_batchId)) revert Errors.FulfillmentFailed();
            emit DataCertified(_batchId, hash, block.timestamp);
            emit BatchCreated(_batchId, hash, block.timestamp);
        } else {
            _updateBatch(_batchId, hash);
            if (!performBatchUpdate(_batchId)) revert Errors.FulfillmentFailed();
            emit BatchStatusUpdated(_batchId, _batch.state, hash, block.timestamp);
        }

        // Essentially registers the newly created data for the batchId
        internalIdForBatchId[_batchId] = info.internalBatchId;
        delete lastValidationRequest[requestId];
    }

    function performBatchCreation(uint256 _batchId) internal virtual returns(bool) {
        // Is called on a successful creation
    }

    function performBatchUpdate(uint256 _batchId) internal virtual returns(bool) {
        // Is called on a successful state update
    }
}