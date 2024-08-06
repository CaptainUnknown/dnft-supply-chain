// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Batch } from "./Batch.sol";
import { AccessManager } from "./AccessManager.sol";
import { String } from "./String.sol";
import { Errors } from "./Errors.sol";

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { FunctionsClient } from "@chainlink/contracts@1.2.0/src/v0.8/functions/v1_0_0/FunctionsClient.sol";
import { FunctionsRequest } from "@chainlink/contracts@1.2.0/src/v0.8/functions/v1_0_0/libraries/FunctionsRequest.sol";

/**
* @title Batch Aggregator.
* @dev Maintains the necessary on-chain batch state, keeping in sync with the underlying collection.
* @custom:security-contact @captainunknown7@gmail.com
*/
contract BatchManager is FunctionsClient {
    using FunctionsRequest for FunctionsRequest.Request;
    using EnumerableSet for EnumerableSet.UintSet;

    AccessManager public acl;
    bytes32 immutable AUTHORIZED_CONTRACT_ROLE;
    bytes32 immutable ADMIN_ROLE;

    modifier onlyAuthorizedContract() {
        if (!acl.hasRole(AUTHORIZED_CONTRACT_ROLE, msg.sender))
            revert Errors.UnAuthorized("AUTHORIZED_CONTRACT_ROLE");
        _;
    }

    modifier onlyAdminRole() {
        if (!acl.hasRole(ADMIN_ROLE, msg.sender))
            revert Errors.UnAuthorized("ADMIN_ROLE");
        _;
    }

    uint8 public constant BATCH_STATE_COUNT = 9;
    enum BatchState {
        Harvested,
        Processed,
        Packaged,
        AtDistributors,
        AtRetailers,
        ToCustomers,
        InStorage,
        InTransit,
        InProcessing // represents all intermediate stages like packaging, processing, quality checks etc
    }

    struct BatchInfo {
        uint256 batchId;
        BatchState state;
        bool isCertified;
        bool qualityControlApproved;
        uint256 farmerId; // Actor Id for the given actors involved in the batch
        uint256 processorId;
        uint256 packagerId;
        uint128 distributorsCount; // Total given actors involved in the batch distribution/retail
        uint128 retailersCount;
        uint256[] distributorIds;
        uint256[] retailerIds;
    }
    mapping(uint256 => BatchInfo) public batchInfoForId;
    Batch public batches; // Collection Responsible for Batches

    // Chainlink config
    struct RequestInfo {
        uint256 batchId;
        address registrar;
        bool isNewCreation;
        BatchInfo batch;
        string hash;
        bytes4 callbackFunction;
    }
    mapping(bytes32 => RequestInfo) private lastValidationRequest;
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

    address public supplyChainContract;

    event DataCertified(uint256 indexed batchId, string hash, uint256 timestamp);
    event DataCertificationFailed(uint256 indexed batchId, string hash, bytes error);
    event BatchCreated(uint256 indexed batchId, string hash, uint256 timestamp);
    event BatchStatusUpdated(uint256 indexed batchId, BatchState state, string hash, uint256 timestamp);

    /**
    * @dev Sets the ACL and determines the hash AUTHORIZED_CONTRACT_ROLE.
    * Along with the Chainlink Configuration & finally the address of the `SupplyChain` contract.
    */
    constructor(address aclAddress, address _supplyChainContract, bytes32 _donId, address _donRouter, uint64 _donSubscriptionId)
        FunctionsClient(_donRouter)
    {
        batches = new Batch(aclAddress, "Batch", "B");
        donId = _donId;
        donCallbackGasLimit = 600000;
        donSubscriptionId = _donSubscriptionId;

        acl = AccessManager(aclAddress);
        AUTHORIZED_CONTRACT_ROLE = acl.AUTHORIZED_CONTRACT_ROLE();
        ADMIN_ROLE = acl.ADMIN_ROLE();

        supplyChainContract = _supplyChainContract;
    }

    /**
    * @dev Creates the batch & updates the on-chain state if the metadata validation succeeds.
    * @param The ID of the farmer who created the batch.
    * @param The hash of the metadata of the batch.
    * @param Callback selector, which calls a post validation function in SupplyChain to perform creation.
    */
    function createBatch(uint256 _farmerId, string calldata hash, bytes4 _callbackFunction)
        external
        onlyAuthorizedContract
    {
        uint256[] memory ids;
        BatchInfo memory _batch = BatchInfo({
            batchId: 0,
            state: BatchState(0),
            isCertified: false,
            qualityControlApproved: false,
            farmerId: _farmerId,
            processorId: 0,
            packagerId: 0,
            distributorsCount: 0,
            retailersCount: 0,
            distributorIds: ids,
            retailerIds: ids
        });

        lastValidationRequest[validateMetadata(hash)] = RequestInfo({
            batchId: 0,
            registrar: msg.sender,
            isNewCreation: true,
            batch: _batch,
            hash: hash,
            callbackFunction: _callbackFunction
        });
    }

    /**
    * @dev Updates the metadata of the batch if the metadata validation succeeds.
    * @param The new updated batch info itself.
    * @param The hash of the new dynamically updated metadata.
    * @param Callback selector, which calls a post validation function in SupplyChain to perform update.
    */
    function updateBatch(BatchInfo calldata _batch, string calldata hash, bytes4 _callbackFunction)
        external
        onlyAuthorizedContract
    {
        if (!(batches.idExists(_batch.batchId))) revert Errors.InvalidTokenId();
        lastValidationRequest[validateMetadata(hash)] = RequestInfo({
            batchId: _batch.batchId,
            registrar: msg.sender,
            isNewCreation: false,
            batch: _batch,
            hash: hash,
            callbackFunction: _callbackFunction
        });
    }

    /**
    * @dev To retrieve the batch URI.
    * @param The ID of the batch.
    * @return The hash of the batch.
    */
    function getBatchURI(uint256 batchId)
        public
        view
        returns(string memory)
    {
        return batches.tokenURI(batchId);
    }

    /**
    * @dev To retrieve the batch URIs in a chunk, chunk size cannot exceed 100.
    * @param The starting index (ID) of the batches.
    * @param Total request size.
    * @return The hashes of the batches.
    */
    function getBatchURIsInBatch(uint256 cursor, uint256 pageSize)
        public
        view
        returns (string[] memory)
    {
        Batch batch = batches;
        if (!(pageSize < 101)) revert Errors.OutOfBounds(pageSize, 100);
        uint256 totalSupply = batch.totalSupply();
        if (!(cursor < totalSupply)) revert Errors.OutOfBounds(cursor, totalSupply);

        uint256 endIndex = cursor + pageSize;
        if (endIndex > totalSupply) endIndex = totalSupply;

        uint256 actualPageSize = endIndex - cursor;
        string[] memory batchURIs = new string[](actualPageSize);
        for (uint256 i = 0; i < actualPageSize; i++) {
            batchURIs[i] = batch.tokenURI(cursor + i);
        }
        return batchURIs;
    }

    /**
    * @dev An internal function to be called to send a validation request.
    * @param The hash of the metadata to be validated.
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
    * @param The validation request ID.
    * @param The response from the DON Function.
    * @return The error from the DON Function (if any).
    */
    function fulfillRequest(bytes32 requestId, bytes memory response, bytes memory err) internal override {
        RequestInfo memory info = lastValidationRequest[requestId];
        if (bytes(info.hash).length == 0) revert Errors.UnexpectedRequestID(requestId);
        
        uint256 _batchId = info.batchId;
        string memory hash = info.hash;

        if (err.length > 0) {
            emit DataCertificationFailed(_batchId, hash, err);
            return;
        } else if (!String.strcmp(string(response), "true")) {
            emit DataCertificationFailed(_batchId, hash, response);
            return;
        }

        if (info.isNewCreation) {
            info.batch.isCertified = true;
            _batchId = batches.createBatch(info.registrar, hash); // Assumption: The Contract creates the batches on behalf of the farmers
            emit DataCertified(_batchId, hash, block.timestamp);
            emit BatchCreated(_batchId, hash, block.timestamp);
        } else {
            batches.updateBatch(_batchId, hash);
            emit BatchStatusUpdated(_batchId, info.batch.state, hash, block.timestamp);
        }

        batchInfoForId[_batchId] = info.batch;
        delete lastValidationRequest[requestId];

        (bool success, ) = supplyChainContract.call(abi.encodeWithSelector(info.callbackFunction, _batchId));
        if(!success) revert Errors.FulfillmentFailed();
    }

    /**
    * @dev A guarded function to change the `SupplyChain` contract address.
    * @param The new `SupplyChain` contract address.
    */
    function setSupplyChainAddress(address _supplyChainAddress) public onlyAdminRole {
        supplyChainContract = _supplyChainAddress;
    }

    /**
    * @dev A guarded function to update the on-chain batch state, to be called by the `SupplyChain` contract.
    * @param The batch ID to set the batch for.
    * @param The new batch info itself.
    */
    function setBatch(uint256 _batchId, BatchInfo calldata batch) external onlyAuthorizedContract {
        batchInfoForId[_batchId] = batch;
    }

    /**
    * @dev To get the actors involved in a particular batch, a read-only external function.
    */
    function getUpdatedBatchActors(uint256 _batchId)
        external
        view
        returns (
            BatchState,
            uint256,
            uint256,
            uint128,
            uint128,
            uint256[] memory,
            uint256[] memory
        )
    {
        BatchInfo storage batch = batchInfoForId[_batchId];
        return (
            batch.state,
            batch.processorId,
            batch.packagerId,
            batch.distributorsCount,
            batch.retailersCount,
            batch.distributorIds,
            batch.retailerIds
        );
    }

    /**
    * @dev To get the getBatchFarmerId of a particular batch, a read-only external function.
    */
    function getBatchFarmerId(uint256 _batchId)
        external
        view
        returns (uint256)
    {
        return batchInfoForId[_batchId].farmerId;
    }
}