// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Batch } from "./Batch.sol";
import { AccessManager } from "./AccessManager.sol";
import { String } from "../String.sol";
import { Errors } from "./Errors.sol";

/// @custom:security-contact @captainunknown7@gmail.com
contract BatchManager {
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

    uint256 public requestIdCounter;

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
    mapping(uint256 => RequestInfo) private lastValidationRequest;
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

    constructor(address aclAddress, address _supplyChainContract, bytes32 _donId, address /*_donRouter*/, uint64 _donSubscriptionId) {
        batches = new Batch(aclAddress, "Batch", "B");
        donId = _donId;
        donCallbackGasLimit = 600000;
        donSubscriptionId = _donSubscriptionId;

        acl = AccessManager(aclAddress);
        AUTHORIZED_CONTRACT_ROLE = acl.AUTHORIZED_CONTRACT_ROLE();
        ADMIN_ROLE = acl.ADMIN_ROLE();

        supplyChainContract = _supplyChainContract;
    }

    function createBatch(uint256 _farmerId, string calldata hash, bytes4 _callbackFunction)
    public
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

    function updateBatch(BatchInfo calldata _batch, string calldata hash, bytes4 _callbackFunction)
    public
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

    function getBatchURI(uint256 batchId)
    public
    view
    returns(string memory)
    {
        return batches.tokenURI(batchId);
    }

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

    // Stub Chainlink Metadata Validation Function
    function validateMetadata(string calldata /*hash*/) internal view returns(uint256) {
        return requestIdCounter;
    }

    function fulfillRequest(uint256 requestId, bytes memory response, bytes memory err) public onlyAuthorizedContract {
        RequestInfo memory info = lastValidationRequest[requestId];
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
    }

    function setSupplyChainAddress(address _supplyChainAddress) public onlyAdminRole {
        supplyChainContract = _supplyChainAddress;
    }

    function setBatch(uint256 _batchId, BatchInfo calldata batch) external onlyAuthorizedContract {
        batchInfoForId[_batchId] = batch;
    }

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

    function getBatchFarmerId(uint256 _batchId)
    external
    view
    returns (uint256)
    {
        return batchInfoForId[_batchId].farmerId;
    }
}