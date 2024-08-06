// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { AccessManager } from "./AccessManager.sol";
import { BatchManager } from "./BatchManager.sol";
import { ActorsManager } from "./ActorsManager.sol";
import { Actor } from "./Actor.sol";
import { Errors } from "./Errors.sol";

/// @custom:security-contact @captainunknown7@gmail.com
contract SupplyChain {
    using EnumerableSet for EnumerableSet.UintSet;
    AccessManager public acl;
    bytes32 immutable COMPANY_USER_ROLE;
    BatchManager public batchManager;
    ActorsManager public actorsManager;

    modifier onlyCompanyUser() {
        if (!acl.hasRole(COMPANY_USER_ROLE, msg.sender))
            revert Errors.UnAuthorized("COMPANY_USER_ROLE");
        _;
    }

    // only BatchManager can call a callback
    modifier onlyBatchManager() {
        // Stub
        _;
    }

    struct BatchIdsForActors {
        EnumerableSet.UintSet batchIds;
    }

    mapping(uint256 => BatchIdsForActors) private farmers;
    mapping(uint256 => BatchIdsForActors) private processors;
    mapping(uint256 => BatchIdsForActors) private packagers;
    mapping(uint256 => BatchIdsForActors) private distributors;
    mapping(uint256 => BatchIdsForActors) private retailers;

    constructor(address aclAddress, address _actorsManager, address _batchManager) {
        batchManager = BatchManager(_batchManager);

        acl = AccessManager(aclAddress);
        COMPANY_USER_ROLE = acl.COMPANY_USER_ROLE();
        actorsManager = ActorsManager(_actorsManager);
    }

    function performBatchCreation(uint256 _batchId)
    public
    onlyBatchManager
    returns (bool)
    {
        return farmers[batchManager.getBatchFarmerId(_batchId)].batchIds.add(_batchId);
    }

    function performBatchUpdate(uint256 _batchId)
    public
    onlyBatchManager
    returns (bool)
    {
        (
            BatchManager.BatchState state,
            uint256 processorId,
            uint256 packagerId,
            uint128 distributorsCount,
            uint128 retailersCount,
            uint256[] memory distributorIds,
            uint256[] memory retailerIds
        ) = batchManager.getUpdatedBatchActors(_batchId);

        if (state == BatchManager.BatchState.Processed) {
            return processors[processorId].batchIds.add(_batchId);
        } else if (state == BatchManager.BatchState.Packaged) {
            return packagers[packagerId].batchIds.add(_batchId);
        } else if (state == BatchManager.BatchState.AtDistributors) {
            uint256 distributorAdded = distributorIds[distributorsCount - 1];
            return distributors[distributorAdded].batchIds.add(_batchId);
        } else if (state == BatchManager.BatchState.AtRetailers) {
            uint256 retailerAdded = retailerIds[retailersCount - 1];
            return retailers[retailerAdded].batchIds.add(_batchId);
        }
        return true; // Batch Update not necessary for intermediary stages i.e storage/transit etc
    }

    function addHarvestedBatch(uint256 farmerId, string calldata hash) public onlyCompanyUser {
        batchManager.createBatch(farmerId, hash, this.performBatchCreation.selector);
    }

    function updateBatchState(BatchManager.BatchInfo calldata _batch, string calldata hash)
    public
    onlyCompanyUser
    {
        batchManager.updateBatch(_batch, hash, this.performBatchUpdate.selector);
    }

    function getBatchesHarvested(uint256 farmerId) public view returns (uint256[] memory) {
        return farmers[farmerId].batchIds.values();
    }

    function getBatchesProcessed(uint256 processorId) public view returns (uint256[] memory) {
        return processors[processorId].batchIds.values();
    }

    function getBatchesPackaged(uint256 packagerId) public view returns (uint256[] memory) {
        return packagers[packagerId].batchIds.values();
    }

    function getBatchesDistributed(uint256 distributorId) public view returns (uint256[] memory) {
        return distributors[distributorId].batchIds.values();
    }

    function getBatchesRetailed(uint256 retailerId) public view returns (uint256[] memory) {
        return retailers[retailerId].batchIds.values();
    }

    function onERC721Received(address, address, uint256, bytes calldata) external view returns(bytes4) {
        if(msg.sender == address(batchManager.batches())) return this.onERC721Received.selector;
        return bytes4(0);
    }
}