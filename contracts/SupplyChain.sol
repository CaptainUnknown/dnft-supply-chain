// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { AccessManager } from "./AccessManager.sol";
import { BatchManager } from "./BatchManager.sol";
import { ActorsManager } from "./ActorsManager.sol";
import { Actor } from "./Actor.sol";
import { Errors } from "./Errors.sol";

/**
* @title The Core DNFT based SupplyChain.
* @custom:security-contact @captainunknown7@gmail.com
*/
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
        address batchManagerAddress = address(batchManager);
        if (batchManagerAddress != msg.sender)
            revert Errors.UnexpectedAgent(msg.sender, batchManagerAddress);
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

    /**
    * @dev Sets the ACL and determines the hash AUTHORIZED_CONTRACT_ROLE.
    * And handles the deployment of the `BatchManager` contract.
    */
    constructor(address aclAddress, address _actorsManager, bytes32 _donId, address _donRouter, uint64 _donSubscriptionId) {
        batchManager = new BatchManager(aclAddress, address(this), _donId, _donRouter, _donSubscriptionId);

        acl = AccessManager(aclAddress);
        COMPANY_USER_ROLE = acl.COMPANY_USER_ROLE();
        actorsManager = ActorsManager(_actorsManager);
    }

    /**
    * @dev A callback function to be called by the `BatchManager` upon batch creation metadata validation.
    * @param Batch ID of the newly created batch.
    * @return The success status if the batch is logged in the ledger, upon a failure it reverts with `FulfillmentFailed`.
    */
    function performBatchCreation(uint256 _batchId)
        external
        onlyBatchManager
        returns (bool)
    {
        return farmers[batchManager.getBatchFarmerId(_batchId)].batchIds.add(_batchId);
    }

    /**
    * @dev A callback function to be called by the `BatchManager` upon the dynamic batch update metadata validation.
    * Note that the on-chain info is managed by the `BatchManager` in sync with this function.
    * @param Batch ID of the updated batch.
    * @return The success status if the batch is logged to the new actor, upon a failure it reverts with `FulfillmentFailed`.
    */
    function performBatchUpdate(uint256 _batchId)
        external
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

    /**
    * @dev To add a newly harvested batch. Creates a new instance of the batch & validates the metadata.
    * @param Farmer ID of the Harvester of the batch.
    * @param The hash of the harvested batch.
    */
    function addHarvestedBatch(uint256 farmerId, string calldata hash) public onlyCompanyUser {
        batchManager.createBatch(farmerId, hash, this.performBatchCreation.selector);
    }

    /**
    * @dev To update the batch state, once the batch moves onto any of the next phases.
    * Performs necessary validation of the metadata & updates the DNFT.
    * @param The updated Batch info itself.
    * @param The updated hash of the batch.
    */
    function updateBatchState(BatchManager.BatchInfo calldata _batch, string calldata hash)
        public
        onlyCompanyUser
    {
        batchManager.updateBatch(_batch, hash, this.performBatchUpdate.selector);
    }

    /**
    * @dev To retrieve all the batches of a particular farmer.
    * @param The farmer ID to retrieve the batches for.
    * @return The IDs of the batches the farmer harvested.
    */
    function getBatchesHarvested(uint256 farmerId) public view returns (uint256[] memory) {
        return farmers[farmerId].batchIds.values();
    }

    /**
    * @dev To retrieve all the batches of a particular processor.
    * @param The processor ID to retrieve the batches for.
    * @return The IDs of the batches the processor ever processed.
    */
    function getBatchesProcessed(uint256 processorId) public view returns (uint256[] memory) {
        return processors[processorId].batchIds.values();
    }

    /**
    * @dev To retrieve all the batches of a particular packager.
    * @param The packager ID to retrieve the batches for.
    * @return The IDs of the batches the packager ever packaged.
    */
    function getBatchesPackaged(uint256 packagerId) public view returns (uint256[] memory) {
        return packagers[packagerId].batchIds.values();
    }

    /**
    * @dev To retrieve all the batches of a particular distributor.
    * @param The distributor ID to retrieve the batches for.
    * @return The IDs of the batches the distributor was involved in.
    */
    function getBatchesDistributed(uint256 distributorId) public view returns (uint256[] memory) {
        return distributors[distributorId].batchIds.values();
    }

    /**
    * @dev To retrieve all the batches of a particular retailer.
    * @param The retailer ID to retrieve the batches for.
    * @return The IDs of the batches the retailer was involved in.
    */
    function getBatchesRetailed(uint256 retailerId) public view returns (uint256[] memory) {
        return retailers[retailerId].batchIds.values();
    }

    /**
    * @dev To interface with ERC721 & receive the batch DNFTs.
    */
    function onERC721Received(address, address, uint256, bytes calldata) external view returns(bytes4) {
        if(msg.sender == address(batchManager.batches())) return this.onERC721Received.selector;
        return bytes4(0);
    }
}