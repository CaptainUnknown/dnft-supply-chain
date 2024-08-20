// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Errors } from "./Errors.sol";
import { Actor } from "./Actor.sol";
import { BatchTypes } from "./BatchTypes.sol";
import { BatchManager } from "./BatchManager.sol";
import { AccessManager } from "./AccessManager.sol";
import { BatchValidationMiddleware as Validate } from "./BatchValidationMiddleware.sol";

import { ActorsManager } from "./ActorsManager.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
* @title The Core DNFT based SupplyChain.
* @custom:security-contact @captainunknown7@gmail.com
*/
contract SupplyChain is BatchManager {
    using EnumerableSet for EnumerableSet.UintSet;
    AccessManager public acl;
    bytes32 immutable COMPANY_USER_ROLE;
    ActorsManager public actorsManager;

    modifier onlyCompanyUser() {
        if (!acl.hasRole(COMPANY_USER_ROLE, msg.sender))
            revert Errors.UnAuthorized("COMPANY_USER_ROLE");
        _;
    }

    struct BatchIdsForActors {
        EnumerableSet.UintSet batchIds;
    }

    struct IdsForDistributors {
        EnumerableSet.UintSet batchIds;
        EnumerableSet.UintSet distributionEventIds;
    }

    struct IdsForRetailers {
        EnumerableSet.UintSet batchIds;
        EnumerableSet.UintSet retailEventIds;
    }

    mapping(uint256 => BatchIdsForActors) private farmers;
    mapping(uint256 => BatchIdsForActors) private processors;
    mapping(uint256 => BatchIdsForActors) private packagers;
    mapping(uint256 => IdsForDistributors) private distributors;
    mapping(uint256 => IdsForRetailers) private retailers;

    // TODO: Update mocks

    /**
    * @dev Sets the ACL and determines the hash AUTHORIZED_CONTRACT_ROLE.
    * And handles the deployment of the `BatchManager` contract.
    */
    constructor(address aclAddress, address _actorsManager, bytes32 _donId, address _donRouter, uint64 _donSubscriptionId)
    BatchManager(_donId, _donRouter, _donSubscriptionId)
    {
        acl = AccessManager(aclAddress);
        COMPANY_USER_ROLE = acl.COMPANY_USER_ROLE();
        actorsManager = ActorsManager(_actorsManager);
    }

    /**
    * @dev To add a newly harvested batch. Creates a new instance of the batch & validates the metadata.
    * @param farmerId - Farmer ID of the Harvester of the batch.
    * @param hash - The hash of the harvested batch.
    */
    function addHarvestedBatch(
        uint256 farmerId,
        uint32 latitude,
        uint32 longitude,
        string calldata harvestMethod,
        string calldata hash
    ) public onlyCompanyUser {
        BatchTypes.HarvestEvent memory _harvestEvent = BatchTypes.HarvestEvent({
            date: uint64(block.timestamp),
            latitude: latitude,
            longitude: longitude,
            method: harvestMethod
        });
        createBatch(farmerId, _harvestEvent, hash);
    }

    /**
    * @dev To push the harvested batch to the processed state. Requires onchain state & metadata validation.
    * @param batchId - BatchID of the batch to be processed.
    * @param processorId - The actor ID of the processor involved.
    * @param latitude - The latitude of the processing facility.
    * @param longitude - The longitude of the processing facility.
    * @param quantity - The quantity of the batch processed.
    * @param hash - Updated hash of the processed batch.
    */
    function pushBatchToProcessed(
        uint256 batchId,
        uint256 processorId,
        uint32 latitude,
        uint32 longitude,
        uint256 quantity,
        string calldata hash
    ) public onlyCompanyUser {
        BatchTypes.BatchInfo storage batchInfo = batchInfoForInternalId[internalIdForBatchId[batchId]];
        Validate.validateChronologicalOrder(batchInfo.state, BatchTypes.BatchState.Processed);
        batchInfo.state = BatchTypes.BatchState.Processed;
        batchInfo.processorId = processorId;
        batchInfo.processingEvent = BatchTypes.ProcessingEvent({
            date: uint64(block.timestamp),
            latitude: latitude,
            longitude: longitude,
            quantity: quantity,
            qualityTest: false
        });
        updateBatch(batchId, batchInfo, hash);
    }

    /**
    * @dev To push the processed batch to the packaged state. Requires onchain state & metadata validation.
    * @param batchId - BatchID of the batch to be packaged.
    * @param packagerId - The actor ID of the packager involved.
    * @param latitude - The latitude of the packaging facility.
    * @param longitude - The longitude of the packaging facility.
    * @param quantity - The quantity of the batch packaged.
    * @param hash - Updated hash of the packaged batch.
    */
    function pushBatchToPackaged(
        uint256 batchId,
        uint256 packagerId,
        uint32 latitude,
        uint32 longitude,
        uint256 quantity,
        string calldata hash
    ) public onlyCompanyUser {
        BatchTypes.BatchInfo storage batchInfo = batchInfoForInternalId[internalIdForBatchId[batchId]];
        Validate.validateChronologicalOrder(batchInfo.state, BatchTypes.BatchState.Packaged);
        batchInfo.state = BatchTypes.BatchState.Packaged;
        batchInfo.packagerId = packagerId;
        batchInfo.packagingEvent = BatchTypes.PackagingEvent({
            date: uint64(block.timestamp),
            latitude: latitude,
            longitude: longitude,
            quantity: quantity
        });
        updateBatch(batchId, batchInfo, hash);
    }

    /**
    * @dev To assign a packaged batch to a distributor. Requires onchain state & metadata validation.
    * @param batchId - BatchID of the batch to be distributed.
    * @param distributorId - The actor ID of the distributor involved.
    * @param latitude - The latitude of the distribution facility.
    * @param longitude - The longitude of the distribution facility.
    * @param storageCondition - Storage Condition of the batch during distribution.
    * Expected: "cool", "refrigerated", "frozen", "ambient", "warm", "dry",
    * "humid", "controlled-humidity", "dark", "light", "ventilated", "sealed".
    * @param handling - The handling status of the batch during distribution.
    * Expected: "careful", "gentle", "do-not-stack", "keep-upright" "perishable",
    * "flammable", "temperature-sensitive", "light-sensitive", "moisture-sensitive".
    * @param hash - Updated hash of the distributed batch.
    */
    function assignBatchToDistributor(
        uint256 batchId,
        uint256 distributorId,
        uint32 latitude,
        uint32 longitude,
        string calldata storageCondition,
        string calldata handling,
        string calldata hash
    ) public onlyCompanyUser {
        BatchTypes.BatchInfo storage batchInfo = batchInfoForInternalId[internalIdForBatchId[batchId]];
        Validate.validateChronologicalOrder(batchInfo.state, BatchTypes.BatchState.AtDistributors);
        batchInfo.state = BatchTypes.BatchState.AtDistributors;
        distributorsIdsForBatchId[batchId].add(distributorId);
        distributionEventForId[_distributionEventId++] = BatchTypes.DistributionEvent({
            date: uint64(block.timestamp),
            latitude: latitude,
            longitude: longitude,
            storageCondition: storageCondition,
            handling: handling
        });
        updateBatch(batchId, batchInfo, hash);
    }

    /**
    * @dev To assign a distributed batch to a retailer. Requires onchain state & metadata validation.
    * @param batchId - BatchID of the batch to be retailed.
    * @param retailerId - The actor ID of the retailer involved.
    * @param latitude - The latitude of the retailer.
    * @param longitude - The longitude of the retailer.
    * @param quantity - The quantity of the batch retailed.
    * @param hash - Updated hash of the retailed batch.
    */
    function assignBatchToRetailer(
        uint256 batchId,
        uint256 retailerId,
        uint32 latitude,
        uint32 longitude,
        uint256 quantity,
        string calldata hash
    ) public onlyCompanyUser {
        BatchTypes.BatchInfo storage batchInfo = batchInfoForInternalId[internalIdForBatchId[batchId]];
        Validate.validateChronologicalOrder(batchInfo.state, BatchTypes.BatchState.AtRetailers);
        batchInfo.state = BatchTypes.BatchState.AtRetailers;
        retailersIdsForBatchId[batchId].add(retailerId);
        retailEventForId[_retailEventId++] = BatchTypes.RetailEvent({
            date: uint64(block.timestamp),
            latitude: latitude,
            longitude: longitude,
            quantity: quantity
        });
        updateBatch(batchId, batchInfo, hash);
    }

    /**
    * @dev To retrieve all the batches of a particular farmer.
    * @param farmerId - The farmer ID to retrieve the batches for.
    * @return The IDs of the batches the farmer harvested.
    */
    function getBatchesHarvested(uint256 farmerId) public view returns (uint256[] memory) {
        return farmers[farmerId].batchIds.values();
    }

    /**
    * @dev To retrieve all the batches of a particular processor.
    * @param processorId - The processor ID to retrieve the batches for.
    * @return The IDs of the batches the processor ever processed.
    */
    function getBatchesProcessed(uint256 processorId) public view returns (uint256[] memory) {
        return processors[processorId].batchIds.values();
    }

    /**
    * @dev To retrieve all the batches of a particular packager.
    * @param packagerId - The packager ID to retrieve the batches for.
    * @return The IDs of the batches the packager ever packaged.
    */
    function getBatchesPackaged(uint256 packagerId) public view returns (uint256[] memory) {
        return packagers[packagerId].batchIds.values();
    }

    /**
    * @dev To retrieve all the batches of a particular distributor.
    * @param distributorId - The distributor ID to retrieve the batches for.
    * @return The IDs of the batches the distributor was involved in.
    */
    function getBatchesDistributed(uint256 distributorId) public view returns (uint256[] memory) {
        return distributors[distributorId].batchIds.values();
    }

    /**
    * @dev To retrieve all the batches of a particular retailer.
    * @param retailerId - The retailer ID to retrieve the batches for.
    * @return The IDs of the batches the retailer was involved in.
    */
    function getBatchesRetailed(uint256 retailerId) public view returns (uint256[] memory) {
        return retailers[retailerId].batchIds.values();
    }

    /**
    * @dev To retrieve all distributionEventIds for any particular distributor.
    * @param distributorId - The distributor ID to retrieve the distributionEventIds for.
    * @return The Distribution Event IDs the distributor was involved in.
    */
    function getDistributionEventIdsForDistributor(uint256 distributorId)
    public view returns (uint256[] memory)
    {
        return distributors[distributorId].distributionEventIds.values();
    }

    /**
    * @dev To retrieve all retailEventIds for any particular retailer.
    * @param retailerId - The retailer ID to retrieve the retailEventIds for.
    * @return The Retail Event IDs the retailer was involved in.
    */
    function getRetailEventIdsForRetailer(uint256 retailerId)
    public view returns (uint256[] memory)
    {
        return retailers[retailerId].retailEventIds.values();
    }

    /**
    * @dev To retrieve all the distributors involved in a batch.
    * @param batchId - The batch ID to query for.
    * @return The Distributors IDs that were involved in the batch.
    */
    function getAllDistributorsForBatch(uint256 batchId)
    public view returns (uint256[] memory)
    {
        return distributorsIdsForBatchId[batchId].values();
    }

    /**
    * @dev To retrieve all the retailers involved in a batch.
    * @param batchId - The batch ID to query for.
    * @return The Retailers IDs that were involved in the batch.
    */
    function getAllRetailersForBatch(uint256 batchId)
    public view returns (uint256[] memory)
    {
        return retailersIdsForBatchId[batchId].values();
    }

    // Overrides:
    /**
    * @dev Post fulfillment function to register the batch for the corresponding farmerId on chain.
    */
    function performBatchCreation(uint256 _batchId) internal override returns(bool) {
        return farmers[batchInfoForInternalId[internalIdForBatchId[_batchId]].farmerId].batchIds.add(_batchId);
    }

    /**
    * @dev Post fulfillment function to assign the new actor involved for the said batch on chain.
    */
    function performBatchUpdate(uint256 _batchId) internal override returns(bool) {
        (
            BatchTypes.BatchState state,
            uint256 farmerId,
            uint256 processorId,
            uint256 packagerId,
            uint256[] memory distributorIds,
            uint256[] memory retailerIds
        ) = getUpdatedBatchActors(_batchId);

        if (state == BatchTypes.BatchState.Processed) {
            return processors[processorId].batchIds.add(_batchId);
        } else if (state == BatchTypes.BatchState.Packaged) {
            return packagers[packagerId].batchIds.add(_batchId);
        } else if (state == BatchTypes.BatchState.AtDistributors) {
            uint256 distributorAdded = distributorIds[distributorIds.length - 1];
            return distributors[distributorAdded].batchIds.add(_batchId);
        } else if (state == BatchTypes.BatchState.AtRetailers) {
            uint256 retailerAdded = retailerIds[retailerIds.length - 1];
            return retailers[retailerAdded].batchIds.add(_batchId);
        }
        return false;
    }

    /**
    * @dev To interface with ERC721 & receive the batch dNFTs.
    */
    function onERC721Received(address, address, uint256, bytes calldata) external view returns(bytes4) {
        if(msg.sender == address(this)) return this.onERC721Received.selector;
        return bytes4(0);
    }
}