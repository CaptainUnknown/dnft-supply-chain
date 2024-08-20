// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
* @title BatchType Definitions
* @custom:security-contact @captainunknown7@gmail.com
*/
/*
* Example Data:
*
* Harvest Event:
* 1 - Date
* 2 - Location
* 3 - Method
*
* Processing Event:
* 1 - Date
* 2 - Location
* 3 - Quantity
* 4 - Quality Test
*
* Bottling Event:
* 1 - Date
* 2 - Location
* 3 - Quantity
*
* Distribution Event:
* 1 - Date
* 2 - Location
* 3 - Storage Condition
* 4 - Handling
*
* Retail Event:
* 1 - Date
* 2 - Location
*/
library BatchTypes {
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

    struct HarvestEvent {
        uint64 date;
        uint32 latitude;
        uint32 longitude;
        string method;
    }

    struct ProcessingEvent {
        uint64 date;
        uint32 latitude;
        uint32 longitude;
        uint256 quantity;
        bool qualityTest;
    }

    struct PackagingEvent {
        uint64 date;
        uint32 latitude;
        uint32 longitude;
        uint256 quantity;
    }

    struct DistributionEvent {
        uint64 date;
        uint32 latitude;
        uint32 longitude;
        string storageCondition;
        string handling;
    }

    struct RetailEvent {
        uint64 date;
        uint32 latitude;
        uint32 longitude;
        uint256 quantity;
    }

    struct BatchInfo {
        BatchState state;
        bool isCertified;
        // Actor Ids for the given actors involved in the batch
        uint256 farmerId;
        HarvestEvent harvestEvent;
        uint256 processorId;
        ProcessingEvent processingEvent;
        uint256 packagerId;
        PackagingEvent packagingEvent;
    }
}