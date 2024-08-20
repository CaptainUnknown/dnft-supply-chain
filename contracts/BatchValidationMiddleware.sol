// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { String } from "./String.sol";
import { BatchTypes } from "./BatchTypes.sol";

/**
* @title Acts as middleware to validate batch data.
* @custom:security-contact @captainunknown7@gmail.com
*/
library BatchValidationMiddleware {
    uint8 public constant LOCATION_DECIMALS = 8;
    uint8 public constant QTY_DECIMALS = 18;
    uint256 public constant MAX_PROCESSING_QUANTITY = type(uint256).max;
    uint256 public constant MIN_PROCESSING_QUANTITY = 100 * 10**QTY_DECIMALS; // Example Min 100 Units

    function getValidMethods() public pure returns(string[] memory) {
        string[] memory validMethods = new string[](7);
        validMethods[0] = "hand-picked";
        validMethods[1] = "sickle-cut";
        validMethods[2] = "reaping-hook";
        validMethods[3] = "mechanical-shaker";
        validMethods[4] = "combined-harvester";
        validMethods[5] = "suction-harvester";
        validMethods[6] = "laser-harvester";

        return validMethods;
    }

    function getStorageConditions() public pure returns(string[] memory) {
        string[] memory validMethods = new string[](12);
        validMethods[0] = "cool";
        validMethods[1] = "refrigerated";
        validMethods[2] = "frozen";
        validMethods[3] = "ambient";
        validMethods[4] = "warm";
        validMethods[5] = "dry";
        validMethods[6] = "humid";
        validMethods[7] = "controlled-humidity";
        validMethods[8] = "dark";
        validMethods[9] = "light";
        validMethods[10] = "ventilated";
        validMethods[11] = "sealed";

        return validMethods;
    }

    function getHandlingConditions() public pure returns(string[] memory) {
        string[] memory validMethods = new string[](9);
        validMethods[0] = "careful";
        validMethods[1] = "gentle";
        validMethods[2] = "do-not-stack";
        validMethods[3] = "keep-upright";
        validMethods[4] = "perishable";
        validMethods[5] = "flammable";
        validMethods[6] = "temperature-sensitive";
        validMethods[7] = "light-sensitive";
        validMethods[8] = "moisture-sensitive";

        return validMethods;
    }

    function validateDate(uint256 date) internal view returns (bool) {
        return date <= block.timestamp;
    }

    function validateLocation(uint256 latitude, uint256 longitude) internal pure returns (bool) {
        uint256 maxLatitude = 90 * (10 ** LOCATION_DECIMALS);
        uint256 maxLongitude = 180 * (10 ** LOCATION_DECIMALS);

        if (latitude > maxLatitude || latitude < 0 || longitude > maxLongitude || longitude < 0) return false;
        return true;
    }

    function validateMethod(string memory method) internal pure returns (bool) {
        string[] memory validMethods = getValidMethods();
        for (uint i = 0; i < validMethods.length; i++)
            if (String.strcmp(method, validMethods[i])) return true;
        return false;
    }

    function validateQuantity(uint256 quantity) internal pure returns (bool) {
        return quantity > MIN_PROCESSING_QUANTITY && quantity < MAX_PROCESSING_QUANTITY;
    }

    function validateStorageCondition(string memory storageCondition) internal pure returns (bool) {
        string[] memory storageConditions = getStorageConditions();
        for (uint i = 0; i < storageConditions.length; i++)
            if (String.strcmp(storageCondition, storageConditions[i])) return true;
        return false;
    }

    function validateHandling(string memory handling) internal pure returns (bool) {
        string[] memory handlingConditions = getHandlingConditions();
        for (uint i = 0; i < handlingConditions.length; i++)
            if (String.strcmp(handling, handlingConditions[i])) return true;
        return false;
    }

    // Event Validators
    function validateHarvestEvent(
        uint256 date,
        uint256 latitude,
        uint256 longitude,
        string memory method
    ) internal view returns (bool) {
        return validateDate(date) && validateLocation(latitude, longitude) && validateMethod(method);
    }

    function validateHarvestEvent(
        BatchTypes.HarvestEvent memory _harvestEvent
    ) internal view returns (bool) {
        return validateDate(_harvestEvent.date)
        &&
        validateLocation(_harvestEvent.latitude, _harvestEvent.longitude)
            &&
            validateMethod(_harvestEvent.method);
    }

    function validateProcessingEvent(
        uint256 date,
        uint256 latitude,
        uint256 longitude,
        uint256 quantity
    ) internal view returns (bool) {
        return validateDate(date) && validateLocation(latitude, longitude) && validateQuantity(quantity);
    }

    function validatePackagingEvent(
        uint256 date,
        uint256 latitude,
        uint256 longitude,
        uint256 quantity
    ) internal view returns (bool) {
        return validateDate(date) && validateLocation(latitude, longitude) && validateQuantity(quantity);
    }

    function validateDistributionEvent(
        uint256 date,
        uint256 latitude,
        uint256 longitude,
        string memory storageCondition,
        string memory handlingCondition
    ) internal view returns (bool) {
        return validateDate(date) && validateLocation(latitude, longitude) && validateStorageCondition(storageCondition) && validateHandling(handlingCondition);
    }

    function validateRetailEvent(
        uint256 date,
        uint256 latitude,
        uint256 longitude
    ) internal view returns (bool) {
        return validateDate(date) && validateLocation(latitude, longitude);
    }

    function validateBatchEvents(
        BatchTypes.BatchInfo memory _batch
    ) internal view returns (bool) {
        // Only validates the events that are logged
        if (_batch.state == BatchTypes.BatchState(0))
            return validateHarvestEvent(
                _batch.harvestEvent.date,
                _batch.harvestEvent.latitude,
                _batch.harvestEvent.longitude,
                _batch.harvestEvent.method
            );
        else if (_batch.state == BatchTypes.BatchState(1))
            return validateHarvestEvent(
                _batch.harvestEvent.date,
                _batch.harvestEvent.latitude,
                _batch.harvestEvent.longitude,
                _batch.harvestEvent.method
            ) && validateProcessingEvent(
                _batch.processingEvent.date,
                _batch.processingEvent.latitude,
                _batch.processingEvent.longitude,
                _batch.processingEvent.quantity
            );
        else
            return validateHarvestEvent(
                _batch.harvestEvent.date,
                _batch.harvestEvent.latitude,
                _batch.harvestEvent.longitude,
                _batch.harvestEvent.method
            ) && validateProcessingEvent(
                _batch.processingEvent.date,
                _batch.processingEvent.latitude,
                _batch.processingEvent.longitude,
                _batch.processingEvent.quantity
            ) && validatePackagingEvent(
                _batch.packagingEvent.date,
                _batch.packagingEvent.latitude,
                _batch.packagingEvent.longitude,
                _batch.packagingEvent.quantity
            );
        // Manually validate Distribution & Retail Events when being pushed
    }

    function validateChronologicalOrder(
        BatchTypes.BatchState oldBatchState,
        BatchTypes.BatchState newBatchState
    ) internal pure returns (bool) {
        if (oldBatchState < newBatchState) return true;
        else if (oldBatchState == BatchTypes.BatchState.AtDistributors && oldBatchState == newBatchState)
            return true;
        else if (oldBatchState == BatchTypes.BatchState.AtRetailers && oldBatchState == newBatchState)
            return true;
            // In case there is no packaging stage
        else if (oldBatchState == BatchTypes.BatchState.Processed && newBatchState == BatchTypes.BatchState.AtDistributors)
            return true;
        return false;
    }
}