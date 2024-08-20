// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { ERC721Enumerable } from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import { ERC721URIStorage } from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import { AccessManager } from "./AccessManager.sol";
import { Errors } from "./Errors.sol";

/**
* @title An ERC721 collection of batches.
* @dev A soul-bound NFT to identify batches as dNFTs held by the `SupplyChain` contract.
* @custom:security-contact @captainunknown7@gmail.com
*/
contract Batch is ERC721, ERC721Enumerable, ERC721URIStorage {
    uint256 private _batchId;

    /**
    * @dev Initializes the batch collection.
    */
    constructor(string memory batchName, string memory batchSymbol)
        ERC721(batchName, batchSymbol) {}

    function _baseURI() internal pure override returns (string memory) {
        return "ipfs://";
    }

    /**
    * @dev To create a new batch with the provided hash.
    * Can only by called an external contract which would be `BatchManager`.
    * @param account - The receiver of the batch. It'd be `SupplyChain` when called as a registrar.
    * @param hash - The hash of the Batch.
    * @return The registered Batch ID.
    */
    function _createBatch(address account, string memory hash) internal returns (uint256) {
        uint256 batchId = _batchId++;
        _safeMint(account, batchId);
        _setTokenURI(batchId, hash);
        return batchId;
    }

    /**
    * @dev To update batch hash.
    * Can only by called an external contract which would be `BatchManager`.
    * @param batchId - Batch ID to update.
    * @param newHash - The new hash to update the old hash with.
    */
    function _updateBatch(uint256 batchId, string memory newHash) internal {
        _setTokenURI(batchId, newHash);
    }

    /**
    * @dev Reverts with `SoulBoundTransferNotAllowed`.
    */
    function transferFrom(address /*from*/, address /*to*/, uint256 /*tokenId*/) public pure override(IERC721, ERC721) {
        revert Errors.SoulBoundTransferNotAllowed();
    }

    /**
    * @dev Reverts with `SoulBoundTransferNotAllowed`.
    */
    function safeTransferFrom(address /*from*/, address /*to*/, uint256 /*tokenId*/, bytes memory /*data*/) public pure override(IERC721, ERC721) {
        revert Errors.SoulBoundTransferNotAllowed();
    }

    /**
    * @return Whether the id has been issued or not.
    */
    function idExists(uint256 id) public view returns(bool) {
        return id < totalSupply();
    }

    // Necessary Overrides
    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721, ERC721Enumerable)
        returns (address)
    {
        return super._update(to, tokenId, auth);
    }

    function _increaseBalance(address account, uint128 value)
        internal
        override(ERC721, ERC721Enumerable)
    {
        super._increaseBalance(account, value);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721, ERC721Enumerable, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}