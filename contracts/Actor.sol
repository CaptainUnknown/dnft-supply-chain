// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { ERC721Enumerable } from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import { ERC721URIStorage } from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import { AccessManager } from "./AccessManager.sol";
import { Errors } from "./Errors.sol";

/// @custom:security-contact @captainunknown7@gmail.com
contract Actor is ERC721, ERC721Enumerable, ERC721URIStorage {
    uint256 private _nextActorId;
    AccessManager public acl;
    bytes32 immutable AUTHORIZED_CONTRACT_ROLE;

    modifier onlyAuthorizedContract() {
        if (!acl.hasRole(AUTHORIZED_CONTRACT_ROLE, msg.sender))
            revert Errors.UnAuthorized("AUTHORIZED_CONTRACT_ROLE");
        _;
    }

    constructor(address aclAddress, string memory actorType, string memory prefix) ERC721(actorType, prefix) {
        acl = AccessManager(aclAddress);
        AUTHORIZED_CONTRACT_ROLE = acl.AUTHORIZED_CONTRACT_ROLE();
    }

    function _baseURI() internal pure override returns (string memory) {
        return "ipfs://";
    }

    function registerActor(address account, string calldata hash)
    external
    onlyAuthorizedContract
    returns (uint256)
    {
        if (balanceOf(account) != 0) revert Errors.DoubleRegistrationNotAllowed();
        uint256 actorId = _nextActorId++;
        _safeMint(account, actorId);
        _setTokenURI(actorId, hash);
        return actorId;
    }

    function updateActor(uint256 actorId, string memory newHash)
    external
    onlyAuthorizedContract
    {
        _setTokenURI(actorId, newHash);
    }

    function transferFrom(address /*from*/, address /*to*/, uint256 /*tokenId*/) public pure override(IERC721, ERC721) {
        revert Errors.SoulBoundTransferNotAllowed();
    }

    function safeTransferFrom(address /*from*/, address /*to*/, uint256 /*tokenId*/, bytes memory /*data*/) public pure override(IERC721, ERC721) {
        revert Errors.SoulBoundTransferNotAllowed();
    }

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
