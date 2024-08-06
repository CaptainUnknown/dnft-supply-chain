# Dynamic NFT Based Supply Chain
![Hardhat CI](https://github.com/CaptainUnknown/dnft-supply-chain/actions/workflows/ci.yml/badge.svg)

An innovative blockchain-based traceability tool designed for the agrifood industry. It certifies the quality and origin of products by tracking each step of the production process, from planting to the distribution, using blockchain technology.

## Introduction
These smart contracts are designed to manage and track the lifecycle of produced batches in the supply chain & the actors involved in each step. All actors are assigned a soul-bound unique NFT that should be generated based on their compliance and necessary checks. Similarly, each batch is represented by a unique dNFT tied to the necessary on-chain data held in `BatchManager` contract.

## Overview
The repo contains the following contracts:
- `AccessManager`: Responsible for guard checks on sensitive changes and regular operations performed by ERP 'company users'.
- `Actor`: Represents a soul-bound ERC721 collection of NFT IDs for a specific type of actors. Each actor has a unique NFT ID tied to their identity.
- `Batch`: A dynamic NFT (dNFT) ERC721 collection where each dNFT represents a 'batch' in the supply chain. Each token is tied to the actor IDs involved in the batch and includes necessary on-chain data such as the current batch state.
- `ActorsManager`: Aggregates multiple Actor contracts, each representing a standalone collection for a specific type of actors. It manages the creation and organization of actor collections.
- `BatchManager`: Handles the validation of metadata, emission of important events, creation of batch NFTs, and linking them to the on-chain state.
- `SupplyChain`: Orchestrates the overall supply chain process, coordinating interactions between actors and batches.

## Deployment
The system can be deployed on:
- Public L2: Ensures transparency with relatively the slowest throughput.
- Custom Rollup (RaaS): Provides a configurable modular stack with transparency & faster finality.
- Hyperledger Besu: Offers granularity & configurable privacy with both PoA or IBFT consensus.
Additionally, a Chainlink Oracle node needs to be deployed to handle metadata validation jobs, connecting the contracts with a potential serverless function responsible for the validations.

## Usage
1. On `AccessManager` grant the 'Company User' role to an EOA.
2. Grant the `SupplyChain`, `ActorsManager` & `BatchManager` the 'Authorized Contract' role.
3. On `ActorsManager`, register the involved actors & retrieve their IDs. The actors will receive unique dNFTs from different collections based upon their role (actor type). With integration in mind, this can either be done manually by the 'company user' but more preferrably users should be able to trigger those functions using a backend service as the middle man. Which could be responsible for the actor registration, authentication, data validation & other necessary off chain steps.
4. Use the `addHarvestedBatch()` on the `SupplyChain` contract to create an initial batch. Which mints a dNFT tied to the farmer by default. This should be triggerable by the farmers requesting a batch to be created through the MES system.
5. Any changes on the MES systems can trigger a service that invokes the `updateBatchState()`. This will tie the dNFT representing the batch to the actor involved in each step.

## Activity Diagram
![activityDiagram](https://github.com/user-attachments/assets/a9a753fa-ecfc-4d02-8d5c-97e11503bdf3)

## Class Diagram
<img width="2900" alt="dNFT Supply Chain Class Diagram" src="https://github.com/user-attachments/assets/374c84f4-4d56-449d-973a-e7e0e959f8f3">
