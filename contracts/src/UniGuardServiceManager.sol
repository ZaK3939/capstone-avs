// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {ECDSAServiceManagerBase} from
    "@eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import {ECDSAStakeRegistry} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {IServiceManager} from "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {ECDSAUpgradeable} from
    "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import {IERC1271Upgradeable} from
    "@openzeppelin-upgrades/contracts/interfaces/IERC1271Upgradeable.sol";
import {IUniGuardServiceManager} from "./interfaces/IUniGuardServiceManager.sol";
import {IHookRegistry} from "./interfaces/IHookRegistry.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";

contract UniGuardServiceManager is ECDSAServiceManagerBase, IUniGuardServiceManager {
    using ECDSAUpgradeable for bytes32;

    uint32 public latestTaskNum;
    IHookRegistry public hookRegistry;
    bool public isHookRegistrySet;

    error InvalidSignature();

    mapping(uint32 => bytes32) public allTaskHashes;
    mapping(address => mapping(uint32 => bytes)) public allTaskResponses;

    constructor(
        address _avsDirectory,
        address _stakeRegistry,
        address _rewardsCoordinator,
        address _delegationManager
    )
        ECDSAServiceManagerBase(_avsDirectory, _stakeRegistry, _rewardsCoordinator, _delegationManager)
    {}

    function setHookRegistry(address _hookRegistry) external onlyOwner {
        require(_hookRegistry != address(0), "Invalid HookRegistry address");
        hookRegistry = IHookRegistry(_hookRegistry);
        isHookRegistrySet = true;
    }

    function createNewTask(string memory name) external returns (Task memory) {
        Task memory newTask;
        newTask.name = name;
        newTask.taskCreatedBlock = uint32(block.number);

        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        emit NewTaskCreated(latestTaskNum, newTask);
        latestTaskNum = latestTaskNum + 1;

        return newTask;
    }

    function respondToTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes memory signature,
        string memory metrics,
        uint256 riskScore,
        address hook
    ) external {
        require(keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex], "Invalid task");
        require(allTaskResponses[msg.sender][referenceTaskIndex].length == 0, "Already responded");

        bytes32 messageHash = keccak256(abi.encodePacked(metrics, task.name, riskScore, hook));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;

        if (
            !(
                magicValue
                    == ECDSAStakeRegistry(stakeRegistry).isValidSignature(
                        ethSignedMessageHash, signature
                    )
            )
        ) {
            revert InvalidSignature();
        }

        allTaskResponses[msg.sender][referenceTaskIndex] = signature;
        hookRegistry.updateRiskScore(hook, riskScore);

        emit TaskResponded(referenceTaskIndex, task, msg.sender);
    }
}
