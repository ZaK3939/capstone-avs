// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IHookRegistry {
    // Custom Errors
    error NotAuthorized();
    error InvalidDeposit();
    error HookNotRegistered();
    error HookAlreadyRegistered();
    error HookAlreadyPaused();
    error HookNotPaused();

    // Events
    event HookRegistered(address indexed hook, address indexed developer, uint256 deposit);
    event HookActivated(address indexed hook);
    event HookDeactivated(address indexed hook);
    event HookPaused(address indexed hook);
    event HookUnpaused(address indexed hook);
    event RiskScoreUpdated(address indexed hook, uint256 score);

    // Setup
    function setVault(address _vault) external;
    function setServiceManager(address _serviceManager) external;

    // Hook Management
    function registerHook(address hook, uint256 usdcAmount) external;
    function activateHook(address hook) external;
    function deactivateHook(address hook) external;
    function pauseHook(address hook) external;
    function unpauseHook(address hook) external;
    function updateRiskScore(address hook, uint256 score) external;

    // View Functions
    function getHookInfo(address hook)
        external
        view
        returns (
            address developer,
            uint256 usdcDeposit,
            bool isActive,
            bool isPaused,
            uint256 riskScore
        );

    // Hook Status
    function getDepositedAmount(address hook) external view returns (uint256);
    function getDeveloper(address hook) external view returns (address);
    function getRiskScore(address hook) external view returns (uint256);
    function isHookPaused(address hook) external view returns (bool);
}
