// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BuilderCodes} from "../src/BuilderCodes.sol";

/// @notice Script for deploying the BuilderCodes contract
contract DeployBuilderCodes is Script {
    function run() external returns (address) {
        address owner = 0x1D8958f7b9AE9FbB9d78C1e1aB18b44Fd54a0B7A; // testnet key
        address initialRegistrar = 0x6Bd08aCF2f8839eAa8a2443601F2DeED892cd389; // dev registrar key
        string memory uriPrefix = "https://flywheel.com/";

        console.log("Initial registrar:", initialRegistrar);
        console.log("URI Prefix:", uriPrefix);

        vm.startBroadcast();

        // Deploy the implementation contract
        BuilderCodes implementation = new BuilderCodes{salt: 0}();

        // Prepare initialization data
        bytes memory initData = abi.encodeCall(BuilderCodes.initialize, (owner, initialRegistrar, uriPrefix));
        console.logBytes(initData);

        // Deploy the proxy
        ERC1967Proxy proxy = new ERC1967Proxy{salt: 0}(address(implementation), initData);

        console.log("BuilderCodes implementation deployed at:", address(implementation));
        console.log("BuilderCodes proxy deployed at:", address(proxy));

        vm.stopBroadcast();

        return address(proxy);
    }
}
