// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {BuilderCodesTest} from "../lib/BuilderCodesTest.sol";
import {BuilderCodes} from "../../src/BuilderCodes.sol";
import {MockTransferAgent} from "../lib/mocks/MockTransferAgent.sol";

/// @notice Integration tests for BuilderCodes transfers
contract BuilderCodesTransfersTest is BuilderCodesTest {
    /// @notice Test that transferFrom succeeds when a token owner approves a transfer agent
    ///
    /// @param from The from address
    /// @param to The to address
    /// @param codeSeed The seed for generating the code
    /// @param payoutAddress The payout address
    function test_approveTransferAgentToTransferToken(address from, address to, uint256 codeSeed, address payoutAddress)
        public
    {
        from = _boundNonZeroAddress(from);
        to = _boundNonZeroAddress(to);
        vm.assume(from != owner);
        vm.assume(from != to);
        payoutAddress = _boundNonZeroAddress(payoutAddress);
        MockTransferAgent transferAgent = new MockTransferAgent(address(builderCodes));

        // Register the code
        string memory code = _generateValidCode(codeSeed);
        uint256 tokenId = builderCodes.toTokenId(code);
        vm.prank(owner);
        builderCodes.register(code, from, payoutAddress);

        // Owner grants transfer role to transfer agent
        vm.prank(owner);
        builderCodes.grantRole(TRANSFER_ROLE, address(transferAgent));

        // Owner approves specific transfer on agent
        vm.prank(owner);
        transferAgent.approveTransfer(from, to);

        // User approves transfer agent to transfer the token
        vm.prank(from);
        builderCodes.approve(address(transferAgent), tokenId);

        // Transfer the token from `from` to `to`
        vm.prank(from);
        transferAgent.transfer(to, tokenId);

        // Verify the token was transferred
        assertEq(builderCodes.ownerOf(tokenId), to);
        assertEq(builderCodes.balanceOf(from), 0);
        assertEq(builderCodes.balanceOf(to), 1);
    }
}
