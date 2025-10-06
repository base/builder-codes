// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessControlUpgradeable} from "openzeppelin-contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Ownable2StepUpgradeable} from "openzeppelin-contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC721Upgradeable, IERC721} from "openzeppelin-contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {IERC165} from "openzeppelin-contracts/interfaces/IERC165.sol";
import {IERC4906} from "openzeppelin-contracts/interfaces/IERC4906.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {LibBit} from "solady/utils/LibBit.sol";
import {LibString} from "solady/utils/LibString.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

/// @title BuilderCodes
///
/// @notice Registry for Builder Codes
///
/// @author Coinbase (https://github.com/base/builder-codes)
contract BuilderCodes is
    Initializable,
    ERC721Upgradeable,
    AccessControlUpgradeable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable,
    EIP712,
    IERC4906
{
    /// @notice EIP-712 storage structure for registry data
    /// @custom:storage-location erc7201:base.BuilderCodes
    struct RegistryStorage {
        /// @dev Base URI for referral code metadata
        string uriPrefix;
        /// @dev Mapping of builder code token IDs to payout recipients
        mapping(uint256 tokenId => address payoutAddress) payoutAddresses;
    }

    ////////////////////////////////////////////////////////////////
    ///                        Constants                         ///
    ////////////////////////////////////////////////////////////////

    /// @notice Role identifier for addresses authorized to call register or sign registrations
    bytes32 public constant REGISTER_ROLE = keccak256("REGISTER_ROLE");

    /// @notice Role identifier for addresses authorized to transfer codes (still must own token or receive approval)
    bytes32 public constant TRANSFER_ROLE = keccak256("TRANSFER_ROLE");

    /// @notice Role identifier for addresses authorized to update metadata for one or all codes
    bytes32 public constant METADATA_ROLE = keccak256("METADATA_ROLE");

    /// @notice EIP-712 typehash for registration
    bytes32 public constant REGISTRATION_TYPEHASH =
        keccak256("BuilderCodeRegistration(string code,address initialOwner,address payoutAddress,uint48 deadline)");

    /// @notice Allowed characters for referral codes
    string public constant ALLOWED_CHARACTERS = "0123456789abcdefghijklmnopqrstuvwxyz_";

    /// @notice Allowed characters for referral codes lookup
    /// @dev LibString.to7BitASCIIAllowedLookup(ALLOWED_CHARACTERS)
    uint128 public constant ALLOWED_CHARACTERS_LOOKUP = 10633823847437083212121898993101832192;

    /// @notice EIP-1967 storage slot base for registry mapping using ERC-7201
    /// @dev keccak256(abi.encode(uint256(keccak256("base.BuilderCodes")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REGISTRY_STORAGE_LOCATION =
        0x015aa89e92b56dd64cffc1c9b26553e653b294bc48004bbcc753732d19b11100;

    ////////////////////////////////////////////////////////////////
    ///                          Events                          ///
    ////////////////////////////////////////////////////////////////

    /// @notice Emitted when a referral code is registered
    ///
    /// @param tokenId Token ID of the referral code
    /// @param code Referral code
    event CodeRegistered(uint256 indexed tokenId, string code);

    /// @notice Emitted when a publisher's default payout address is updated
    ///
    /// @param tokenId Token ID of the referral code
    /// @param payoutAddress New default payout address
    event PayoutAddressUpdated(uint256 indexed tokenId, address payoutAddress);

    ////////////////////////////////////////////////////////////////
    ///                          Errors                          ///
    ////////////////////////////////////////////////////////////////

    /// @notice Emitted when the contract URI is updated (ERC-7572)
    event ContractURIUpdated();

    /// @notice Thrown when call doesn't have required permissions
    error Unauthorized();

    /// @notice Thrown when provided address is invalid (usually zero address)
    error ZeroAddress();

    /// @notice Thrown when signed registration deadline has passed
    error AfterRegistrationDeadline(uint48 deadline);

    /// @notice Thrown when builder code is invalid
    error InvalidCode(string code);

    /// @notice Thrown when token ID is invalid
    error InvalidTokenId(uint256 tokenId);

    /// @notice Thrown when builder code is not registered
    error Unregistered(string code);

    /// @notice Thrown when trying to renounce ownership (disabled for security)
    error OwnershipRenunciationDisabled();

    ////////////////////////////////////////////////////////////////
    ///                    External Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract (replaces constructor)
    ///
    /// @param initialOwner Address that will own the contract
    /// @param initialRegistrar Address to grant REGISTER_ROLE (can be address(0) to skip)
    function initialize(address initialOwner, address initialRegistrar, string memory uriPrefix) external initializer {
        if (initialOwner == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ERC721_init("Builder Codes", "BUILDERCODE");
        __Ownable2Step_init();
        _transferOwnership(initialOwner);
        __UUPSUpgradeable_init();
        _getRegistryStorage().uriPrefix = uriPrefix;

        if (initialRegistrar != address(0)) _grantRole(REGISTER_ROLE, initialRegistrar);
    }

    /// @notice Registers a new referral code in the system with a custom value
    ///
    /// @param code Custom builder code for the builder code
    /// @param initialOwner Owner of the builder code
    /// @param initialPayoutAddress Default payout address
    function register(string memory code, address initialOwner, address initialPayoutAddress)
        external
        onlyRole(REGISTER_ROLE)
    {
        _register(code, initialOwner, initialPayoutAddress);
    }

    /// @notice Registers a new referral code in the system with a signature
    ///
    /// @param code Custom builder code for the builder code
    /// @param initialOwner Owner of the builder code
    /// @param initialPayoutAddress Default payout address
    /// @param deadline Deadline to submit the registration
    /// @param registrar Address of the registrar
    /// @param signature Signature of the registrar
    function registerWithSignature(
        string memory code,
        address initialOwner,
        address initialPayoutAddress,
        uint48 deadline,
        address registrar,
        bytes memory signature
    ) external {
        // Check deadline has not passed
        if (block.timestamp > deadline) revert AfterRegistrationDeadline(deadline);

        // Check registrar has role
        _checkRole(REGISTER_ROLE, registrar);

        // Check signature is valid
        bytes32 structHash = keccak256(
            abi.encode(REGISTRATION_TYPEHASH, keccak256(bytes(code)), initialOwner, initialPayoutAddress, deadline)
        );
        if (!SignatureCheckerLib.isValidSignatureNow(registrar, _hashTypedData(structHash), signature)) {
            revert Unauthorized();
        }

        _register(code, initialOwner, initialPayoutAddress);
    }

    /// @inheritdoc ERC721Upgradeable
    ///
    /// @dev Requires sender has TRANSFER_ROLE
    /// @dev ERC721Upgradeable.safeTransferFrom inherits this function (and no other functions can initiate transfers)
    function transferFrom(address from, address to, uint256 tokenId) public override(ERC721Upgradeable, IERC721) {
        _checkRole(TRANSFER_ROLE, msg.sender);
        // test
        super.transferFrom(from, to, tokenId);
    }

    /// @notice Updates the metadata for a builder code
    ///
    /// @param tokenId Token ID of the builder code
    function updateMetadata(uint256 tokenId) external onlyRole(METADATA_ROLE) {
        _requireOwned(tokenId); // verifies token exists
        emit MetadataUpdate(tokenId);
    }

    /// @notice Updates the base URI for the builder codes
    ///
    /// @param uriPrefix New base URI for the builder codes
    function updateBaseURI(string memory uriPrefix) external onlyRole(METADATA_ROLE) {
        _getRegistryStorage().uriPrefix = uriPrefix;
        emit BatchMetadataUpdate(0, type(uint256).max);
        emit ContractURIUpdated();
    }

    /// @notice Updates the default payout address for a referral code
    ///
    /// @param code Builder code
    /// @param newPayoutAddress New default payout address
    /// @dev Only callable by referral code owner
    function updatePayoutAddress(string memory code, address newPayoutAddress) external {
        uint256 tokenId = toTokenId(code);
        if (_requireOwned(tokenId) != msg.sender) revert Unauthorized();
        _updatePayoutAddress(tokenId, newPayoutAddress);
    }

    /// @notice Gets the default payout address for a referral code
    ///
    /// @param code Builder code
    ///
    /// @return The default payout address
    function payoutAddress(string memory code) external view returns (address) {
        uint256 tokenId = toTokenId(code);
        if (_ownerOf(tokenId) == address(0)) revert Unregistered(code);
        return _getRegistryStorage().payoutAddresses[tokenId];
    }

    /// @notice Gets the default payout address for a referral code
    ///
    /// @param tokenId Token ID of the referral code
    ///
    /// @return The default payout address
    function payoutAddress(uint256 tokenId) external view returns (address) {
        if (_ownerOf(tokenId) == address(0)) revert Unregistered(toCode(tokenId));
        return _getRegistryStorage().payoutAddresses[tokenId];
    }

    /// @notice Returns the URI for a referral code
    ///
    /// @param code Builder code
    ///
    /// @return The URI for the referral code
    function codeURI(string memory code) external view returns (string memory) {
        return tokenURI(toTokenId(code));
    }

    /// @notice Returns the URI for the contract
    ///
    /// @return The URI for the contract
    function contractURI() external view returns (string memory) {
        string memory uriPrefix = _getRegistryStorage().uriPrefix;
        return bytes(uriPrefix).length > 0 ? string.concat(uriPrefix, "contractURI.json") : "";
    }

    /// @notice Returns the URI for a referral code
    ///
    /// @param tokenId Token ID of the referral code
    ///
    /// @return uri The URI for the referral code
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId); // verifies token exists
        string memory uriPrefix = _getRegistryStorage().uriPrefix;
        return bytes(uriPrefix).length > 0 ? string.concat(uriPrefix, toCode(tokenId)) : "";
    }

    /// @notice Checks if a referral code exists
    ///
    /// @param code Builder code to check
    ///
    /// @return True if the referral code exists
    function isRegistered(string memory code) public view returns (bool) {
        return _ownerOf(toTokenId(code)) != address(0);
    }

    /// @notice Checks if an address has a role
    ///
    /// @param role The role to check
    /// @param account The address to check
    ///
    /// @return True if the address has the role
    function hasRole(bytes32 role, address account) public view override returns (bool) {
        return account == owner() || super.hasRole(role, account);
    }

    /// @inheritdoc ERC721Upgradeable
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Upgradeable, AccessControlUpgradeable, IERC165)
        returns (bool)
    {
        return ERC721Upgradeable.supportsInterface(interfaceId)
            || AccessControlUpgradeable.supportsInterface(interfaceId) || interfaceId == bytes4(0x49064906);
    }

    /// @notice Checks if a referral code is valid
    ///
    /// @param code Builder code to check
    ///
    /// @return True if the referral code is valid
    function isValidCode(string memory code) public pure returns (bool) {
        // Early return invalid if code is zero or over 32 bytes/characters
        uint256 length = bytes(code).length;
        if (length == 0 || length > 32) return false;

        // Return if code is 7-bit ASCII matching the allowed characters
        return LibString.is7BitASCII(code, ALLOWED_CHARACTERS_LOOKUP);
    }

    /// @notice Converts a referral code to a token ID
    ///
    /// @param code Builder code to convert
    ///
    /// @return tokenId The token ID for the referral code
    function toTokenId(string memory code) public pure returns (uint256 tokenId) {
        if (!isValidCode(code)) revert InvalidCode(code);

        // Shift nonzero bytes right so high-endian bits are zero, undoing left-shift from bytes->bytes32 cast
        uint256 trailingZeroBytes = 32 - bytes(code).length;
        tokenId = uint256(bytes32(bytes(code))) >> trailingZeroBytes * 8;
    }

    /// @notice Converts a token ID to a referral code
    ///
    /// @param tokenId Token ID to convert
    ///
    /// @return code The referral code for the token ID
    function toCode(uint256 tokenId) public pure returns (string memory code) {
        // Shift nonzero bytes left so low-endian bits are zero, matching LibString's expectation to trim `\0` bytes
        uint256 leadingZeroBytes = LibBit.clz(tokenId) / 8; // "clz" = count leading zeros
        bytes32 smallString = bytes32(tokenId << leadingZeroBytes * 8);
        if (smallString != LibString.normalizeSmallString(smallString)) revert InvalidTokenId(tokenId);
        code = LibString.fromSmallString(smallString);
        if (!isValidCode(code)) revert InvalidCode(code);
    }

    /// @notice Disabled to prevent accidental ownership renunciation
    ///
    /// @dev Overrides OpenZeppelin's renounceOwnership to prevent accidental calls
    function renounceOwnership() public pure override {
        revert OwnershipRenunciationDisabled();
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Registers a new referral code
    ///
    /// @param code Referral code
    /// @param initialOwner Owner of the ref code
    /// @param initialPayoutAddress Default payout address
    function _register(string memory code, address initialOwner, address initialPayoutAddress) internal {
        uint256 tokenId = toTokenId(code);
        _mint(initialOwner, tokenId);
        emit CodeRegistered(tokenId, code);
        _updatePayoutAddress(tokenId, initialPayoutAddress);
    }

    /// @notice Registers a new referral code
    ///
    /// @param tokenId Token ID of the referral code
    /// @param newPayoutAddress New payout address
    function _updatePayoutAddress(uint256 tokenId, address newPayoutAddress) internal {
        if (newPayoutAddress == address(0)) revert ZeroAddress();
        _getRegistryStorage().payoutAddresses[tokenId] = newPayoutAddress;
        emit PayoutAddressUpdated(tokenId, newPayoutAddress);
    }

    /// @notice Authorization for upgrades
    ///
    /// @param newImplementation Address of new implementation
    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {}

    /// @notice Returns the domain name and version for the referral codes
    ///
    /// @return name The domain name for the referral codes
    /// @return version The version of the referral codes
    function _domainNameAndVersion()
        internal
        pure
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "Builder Codes";
        version = "1";
    }

    /// @notice Returns if the domain name and version may change
    ///
    /// @return True if the domain name and version may change
    function _domainNameAndVersionMayChange() internal pure override returns (bool) {
        return true;
    }

    /// @notice Gets the storage reference for the registry
    ///
    /// @return $ Storage reference for the registry
    function _getRegistryStorage() private pure returns (RegistryStorage storage $) {
        assembly {
            $.slot := REGISTRY_STORAGE_LOCATION
        }
    }
}
