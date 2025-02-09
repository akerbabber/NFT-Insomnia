// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.26;

import {ERC721} from "openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ud60x18} from "prb-math/UD60x18.sol";
import {ISablierLockup} from "v2-core/interfaces/ISablierLockup.sol";
import {Broker, Lockup, LockupLinear, IERC20 as IERC20Sablier} from "v2-core/types/DataTypes.sol";

// Custom errors with documentation
/// @notice Thrown when the caller's address is not in the whitelist.
error NotWhitelisted();
/// @notice Thrown when the caller is not eligible for discount mint.
error NotEligibleForDiscountMint();
/// @notice Thrown when the discount signature validation fails.
error InvalidDiscountSignature();
/// @notice Thrown when an invalid minting phase is encountered.
error InvalidPhase();
/// @notice Thrown when a free mint has already been claimed.
error AlreadyClaimedFreeMint();
/// @notice Thrown when a discount mint has already been claimed.
error AlreadyClaimedDiscountMint();
/// @notice Thrown when a mint is attempted after the minting period is over.
error MintingPeriodOver();
/// @notice Thrown when an action is attempted before the minting period is over.
error MintingPeriodNotOver();
/// @notice Thrown when the provided phases are in an incorrect order.
error InvalidPhaseOrder();

/// @notice Enum representing the current minting phase.
enum MintPhase {
    FreeMint,
    DiscountMint,
    FullMint,
    MintOver
}

/// @title MultiUtilityNft
/// @notice Manages phased NFT minting (free, discount, full) with vesting integration via Sablier Lockup.
/// @dev Inherits from ERC721, Ownable, and EIP712 for secure minting operations.
contract MultiUtilityNft is ERC721, Ownable, EIP712 {
    using SafeERC20 for IERC20;

    /// @notice Timestamp marking the end of the free mint phase.
    uint256 public immutable phase1End;
    /// @notice Timestamp marking the end of the discount mint phase.
    uint256 public immutable phase2End;
    /// @notice Timestamp marking the end of overall minting.
    uint256 public immutable mintEnd;
    /// @notice Merkle root for free mint eligibility.
    bytes32 public immutable merkleRootPhase1;
    /// @notice Merkle root for discount mint eligibility.
    bytes32 public immutable merkleRootPhase2;

    /// @notice Price for discounted mint.
    uint256 public immutable discountPrice;
    /// @notice Price for full mint.
    uint256 public immutable fullPrice;

    /// @notice ERC20 token used for mint payment.
    IERC20 public immutable paymentToken;
    /// @notice Sablier Lockup contract used for vesting locked funds.
    ISablierLockup public immutable sablierLockup;
    /// @notice Vesting duration constant (365 days).
    uint40 public constant VESTING_DURATION = 365 days;

    /// @notice Mapping of user addresses to their discount mint nonces.
    mapping(address => uint256) public nonces;
    /// @notice Records whether an address has claimed the free mint.
    mapping(address => bool) private _freeMintClaimed;
    /// @notice Records whether an address has claimed the discount mint.
    mapping(address => bool) private _discountMintClaimed;

    /// @notice Internal counter for tracking the next token ID.
    uint256 private _nextTokenId;

    /// @notice Emitted when an NFT is minted.
    /// @param minter Address of the minter.
    /// @param tokenId Token ID of the minted NFT.
    /// @param phase Mint phase during which the NFT was minted.
    event Minted(address indexed minter, uint256 tokenId, MintPhase phase);
    /// @notice Emitted when funds are locked on Sablier.
    /// @param streamId ID of the created Sablier stream.
    /// @param amount Amount of funds locked.
    event SablierStreamCreated(uint256 streamId, uint256 amount);

    /// @notice EIP712 TYPEHASH for discount mint signature verification.
    bytes32 public constant DISCOUNT_MINT_TYPEHASH = keccak256("DiscountMint(address minter,uint256 nonce)");

    /**
     * @notice Initializes the MultiUtilityNft contract.
     * @param initialOwner Address of the contract owner.
     * @param _paymentToken ERC20 token used for payment.
     * @param _sablierLockup Address of the Sablier Lockup contract.
     * @param _merkleRootPhase1 Merkle root for free mint eligibility.
     * @param _merkleRootPhase2 Merkle root for discount mint eligibility.
     * @param _discountPrice Price for discounted mint.
     * @param _fullPrice Price for full mint.
     * @param _phase1End Timestamp marking end of free mint phase.
     * @param _phase2End Timestamp marking end of discount mint phase.
     * @param _mintEnd Timestamp marking end of overall minting.
     */
    constructor(
        address initialOwner,
        IERC20 _paymentToken,
        address _sablierLockup,
        bytes32 _merkleRootPhase1,
        bytes32 _merkleRootPhase2,
        uint256 _discountPrice,
        uint256 _fullPrice,
        uint256 _phase1End,
        uint256 _phase2End,
        uint256 _mintEnd // new parameter for mint end
    ) ERC721("MultiUtilityNFT", "MUN") Ownable(initialOwner) EIP712("MultiUtilityNFT", "1") {
        if (_phase2End <= _phase1End) revert InvalidPhaseOrder();
        if (_mintEnd <= _phase2End) revert InvalidPhase();
        paymentToken = _paymentToken;
        sablierLockup = ISablierLockup(_sablierLockup);
        merkleRootPhase1 = _merkleRootPhase1;
        merkleRootPhase2 = _merkleRootPhase2;
        discountPrice = _discountPrice;
        fullPrice = _fullPrice;
        phase1End = _phase1End;
        phase2End = _phase2End;
        mintEnd = _mintEnd;
    }

    /**
     * @notice Gets the current mint phase based on block timestamp.
     * @return Current MintPhase (FreeMint, DiscountMint, FullMint, or MintOver).
     */
    function getCurrentMintPhase() external view returns (MintPhase) {
        if (block.timestamp >= mintEnd) {
            return MintPhase.MintOver;
        } else if (block.timestamp <= phase1End) {
            return MintPhase.FreeMint;
        } else if (block.timestamp <= phase2End) {
            return MintPhase.DiscountMint;
        } else {
            return MintPhase.FullMint;
        }
    }

    /**
     * @notice Executes a free mint for whitelisted users during Phase1.
     * @param merkleProof Array of bytes32 proofs verifying whitelist eligibility.
     */
    function mintPhase1(bytes32[] calldata merkleProof) external {
        if (block.timestamp > phase1End) revert InvalidPhase();
        _phase1Validate(merkleProof);
        uint256 tokenId = _nextTokenId++;
        emit Minted(msg.sender, tokenId, MintPhase.FreeMint);
        _safeMint(msg.sender, tokenId);
    }

    /**
     * @notice Executes a discounted mint for eligible users during Phase2.
     * @param merkleProof Array of bytes32 proofs verifying whitelist eligibility.
     * @param v ECDSA signature parameter.
     * @param r ECDSA signature parameter.
     * @param s ECDSA signature parameter.
     */
    function mintPhase2(bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s) external {
        if (block.timestamp <= phase1End || block.timestamp > phase2End) revert InvalidPhase();
        _phase2Validate(merkleProof, v, r, s);
        uint256 tokenId = _nextTokenId++;
        emit Minted(msg.sender, tokenId, MintPhase.DiscountMint);
        paymentToken.safeTransferFrom(msg.sender, address(this), discountPrice);
        _safeMint(msg.sender, tokenId);
    }

    /**
     * @notice Executes a full-price mint during the open mint phase (Phase3).
     */
    function mintPhase3() external {
        if (block.timestamp >= mintEnd) revert MintingPeriodOver();
        if (block.timestamp <= phase2End) revert InvalidPhase();
        uint256 tokenId = _nextTokenId++;
        emit Minted(msg.sender, tokenId, MintPhase.FullMint);
        paymentToken.safeTransferFrom(msg.sender, address(this), fullPrice);
        _safeMint(msg.sender, tokenId);
    }

    /**
     * @notice Validates free mint eligibility using a Merkle proof.
     * @param merkleProof Array of bytes32 proofs verifying inclusion in the whitelist.
     */
    function _phase1Validate(bytes32[] calldata merkleProof) internal {
        if (_freeMintClaimed[msg.sender]) revert AlreadyClaimedFreeMint();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(msg.sender))));
        if (!MerkleProof.verify(merkleProof, merkleRootPhase1, leaf)) revert NotWhitelisted();
        _freeMintClaimed[msg.sender] = true;
    }

    /**
     * @notice Validates discount mint eligibility and signature using a Merkle proof.
     * @param merkleProof Array of bytes32 proofs verifying inclusion in the whitelist.
     * @param v ECDSA signature parameter.
     * @param r ECDSA signature parameter.
     * @param s ECDSA signature parameter.
     */
    function _phase2Validate(bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s) internal {
        if (_discountMintClaimed[msg.sender]) revert AlreadyClaimedDiscountMint();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(msg.sender))));
        if (!MerkleProof.verify(merkleProof, merkleRootPhase2, leaf)) revert NotWhitelisted();
        uint256 userNonce = nonces[msg.sender]++;
        bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, msg.sender, userNonce));
        bytes32 digest = _hashTypedDataV4(structHash);
        if (owner() != ECDSA.recover(digest, v, r, s)) revert InvalidDiscountSignature();
        _discountMintClaimed[msg.sender] = true;
    }

    /**
     * @notice Locks funds on Sablier with a linear vesting schedule after minting is over.
     * @dev Callable only by the owner after mintEnd.
     */
    function lockFundsLinearlyOnSablierFor356Days() external onlyOwner {
        if (block.timestamp < mintEnd) revert MintingPeriodNotOver();
        uint256 balance = paymentToken.balanceOf(address(this));
        Lockup.CreateWithDurations memory params = Lockup.CreateWithDurations({
            sender: owner(),
            recipient: owner(),
            totalAmount: uint128(balance),
            token: IERC20Sablier(address(paymentToken)),
            cancelable: false,
            transferable: true,
            shape: "Linear Stream",
            broker: Broker(address(0), ud60x18(0))
        });
        LockupLinear.UnlockAmounts memory unlockAmounts = LockupLinear.UnlockAmounts({start: 0, cliff: 0});
        LockupLinear.Durations memory durations = LockupLinear.Durations({cliff: 0, total: uint40(VESTING_DURATION)});
        paymentToken.safeIncreaseAllowance(address(sablierLockup), balance);
        uint256 streamId = sablierLockup.createWithDurationsLL(params, unlockAmounts, durations);
        emit SablierStreamCreated(streamId, balance);
    }

    /**
     * @notice Returns the next token ID to be minted.
     * @return uint256 representing the next token ID.
     */
    function getNextTokenId() external view returns (uint256) {
        return _nextTokenId;
    }

    /**
     * @notice Checks if a free mint has already been claimed by the address.
     * @param account The address to check.
     * @return True if free mint claimed; otherwise false.
     */
    function isFreeMintClaimed(address account) external view returns (bool) {
        return _freeMintClaimed[account];
    }

    /**
     * @notice Checks if a discount mint has already been claimed by the address.
     * @param account The address to check.
     * @return True if discount mint claimed; otherwise false.
     */
    function isDiscountMintClaimed(address account) external view returns (bool) {
        return _discountMintClaimed[account];
    }
}
