// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.22;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Custom errors
error NotWhitelisted();
error NotEligibleForDiscountMint();
error InvalidDiscountSignature();
error InvalidPhase();
error AlreadyClaimedFreeMint();
error AlreadyClaimedDiscountMint();
error MintingPeriodOver();
error MintingPeriodNotOver();
error InvalidPhaseOrder();

// Extend the enum to include a phase for when minting is over.
enum MintPhase {
    FreeMint,
    DiscountMint,
    FullMint,
    MintOver
}

contract MultiUtilityNft is ERC721, Ownable, EIP712 {
    using SafeERC20 for IERC20;

    // Minting phases no longer passed as parameter; determined by timestamps
    uint256 public immutable phase1End; // Using 256 bits for timestamps since it is immutable
    uint256 public immutable phase2End; // Using 256 bits for timestamps since it is immutable

    // Merkle roots for two phases
    bytes32 public immutable merkleRootPhase1;
    bytes32 public immutable merkleRootPhase2;

    // Pricing parameters
    uint256 public immutable discountPrice;
    uint256 public immutable fullPrice;

    // Payment token (ERC20) and Sablier vesting integration
    IERC20 public immutable paymentToken;
    address public immutable sablier;
    uint256 public immutable vestingDuration = 365 days; // Using 256 bits for duration since it is immutable

    // New state: mintEnd timestamp after which minting stops.
    uint256 public immutable mintEnd;

    // Nonces for discount mints per user
    mapping(address => uint256) public nonces;
    // Mappings to prevent Merkle proof replay
    mapping(address => bool) private _freeMintClaimed;
    mapping(address => bool) private _discountMintClaimed;

    uint256 private _nextTokenId;

    // Update event: now using the MintPhase enum.
    event Minted(address indexed minter, uint256 tokenId, MintPhase phase);

    // Updated type hash including nonce
    bytes32 public constant DISCOUNT_MINT_TYPEHASH = keccak256("DiscountMint(address minter,uint256 nonce)");

    constructor(
        address initialOwner,
        IERC20 _paymentToken,
        address _sablier,
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
        sablier = _sablier;
        merkleRootPhase1 = _merkleRootPhase1;
        merkleRootPhase2 = _merkleRootPhase2;
        discountPrice = _discountPrice;
        fullPrice = _fullPrice;
        phase1End = _phase1End;
        phase2End = _phase2End;
        mintEnd = _mintEnd;
    }

    // Remove or deprecate the unified mint() function.
    // New separate functions for each mint phase:

    // Update helper function to include MintOver phase.
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

    // Phase1: Free mint for whitelisted users.
    function mintPhase1(bytes32[] calldata merkleProof) external {
        if (block.timestamp > phase1End) revert InvalidPhase();
        _phase1Validate(merkleProof);
        uint256 tokenId = _nextTokenId++;
        emit Minted(msg.sender, tokenId, MintPhase.FreeMint);
        _safeMint(msg.sender, tokenId);
    }

    // Phase2: Discounted mint with fee.
    function mintPhase2(bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s) external {
        if (block.timestamp <= phase1End || block.timestamp > phase2End) revert InvalidPhase();
        _phase2Validate(merkleProof, v, r, s);
        uint256 tokenId = _nextTokenId++;
        emit Minted(msg.sender, tokenId, MintPhase.DiscountMint);
        paymentToken.safeTransferFrom(msg.sender, address(this), discountPrice);
        _safeMint(msg.sender, tokenId);
    }

    // Phase3: Open mint at full price.
    function mintPhase3() external {
        if (block.timestamp >= mintEnd) revert MintingPeriodOver();
        if (block.timestamp <= phase2End) revert InvalidPhase();
        uint256 tokenId = _nextTokenId++;
        emit Minted(msg.sender, tokenId, MintPhase.FullMint);
        paymentToken.safeTransferFrom(msg.sender, address(this), fullPrice);
        _safeMint(msg.sender, tokenId);
    }

    // Renamed internal function for Phase1 validation only.
    function _phase1Validate(bytes32[] calldata merkleProof) internal {
        if (_freeMintClaimed[msg.sender]) revert AlreadyClaimedFreeMint();
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        if (!MerkleProof.verify(merkleProof, merkleRootPhase1, leaf)) revert NotWhitelisted();
        _freeMintClaimed[msg.sender] = true;
    }

    // Renamed internal function for Phase2 validation only.
    function _phase2Validate(bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s) internal {
        if (_discountMintClaimed[msg.sender]) revert AlreadyClaimedDiscountMint();
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        if (!MerkleProof.verify(merkleProof, merkleRootPhase2, leaf)) revert NotEligibleForDiscountMint();
        uint256 userNonce = nonces[msg.sender]++;
        bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, msg.sender, userNonce));
        bytes32 digest = _hashTypedDataV4(structHash);
        if (owner() != ECDSA.recover(digest, v, r, s)) revert InvalidDiscountSignature();
        _discountMintClaimed[msg.sender] = true;
    }

    // New function: After mintEnd, owner can transfer funds to sablier.
    function transferFundsToSablier() external onlyOwner {
        if (block.timestamp < mintEnd) revert MintingPeriodNotOver();
        uint256 balance = paymentToken.balanceOf(address(this));
        paymentToken.safeTransfer(sablier, balance);
    }

    // Getter for the next token ID to be minted
    function getNextTokenId() external view returns (uint256) {
        return _nextTokenId;
    }

    // Getter for free mint claimed status
    function isFreeMintClaimed(address account) external view returns (bool) {
        return _freeMintClaimed[account];
    }

    // Getter for discount mint claimed status
    function isDiscountMintClaimed(address account) external view returns (bool) {
        return _discountMintClaimed[account];
    }
}
