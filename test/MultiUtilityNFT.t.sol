// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console, Vm} from "forge-std/Test.sol";
import {
    MultiUtilityNft,
    MintPhase,
    InvalidPhase,
    AlreadyClaimedFreeMint,
    NotWhitelisted,
    InvalidPhaseOrder,
    MintingPeriodOver,
    MintingPeriodNotOver,
    AlreadyClaimedDiscountMint,
    NotEligibleForDiscountMint,
    InvalidDiscountSignature
} from "../src/MultiUtilityNft.sol";
import {PaymentToken} from "../src/PaymentToken.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ISablierLockup} from "v2-core/interfaces/ISablierLockup.sol";

contract MultiUtilityNftTest is Test {
    MultiUtilityNft nft;
    IERC20 paymentToken;
    ISablierLockup sablierLockup;
    // create owner wallet
    Vm.Wallet owner;

    // create an array of 30 user wallets
    Vm.Wallet[30] users = new Vm.Wallet[](30);

    // Set test phase timestamps.
    uint256 phase1End = block.timestamp;
    uint256 phase2End = block.timestamp + 1 weeks;
    uint256 mintEnd = block.timestamp + 2 weeks;
    bytes32 rootPhase1;
    bytes32 rootPhase2;

    // Typehash used by the NFT contract.
    bytes32 constant DISCOUNT_MINT_TYPEHASH = keccak256("DiscountMint(address minter,uint256 nonce)");

    function setUp() public {
        owner = vm.createWallet();
        ownerAddr = owner.addr;
        // Set up 30 user wallets.
        for (uint256 i = 0; i < 30; i++) {
            users[i] = vm.createWallet();
        }
        // For testing, set merkle roots as the hash of the address.
        rootPhase1 = keccak256(abi.encodePacked(address(0xBEEF)));
        rootPhase2 = keccak256(abi.encodePacked(address(0xCAFE)));
        paymentToken = new FakeERC20();
        sablierLockup = new FakeSablierLockup();
        // Deploy NFT with owner as ownerAddr.
        vm.prank(ownerAddr);
        nft = new MultiUtilityNft(
            ownerAddr,
            IERC20(address(paymentToken)),
            address(sablierLockup),
            rootPhase1,
            rootPhase2,
            10 ether,
            20 ether,
            phase1End,
            phase2End,
            mintEnd
        );
        // Mint tokens for discount/full mint payments.
        paymentToken.mint(address(this), 100 ether);
        // Approve NFT contract spending.
        paymentToken.approve(address(nft), 100 ether);
    }

    // Constructor Tests
    function testConstructorSetsImmutables() public {
        assertEq(nft.phase1End(), phase1End);
        assertEq(nft.phase2End(), phase2End);
        assertEq(nft.mintEnd(), mintEnd);
    }

    function testInvalidConstructorPhaseOrder() public {
        vm.prank(ownerAddr);
        vm.expectRevert(InvalidPhaseOrder.selector);
        new MultiUtilityNft(
            ownerAddr,
            IERC20(address(paymentToken)),
            address(sablierLockup),
            rootPhase1,
            rootPhase2,
            10 ether,
            20 ether,
            1000,
            1000, // phase2End <= phase1End
            mintEnd
        );
    }

    function testInvalidConstructorMintEnd() public {
        vm.prank(ownerAddr);
        vm.expectRevert(InvalidPhase.selector);
        new MultiUtilityNft(
            ownerAddr,
            IERC20(address(paymentToken)),
            address(sablierLockup),
            rootPhase1,
            rootPhase2,
            10 ether,
            20 ether,
            phase1End,
            phase2End,
            phase2End // mintEnd <= phase2End
        );
    }

    // getCurrentMintPhase Tests
    function testGetCurrentMintPhase() public {
        // FreeMint: block.timestamp <= phase1End
        vm.warp(500);
        assertEq(uint256(nft.getCurrentMintPhase()), uint256(MintPhase.FreeMint));
        // DiscountMint: phase1End < timestamp <= phase2End
        vm.warp(1500);
        assertEq(uint256(nft.getCurrentMintPhase()), uint256(MintPhase.DiscountMint));
        // FullMint: phase2End < timestamp < mintEnd
        vm.warp(2500);
        assertEq(uint256(nft.getCurrentMintPhase()), uint256(MintPhase.FullMint));
        // MintOver: timestamp >= mintEnd
        vm.warp(3500);
        assertEq(uint256(nft.getCurrentMintPhase()), uint256(MintPhase.MintOver));
    }

    // mintPhase1 Tests
    function testMintPhase1Valid() public {
        // Use a test user whose merkle leaf is valid.
        address user = address(0xBEEF);
        vm.warp(500);
        vm.prank(user);
        // Valid proof is empty when root = keccak256(abi.encodePacked(user))
        nft.mintPhase1(new bytes32[](0));
        // Verify getter
        bool claimed = nft.isFreeMintClaimed(user);
        assertTrue(claimed);
    }

    function testMintPhase1AlreadyClaimed() public {
        address user = address(0xBEEF);
        vm.warp(500);
        vm.prank(user);
        nft.mintPhase1(new bytes32[](0));
        vm.prank(user);
        vm.expectRevert(AlreadyClaimedFreeMint.selector);
        nft.mintPhase1(new bytes32[](0));
    }

    function testMintPhase1InvalidMerkleProof() public {
        address user = address(0xABCD);
        vm.warp(500);
        vm.prank(user);
        vm.expectRevert(NotWhitelisted.selector);
        nft.mintPhase1(new bytes32[](0));
    }

    // mintPhase2 Tests
    function testMintPhase2Valid() public {
        // Set phase2 window.
        vm.warp(1500);
        // Use a test user with valid leaf for phase2: set root = keccak256(abi.encodePacked(user))
        address user = address(0xCAFE);
        uint256 nonce = 0; // first call: nonce is 0
        // Compute struct hash and digest.
        bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
        bytes32 domainSeparator = _computeDomainSeparator(address(nft));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        vm.prank(user);
        // Valid proof is empty because leaf = keccak256(abi.encodePacked(user))
        nft.mintPhase2(new bytes32[](0), v, r, s);
        bool claimed = nft.isDiscountMintClaimed(user);
        assertTrue(claimed);
    }

    function testMintPhase2RevertOutsidePhase2() public {
        address user = address(0xCAFE);
        // Use timestamp not in phase2 window.
        vm.warp(500);
        uint256 nonce = 0;
        bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
        bytes32 domainSeparator = _computeDomainSeparator(address(nft));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        vm.prank(user);
        vm.expectRevert(InvalidPhase.selector);
        nft.mintPhase2(new bytes32[](0), v, r, s);
    }

    function testMintPhase2AlreadyClaimed() public {
        address user = address(0xCAFE);
        vm.warp(1500);
        uint256 nonce = 0;
        bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
        bytes32 domainSeparator = _computeDomainSeparator(address(nft));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        vm.prank(user);
        nft.mintPhase2(new bytes32[](0), v, r, s);
        // Next call should revert.
        vm.warp(1501);
        uint256 newNonce = 1;
        bytes32 structHash2 = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, newNonce));
        bytes32 digest2 = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerKey, digest2);
        vm.prank(user);
        vm.expectRevert(AlreadyClaimedDiscountMint.selector);
        nft.mintPhase2(new bytes32[](0), v2, r2, s2);
    }

    function testMintPhase2InvalidMerkleProof() public {
        // Use a user with wrong merkle leaf.
        address user = address(0xBABE);
        vm.warp(1500);
        uint256 nonce = 0;
        bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
        bytes32 domainSeparator = _computeDomainSeparator(address(nft));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        vm.prank(user);
        vm.expectRevert(NotEligibleForDiscountMint.selector);
        nft.mintPhase2(new bytes32[](0), v, r, s);
    }

    function testMintPhase2InvalidDiscountSignature() public {
        address user = address(0xCAFE);
        vm.warp(1500);
        uint256 nonce = 0;
        bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
        bytes32 domainSeparator = _computeDomainSeparator(address(nft));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        // Sign with a key NOT equal to ownerKey.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, digest);
        vm.prank(user);
        vm.expectRevert(InvalidDiscountSignature.selector);
        nft.mintPhase2(new bytes32[](0), v, r, s);
    }

    // mintPhase3 Tests
    function testMintPhase3Valid() public {
        // Set timestamp in full mint window.
        vm.warp(2500);
        address user = address(0xDEAD);
        vm.prank(user);
        nft.mintPhase3();
        uint256 nextId = nft.getNextTokenId();
        assertEq(nextId, 1);
    }

    function testMintPhase3RevertTooEarly() public {
        vm.warp(1500); // still in phase2
        vm.prank(address(0xDEAD));
        vm.expectRevert(InvalidPhase.selector);
        nft.mintPhase3();
    }

    function testMintPhase3RevertAfterMintEnd() public {
        vm.warp(3500);
        vm.prank(address(0xDEAD));
        vm.expectRevert(MintingPeriodOver.selector);
        nft.mintPhase3();
    }

    // lockFundsLinearlyOnSablierFor356Days Tests
    function testLockFundsSuccess() public {
        // Ensure some balance is present in NFT contract.
        vm.warp(2500);
        address user = address(0xDEAD);
        vm.prank(user);
        nft.mintPhase3();
        // Warp past mintEnd.
        vm.warp(3500);
        vm.prank(ownerAddr);
        nft.lockFundsLinearlyOnSablierFor356Days();
    }

    function testLockFundsRevertBeforeMintEnd() public {
        vm.warp(2500);
        vm.prank(ownerAddr);
        vm.expectRevert(MintingPeriodNotOver.selector);
        nft.lockFundsLinearlyOnSablierFor356Days();
    }

    function testLockFundsRevertNonOwner() public {
        vm.warp(3500);
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        nft.lockFundsLinearlyOnSablierFor356Days();
    }

    // Getter Function Tests
    function testGetNextTokenIdAndClaimedStatuses() public {
        vm.warp(500);
        address user1 = address(0xBEEF);
        vm.prank(user1);
        nft.mintPhase1(new bytes32[](0));
        assertEq(nft.getNextTokenId(), 1);
        assertTrue(nft.isFreeMintClaimed(user1));
        address user2 = address(0xCAFE);
        vm.warp(1500);
        uint256 nonce = 0;
        bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user2, nonce));
        bytes32 domainSeparator = _computeDomainSeparator(address(nft));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        vm.prank(user2);
        nft.mintPhase2(new bytes32[](0), v, r, s);
        assertTrue(nft.isDiscountMintClaimed(user2));
        assertEq(nft.getNextTokenId(), 2);
    }

    // Helper: compute domain separator as in EIP712.
    function _computeDomainSeparator(address nftAddr) internal view returns (bytes32) {
        // The domain separator for MultiUtilityNFT constructed as EIP712("MultiUtilityNFT", "1")
        // Following the standard EIP712Domain typehash.
        bytes32 EIP712_DOMAIN_TYPEHASH =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("MultiUtilityNFT")),
                keccak256(bytes("1")),
                block.chainid,
                nftAddr
            )
        );
    }
}
