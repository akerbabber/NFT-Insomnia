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
    InvalidDiscountSignature,
    IERC20
} from "../src/MultiUtilityNft.sol";
import {PaymentToken} from "../src/PaymentToken.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ISablierLockup} from "v2-core/interfaces/ISablierLockup.sol";
import {CompleteMerkle} from "murky/src/CompleteMerkle.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";

contract MultiUtilityNftTest is Test {
    struct Data {
        // Helper struct because of stack too deep
        uint256 userNftCount;
        uint256 nextTokenId;
        uint256 userBalanceBefore;
        uint256 contractBalanceBefore;
    }

    string MAINNET_RPC_URL = "https://eth.llamarpc.com";

    MultiUtilityNft nft;
    IERC20 paymentToken;
    ISablierLockup sablierLockup;
    // create owner wallet
    Vm.Wallet owner;
    address ownerAddr;

    // create an array of 30 user wallets
    Vm.Wallet[] users;

    // Merkle generation contract lib
    CompleteMerkle merkle = new CompleteMerkle();

    // Merle trees leaves
    bytes32[] phase1Leaves;
    bytes32[] phase2Leaves;

    // Set test phase timestamps.
    uint256 phase1End = block.timestamp + 1 weeks;
    uint256 phase2End = block.timestamp + 2 weeks;
    uint256 mintEnd = block.timestamp + 3 weeks;
    bytes32 rootPhase1;
    bytes32 rootPhase2;

    // Typehash used by the NFT contract.
    bytes32 constant DISCOUNT_MINT_TYPEHASH = keccak256("DiscountMint(address minter,uint256 nonce)");

    function setUp() public {
        owner = vm.createWallet(vm.randomUint());
        ownerAddr = owner.addr;
        // Set up 30 user wallets.
        for (uint256 i = 0; i < 30; i++) {
            users.push(vm.createWallet(vm.randomUint()));
        }
        // create two merkle trees for phase1 and phase2, with 10 leaves each
        for (uint256 i = 0; i < 10; i++) {
            phase1Leaves.push(keccak256(bytes.concat(keccak256(abi.encode(users[i].addr)))));
            phase2Leaves.push(keccak256(bytes.concat(keccak256(abi.encode(users[i + 10].addr)))));
        }
        rootPhase1 = merkle.getRoot(phase1Leaves);
        rootPhase2 = merkle.getRoot(phase2Leaves);
        paymentToken = IERC20(address(new PaymentToken()));
        sablierLockup = ISablierLockup(0x7C01AA3783577E15fD7e272443D44B92d5b21056); // Mainnet SablierLockup address
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
    }

    // Constructor Tests
    function testConstructorSetsImmutablesVariablesAndConstants() public {
        assertEq(nft.phase1End(), phase1End);
        assertEq(nft.phase2End(), phase2End);
        assertEq(nft.mintEnd(), mintEnd);
        assertEq(nft.merkleRootPhase1(), rootPhase1);
        assertEq(nft.merkleRootPhase2(), rootPhase2);
        assertEq(nft.discountPrice(), 10 ether);
        assertEq(nft.fullPrice(), 20 ether);
        assertEq(address(nft.paymentToken()), address(paymentToken));
        assertEq(address(nft.sablierLockup()), address(sablierLockup));
        assertEq(nft.VESTING_DURATION(), 365 days);
        assertEq(nft.DISCOUNT_MINT_TYPEHASH(), DISCOUNT_MINT_TYPEHASH);
        assertEq(nft.getNextTokenId(), 0);
        assertEq(nft.owner(), ownerAddr);
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

    function testInvalidConstructorMintEndBeforePhase1() public {
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
            phase1End // mintEnd <= phase1End
        );
    }

    // getCurrentMintPhase Tests
    function testGetCurrentMintPhase() public {
        // Accounting for lteq timestamp comparisons.
        skip(1 seconds);
        // FreeMint: block.timestamp <= phase1End
        assertEq(uint256(nft.getCurrentMintPhase()), uint256(MintPhase.FreeMint));
        // DiscountMint: phase1End < timestamp <= phase2End
        skip(1 weeks);
        assertEq(uint256(nft.getCurrentMintPhase()), uint256(MintPhase.DiscountMint));
        // FullMint: phase2End < timestamp < mintEnd
        skip(1 weeks);
        assertEq(uint256(nft.getCurrentMintPhase()), uint256(MintPhase.FullMint));
        // MintOver: timestamp >= mintEnd
        skip(1 weeks);
        assertEq(uint256(nft.getCurrentMintPhase()), uint256(MintPhase.MintOver));
    }

    // mintPhase1 Tests
    function testMintPhase1Valid() public {
        // For every user in the first 10, which are part of phase1, mint a free NFT.
        for (uint256 i = 0; i < 10; i++) {
            vm.startPrank(users[i].addr);
            assertTrue(
                MerkleProof.verify(
                    merkle.getProof(phase1Leaves, i),
                    rootPhase1,
                    keccak256(bytes.concat(keccak256(abi.encode(users[i].addr))))
                )
            );
            uint256 nextTokenId = nft.getNextTokenId();
            uint256 userNftCount = nft.balanceOf(users[i].addr);
            nft.mintPhase1(merkle.getProof(phase1Leaves, i));
            assertTrue(nft.isFreeMintClaimed(users[i].addr));
            assertEq(nextTokenId + 1, nft.getNextTokenId());
            assertEq(userNftCount + 1, nft.balanceOf(users[i].addr));
            vm.stopPrank();
        }
    }

    function testMintPhase1AlreadyClaimed() public {
        // for every user in the first 10, which are part of phase1, mint a free NFT,
        // then try to mint again, it should revert.
        for (uint256 i = 0; i < 10; i++) {
            vm.startPrank(users[i].addr);
            bytes32[] memory proof = merkle.getProof(phase1Leaves, i);
            nft.mintPhase1(proof);
            assertTrue(nft.isFreeMintClaimed(users[i].addr));
            vm.expectRevert(AlreadyClaimedFreeMint.selector);
            nft.mintPhase1(proof);
            vm.stopPrank();
        }
    }

    function testMintPhase1InvalidMerkleProof() public {
        // pick all users from phase2, which are not part of phase1, and try to mint, it should revert.

        for (uint256 i = 0; i < 10; i++) {
            vm.startPrank(users[i + 10].addr);
            bytes32[] memory proof = merkle.getProof(phase2Leaves, i);
            vm.expectRevert(NotWhitelisted.selector);
            nft.mintPhase1(proof);
        }
    }

    function testMintPhase1AfterPhase1End() public {
        // pick all users from phase1, which are part of phase1, and try to mint after phase1End, it should revert.
        skip(1 weeks + 1 seconds);
        for (uint256 i = 0; i < 10; i++) {
            vm.startPrank(users[i].addr);
            bytes32[] memory proof = merkle.getProof(phase1Leaves, i);
            vm.expectRevert(InvalidPhase.selector);
            nft.mintPhase1(proof);
        }
    }

    // mintPhase2 Tests
    function testMintPhase2Valid() public {
        // Test all users from phase2, generate a valid signature for each of them.
        // Set phase2 window.
        skip(1 weeks + 1 seconds);
        for (uint256 i = 0; i < 10; i++) {
            address user = users[i + 10].addr;
            uint256 nonce = nft.nonces(user);
            bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
            bytes32 domainSeparator = _computeDomainSeparator(address(nft));
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, digest);
            // generate a valid phase2 merkle proof
            assertTrue(
                MerkleProof.verify(
                    merkle.getProof(phase2Leaves, i), rootPhase2, keccak256(bytes.concat(keccak256(abi.encode(user))))
                )
            );
            bytes32[] memory proof = merkle.getProof(phase2Leaves, i);
            vm.startPrank(user);
            PaymentToken(address(paymentToken)).mint(user, 10 ether);
            paymentToken.approve(address(nft), 10 ether);
            Data memory data;
            data.userNftCount = nft.balanceOf(user);
            data.nextTokenId = nft.getNextTokenId();
            data.userBalanceBefore = paymentToken.balanceOf(user);
            data.contractBalanceBefore = paymentToken.balanceOf(address(nft));
            nft.mintPhase2(proof, v, r, s);
            assertEq(data.userBalanceBefore - 10 ether, paymentToken.balanceOf(user));
            assertEq(data.contractBalanceBefore + 10 ether, paymentToken.balanceOf(address(nft)));
            assertEq(data.nextTokenId + 1, nft.getNextTokenId());
            assertEq(data.userNftCount + 1, nft.balanceOf(user));
            vm.stopPrank();
            assertTrue(nft.isDiscountMintClaimed(user));
        }
    }

    function testMintPhase2RevertOutsidePhase2() public {
        // test all users from phase2, generate a valid signature for each of them.
        // Start from phase1, then skip to phase2End, then try to mint, should always revert.
        for (uint256 j = 0; j < 2; j++) {
            for (uint256 i = 0; i < 10; i++) {
                address user = users[i + 10].addr;
                uint256 nonce = nft.nonces(user);
                bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
                bytes32 domainSeparator = _computeDomainSeparator(address(nft));
                bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, digest);
                // generate a valid phase2 merkle proof
                assertTrue(
                    MerkleProof.verify(
                        merkle.getProof(phase2Leaves, i),
                        rootPhase2,
                        keccak256(bytes.concat(keccak256(abi.encode(user))))
                    )
                );
                bytes32[] memory proof = merkle.getProof(phase2Leaves, i);
                vm.startPrank(user);
                PaymentToken(address(paymentToken)).mint(user, 10 ether);
                paymentToken.approve(address(nft), 10 ether);
                vm.expectRevert(InvalidPhase.selector);
                nft.mintPhase2(proof, v, r, s);
                vm.stopPrank();
            }
            skip(2 weeks + 1 seconds);
        }
    }

    function testMintPhase2AlreadyClaimed() public {
        testMintPhase2Valid();
        // Test all users from phase2, generate a valid signature for each of them.
        // All users should already have claimed, so it should revert.
        for (uint256 i = 0; i < 10; i++) {
            address user = users[i + 10].addr;
            uint256 nonce = nft.nonces(user);
            bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
            bytes32 domainSeparator = _computeDomainSeparator(address(nft));
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, digest);
            // generate a valid phase2 merkle proof
            assertTrue(
                MerkleProof.verify(
                    merkle.getProof(phase2Leaves, i), rootPhase2, keccak256(bytes.concat(keccak256(abi.encode(user))))
                )
            );
            bytes32[] memory proof = merkle.getProof(phase2Leaves, i);
            vm.startPrank(user);
            PaymentToken(address(paymentToken)).mint(user, 10 ether);
            paymentToken.approve(address(nft), 10 ether);
            vm.expectRevert(AlreadyClaimedDiscountMint.selector);
            nft.mintPhase2(proof, v, r, s);
            vm.stopPrank();
        }
    }

    function testMintPhase2InvalidMerkleProof() public {
        // Test all users from phase1, generate a valid signature for each of them.
        // All users should have invalid merkle proof, so it should revert.
        skip(1 weeks + 1 seconds);
        for (uint256 i = 0; i < 10; i++) {
            address user = users[i].addr;
            uint256 nonce = nft.nonces(user);
            bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
            bytes32 domainSeparator = _computeDomainSeparator(address(nft));
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, digest);
            // generate a valid phase2 merkle proof
            assertTrue(
                MerkleProof.verify(
                    merkle.getProof(phase1Leaves, i), rootPhase1, keccak256(bytes.concat(keccak256(abi.encode(user))))
                )
            );
            bytes32[] memory proof = merkle.getProof(phase1Leaves, i);
            vm.startPrank(user);
            PaymentToken(address(paymentToken)).mint(user, 10 ether);
            paymentToken.approve(address(nft), 10 ether);
            vm.expectRevert(NotWhitelisted.selector);
            nft.mintPhase2(proof, v, r, s);
            vm.stopPrank();
        }
    }

    function testMintPhase2InvalidDiscountSignature() public {
        // Test all users from phase2, generate an invalid signature for each of them by incrementing the nonce.
        // All users should have invalid signature, so it should revert.
        skip(1 weeks + 1 seconds);
        for (uint256 i = 0; i < 10; i++) {
            address user = users[i + 10].addr;
            uint256 nonce = nft.nonces(user) + 1;
            bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
            bytes32 domainSeparator = _computeDomainSeparator(address(nft));
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, digest);
            // generate a valid phase2 merkle proof
            assertTrue(
                MerkleProof.verify(
                    merkle.getProof(phase2Leaves, i), rootPhase2, keccak256(bytes.concat(keccak256(abi.encode(user))))
                )
            );
            bytes32[] memory proof = merkle.getProof(phase2Leaves, i);
            vm.startPrank(user);
            PaymentToken(address(paymentToken)).mint(user, 10 ether);
            paymentToken.approve(address(nft), 10 ether);
            vm.expectRevert(InvalidDiscountSignature.selector);
            nft.mintPhase2(proof, v, r, s);
            vm.stopPrank();
        }
    }

    function testMintPhase2ReplayedDiscountSignature() public {
        // Test all users from phase2, generate a valid signature for each of them.
        // Simulate replay attack by reusing the same signature by a malicious actor, this malicious actor is a whitelisted user.
        // The malicious actor will use a valid merkle proof, but the signature will be replayed.
        // We should test the replay attack done when the attacker intercepts the signature from the mempool.
        // And also test the replay attack done when the attacker reads the signature from the blockchain.
        skip(1 weeks + 1 seconds);
        Vm.Wallet memory attacker = users[10];
        for (uint256 i = 1; i < 10; i++) {
            address user = users[i + 10].addr;
            uint256 nonce = nft.nonces(user);
            bytes32 structHash = keccak256(abi.encode(DISCOUNT_MINT_TYPEHASH, user, nonce));
            bytes32 domainSeparator = _computeDomainSeparator(address(nft));
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, digest);
            // generate a valid phase2 merkle proof
            assertTrue(
                MerkleProof.verify(
                    merkle.getProof(phase2Leaves, i), rootPhase2, keccak256(bytes.concat(keccak256(abi.encode(user))))
                )
            );
            bytes32[] memory proof = merkle.getProof(phase2Leaves, i);
            bytes32[] memory proofAttacker = merkle.getProof(phase2Leaves, 0);

            // Replay attack from mempool
            vm.startPrank(attacker.addr);
            vm.expectRevert(InvalidDiscountSignature.selector);
            nft.mintPhase2(proofAttacker, v, r, s);
            vm.stopPrank();
            // User should still be able to mint.
            vm.startPrank(user);
            PaymentToken(address(paymentToken)).mint(user, 10 ether);
            paymentToken.approve(address(nft), 10 ether);
            nft.mintPhase2(proof, v, r, s);
            vm.stopPrank();
            // Replay attack from blockchain
            vm.startPrank(attacker.addr);
            vm.expectRevert(InvalidDiscountSignature.selector);
            nft.mintPhase2(proofAttacker, v, r, s);
            vm.stopPrank();
        }
    }

    // mintPhase3 Tests
    function testMintPhase3Valid() public {
        // all users should be able to mint in phase 3 for an arbitrary amount of times
        skip(2 weeks + 1 seconds);
        for (uint256 i = 0; i < 30; i++) {
            vm.startPrank(users[i].addr);
            PaymentToken(address(paymentToken)).mint(users[i].addr, 20 ether);
            paymentToken.approve(address(nft), 20 ether);
            // check next token id and balance before minting
            uint256 nextTokenId = nft.getNextTokenId();
            uint256 balanceBefore = paymentToken.balanceOf(address(nft));
            uint256 balanceBeforeUser = paymentToken.balanceOf(users[i].addr);
            uint256 userNftCount = nft.balanceOf(users[i].addr);
            nft.mintPhase3();
            // check next token id and balance after minting
            uint256 balanceAfter = paymentToken.balanceOf(address(nft));
            assertEq(balanceBefore + 20 ether, balanceAfter);
            assertEq(nextTokenId + 1, nft.getNextTokenId());
            assertEq(balanceBeforeUser - 20 ether, paymentToken.balanceOf(users[i].addr));
            assertEq(userNftCount + 1, nft.balanceOf(users[i].addr));
            vm.stopPrank();
        }
    }

    function testMintPhase3RevertTooEarly() public {
        // all users should try to mint phase 3 in each phase before the phase starts, should revert
        skip(1 seconds);
        for (uint256 y = 0; y < 2; y++) {
            for (uint256 i = 0; i < 30; i++) {
                vm.startPrank(users[i].addr);
                vm.expectRevert(InvalidPhase.selector);
                nft.mintPhase3();
                vm.stopPrank();
            }
            skip(1 weeks);
        }
    }

    function testMintPhase3RevertAfterMintEnd() public {
        // all users should try to mint phase 3 after mint end, should revert
        skip(3 weeks);
        for (uint256 i = 0; i < 30; i++) {
            vm.startPrank(users[i].addr);
            vm.expectRevert(MintingPeriodOver.selector);
            nft.mintPhase3();
            vm.stopPrank();
        }
    }

    function testLockFundsRevertBeforeMintEnd() public {
        skip(3 weeks - 1 seconds); // skip to one second before mint end
        vm.startPrank(ownerAddr);
        vm.expectRevert(MintingPeriodNotOver.selector);
        nft.lockFundsLinearlyOnSablierFor356Days();
        vm.stopPrank();
    }

    function testLockFundsRevertNonOwner() public {
        skip(3 weeks + 1 seconds);
        vm.prank(users[0].addr);
        vm.expectRevert();
        nft.lockFundsLinearlyOnSablierFor356Days();
    }

    // Getter Function Tests
    function testGetNextTokenIdAndClaimedStatuses() public {
        testMintPhase1Valid();
        testMintPhase2Valid();
        rewind(1 weeks + 1 seconds); // rewinding because each test is independent, and by doing them in the same test, we are accumulating skips
        testMintPhase3Valid();
        for (uint256 i = 0; i < 20; i++) {
            assertEq(nft.isFreeMintClaimed(users[i].addr), i < 10);
            assertEq(nft.isDiscountMintClaimed(users[i].addr), i >= 10 && i < 20);
        }
        assertEq(nft.getNextTokenId(), 50);
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
