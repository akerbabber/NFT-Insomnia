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
    string MAINNET_RPC_URL = "https://eth.blockrazor.xyz";

    MultiUtilityNft nft;
    IERC20 paymentToken;
    ISablierLockup sablierLockup;
    // create owner wallet
    Vm.Wallet owner;
    address ownerAddr;

    // create an array of 30 user wallets
    Vm.Wallet[] users;

    // Merkle generation contract lib
    CompleteMerkle merkle;

    // Merle trees leaves
    bytes32[] phase1Leaves;
    bytes32[] phase2Leaves;

    // Set test phase timestamps.
    uint256 phase1End;
    uint256 phase2End;
    uint256 mintEnd;
    bytes32 rootPhase1;
    bytes32 rootPhase2;

    // Sablier stream id.
    uint256 streamId;
    // Sablier lock start time.
    uint256 lockStartTime;

    // Typehash used by the NFT contract.
    bytes32 constant DISCOUNT_MINT_TYPEHASH = keccak256("DiscountMint(address minter,uint256 nonce)");

    function setUp() public {
        uint256 mainnetFork = vm.createFork(MAINNET_RPC_URL);
        vm.selectFork(mainnetFork);
        merkle = new CompleteMerkle();
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
        phase1End = block.timestamp + 1 weeks;
        phase2End = block.timestamp + 2 weeks;
        mintEnd = block.timestamp + 3 weeks;
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
            nft.mintPhase1(merkle.getProof(phase1Leaves, i));
            assertTrue(nft.isFreeMintClaimed(users[i].addr));
            vm.stopPrank();
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
            nft.mintPhase2(proof, v, r, s);
            vm.stopPrank();
            assertTrue(nft.isDiscountMintClaimed(user));
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
            nft.mintPhase3();
            vm.stopPrank();
        }
    }

    // lockFundsLinearlyOnSablierFor356Days Tests
    function testLockFundsSuccess() public {
        testMintPhase1Valid();
        testMintPhase2Valid();
        rewind(1 weeks + 1 seconds);
        testMintPhase3Valid();
        skip(1 weeks + 1 seconds);
        assertEq(paymentToken.balanceOf(address(nft)), 700 ether); // 10 ethers * 10 + 20 ethers * 30
        vm.recordLogs();
        vm.startPrank(ownerAddr);
        nft.lockFundsLinearlyOnSablierFor356Days();

        vm.stopPrank();
        Vm.Log[] memory entries = vm.getRecordedLogs();
        // get the stream id from the logs
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].topics[0] == 0x63dc52ab7611635167bb9f73f49350010862702e8559f7db4b3bdf9a93ca6513) {
                // decode the stream id from the logs
                (streamId,) = abi.decode(entries[i].data, (uint256, uint256));
                break;
            }
        }
        assertEq(paymentToken.balanceOf(address(nft)), 0);
    }

    function testProperLinearVesting() public {
        testLockFundsSuccess();
        // Check if the funds are locked properly, check the stream balance each day.
        for (uint256 i = 0; i < 356; i++) {
            uint256 withdrawable = sablierLockup.withdrawableAmountOf(streamId);
            // Approximate the equality to the last 2 decimal places. Probably sablier math accounts for the remainder and we dont.
            assertApproxEqRel(withdrawable, 700 ether * (i) / 365, 100);
            skip(1 days);
        }
    }

    function testWithdrawFunds() public {
        testProperLinearVesting();
        // Withdraw all funds after 356 days.
        skip(356 days + 1 seconds);
        uint256 withdrawable = sablierLockup.withdrawableAmountOf(streamId);
        vm.startPrank(ownerAddr);
        sablierLockup.withdrawMax(streamId, ownerAddr);
        vm.stopPrank();
        assertEq(paymentToken.balanceOf(ownerAddr), 700 ether);
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
