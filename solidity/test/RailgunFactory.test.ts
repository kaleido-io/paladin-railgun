import { expect } from "chai";
import { ethers } from "hardhat";

// The RailgunFactory is the Paladin registration wrapper: it holds a
// pre-deployed RailgunSmartWallet address and, on deploy(...), announces it to
// the off-chain domain by emitting PaladinRegisterSmartContract_V0.
describe("RailgunFactory", function () {
  async function deployFactory() {
    const [deployer, implementation, initialOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("RailgunFactory");
    const factory = await Factory.deploy(implementation.address);
    await factory.waitForDeployment();
    return { factory, deployer, implementation, initialOwner };
  }

  it("stores the implementation address", async function () {
    const { factory, implementation } = await deployFactory();
    expect(await factory.implementation()).to.equal(implementation.address);
  });

  it("emits PaladinRegisterSmartContract_V0 announcing the implementation", async function () {
    const { factory, implementation, initialOwner } = await deployFactory();
    const txId = ethers.hexlify(ethers.randomBytes(32));
    const config = "0x0001000200030004"; // stand-in for the ABI-encoded DomainInstanceConfig

    await expect(
      factory.deploy(txId, "Railgun", "Test Railgun", "RAIL", initialOwner.address, config),
    )
      .to.emit(factory, "PaladinRegisterSmartContract_V0")
      .withArgs(txId, implementation.address, config);
  });

  it("registers the same implementation for every deploy and forwards config verbatim", async function () {
    const { factory, implementation, initialOwner } = await deployFactory();

    const txId1 = ethers.hexlify(ethers.randomBytes(32));
    const txId2 = ethers.hexlify(ethers.randomBytes(32));

    await expect(factory.deploy(txId1, "A", "A", "A", initialOwner.address, "0x"))
      .to.emit(factory, "PaladinRegisterSmartContract_V0")
      .withArgs(txId1, implementation.address, "0x");

    await expect(factory.deploy(txId2, "B", "B", "B", initialOwner.address, "0xdeadbeef"))
      .to.emit(factory, "PaladinRegisterSmartContract_V0")
      .withArgs(txId2, implementation.address, "0xdeadbeef");
  });

  it("emits with the submitter-determined transaction id (indexed)", async function () {
    const { factory, initialOwner } = await deployFactory();
    const txId = ethers.zeroPadValue("0x1234", 32);

    const tx = await factory.deploy(txId, "Railgun", "Test", "RAIL", initialOwner.address, "0x");
    const receipt = await tx.wait();

    const ev = receipt!.logs
      .map((l) => {
        try {
          return factory.interface.parseLog(l);
        } catch {
          return null;
        }
      })
      .find((p) => p?.name === "PaladinRegisterSmartContract_V0");

    expect(ev, "PaladinRegisterSmartContract_V0 not found").to.not.equal(null);
    expect(ev!.args.txId).to.equal(txId);
  });
});
