import "@nomicfoundation/hardhat-toolbox";
import { HardhatUserConfig } from "hardhat/config";

// Hardhat project for the Railgun Paladin domain's own Solidity — currently the
// RailgunFactory registration wrapper and the IPaladinContractRegistry interface.
// The real RailgunSmartWallet contract and the joinsplit circuit artifacts are
// produced elsewhere (see copy-railgun-artifacts.sh / extract-circuits.sh).
const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
};

export default config;
