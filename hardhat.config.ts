import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox-viem";
import "@nomiclabs/hardhat-waffle";

const config: HardhatUserConfig = {
  solidity: "0.8.20",
};

export default config;
