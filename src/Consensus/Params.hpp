// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_VERIFY_HPP
#define SPHINX_VERIFY_HPP

#include <map>
#include <vector>
#include <chrono>
#include <limits>
#include <Hash.hpp>
#include "Consensus.hpp"

namespace SPHINXConsensus {

enum CustomDeployment : int16_t {
    DEPLOYMENT_HEIGHT_INCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_MY_FEATURE, // Your custom deployment
};

constexpr bool ValidCustomDeployment(CustomDeployment dep) {
    return dep <= DEPLOYMENT_MY_FEATURE; // Update the latest deployment
}

enum CustomDeploymentPos : uint16_t {
    DEPLOYMENT_TEST_DUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot
    MAX_CUSTOM_DEPLOYMENTS
};

constexpr bool ValidCustomDeployment(CustomDeploymentPos dep) {
    return dep < MAX_CUSTOM_DEPLOYMENTS;
}

struct CustomDeploymentInfo {
    int bit{28};
    int64_t nStartTime{ALWAYS_ACTIVE}; // Use custom value if needed
    int64_t nTimeout{NO_TIMEOUT}; // Use custom value if needed
    int min_activation_height{0};

    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

struct CustomParams {
    SPHINXHash::SPHINX_256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    std::map<SPHINXHash::SPHINX_256, uint32_t> script_flag_exceptions;
    int customDeploymentHeightIncb;
    SPHINXHash::SPHINX_256 customDeploymentHashIncb;
    int customDeploymentHeightCLTV;
    int customDeploymentHeightDerSig;
    int customDeploymentHeightCSV;
    int customDeploymentHeightMyFeature; // Update with custom deployment
    int customMinBIP9WarningHeight;
    uint32_t customRuleChangeActivationThreshold;
    uint32_t customMinerConfirmationWindow;
    CustomDeploymentInfo vCustomDeployments[MAX_CUSTOM_DEPLOYMENTS];
    SPHINXHash::SPHINX_256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const {
        return nPowTargetTimespan / nPowTargetSpacing;
    }
    SPHINXHash::SPHINX_256 nMinimumChainWork;
    SPHINXHash::SPHINX_256 defaultAssumeValid;
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int CustomDeploymentHeight(CustomDeployment dep) const {
        switch (dep) {
            case DEPLOYMENT_HEIGHT_INCB:
                return customDeploymentHeightIncb;
            case DEPLOYMENT_CLTV:
                return customDeploymentHeightCLTV;
            case DEPLOYMENT_DERSIG:
                return customDeploymentHeightDerSig;
            case DEPLOYMENT_CSV:
                return customDeploymentHeightCSV;
            case DEPLOYMENT_MY_FEATURE: // Update with your custom deployment
                return customDeploymentHeightMyFeature; // Provide your custom height
        }
        return std::numeric_limits<int>::max();
    }
};

} // namespace SPHINXConsensus
