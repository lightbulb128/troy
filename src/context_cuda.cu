#include "context_cuda.cuh"

namespace troy {

    void SEALContextCuda::initialize(const SEALContext& context) {
        for (auto& pair: context.context_data_map_) {
            context_data_map_.emplace(std::make_pair(
                pair.first,
                std::make_shared<ContextDataCuda>(std::move(ContextDataCuda(*pair.second)))
            ));
        }
        // re-establish the chain
        for (auto& pair: context.context_data_map_) {
            ParmsID current_id = pair.first;
            auto prev = pair.second->prevContextData();
            if (prev) {
                context_data_map_.at(current_id)->prev_context_data_
                    = context_data_map_.at(prev->parmsID());
            }
            auto next = pair.second->nextContextData();
            if (next) {
                context_data_map_.at(current_id)->next_context_data_
                    = context_data_map_.at(next->parmsID());
            }
        }
        key_parms_id_ = context.keyParmsID();
        first_parms_id_ = context.firstParmsID();
        last_parms_id_ = context.lastParmsID();
        using_keyswitching_ = context.using_keyswitching();
    }

    SEALContextCuda::ContextDataCuda::ContextDataCuda(const SEALContext::ContextData& contextData):
        qualifiers_(contextData.qualifiers()),
        parms_(contextData.parms()),
        total_coeff_modulus_bit_count_(contextData.totalCoeffModulusBitCount()),
        plain_upper_half_threshold_(contextData.plainUpperHalfThreshold()),
        coeff_modulus_mod_plain_modulus_(contextData.coeffModulusModPlainModulus()),
        prev_context_data_(),
        next_context_data_(nullptr),
        chain_index_(contextData.chainIndex()),
        total_coeff_modulus_(contextData.total_coeff_modulus_),
        coeff_div_plain_modulus_(contextData.coeff_div_plain_modulus_),
        plain_upper_half_increment_(contextData.plain_upper_half_increment_),
        upper_half_threshold_(contextData.upper_half_threshold_),
        upper_half_increment_(contextData.upper_half_increment_)
    { 
        rns_tool_ = new util::RNSToolCuda(*contextData.rns_tool_);
        size_t n = contextData.small_ntt_tables_.size();
        small_ntt_tables_support_ = util::HostArray<util::NTTTablesCuda>(n);
        for (size_t i = 0; i < n; i++) {
            small_ntt_tables_support_[i] = util::NTTTablesCuda(contextData.small_ntt_tables_[i]);
        }
        small_ntt_tables_ = util::DeviceArray(small_ntt_tables_support_);

        n = contextData.plain_ntt_tables_.size();
        plain_ntt_tables_support_ = util::HostArray<util::NTTTablesCuda>(n);
        for (size_t i = 0; i < n; i++) {
            plain_ntt_tables_support_[i] = util::NTTTablesCuda(contextData.plain_ntt_tables_[i]);
        }
        plain_ntt_tables_ = util::DeviceArray(plain_ntt_tables_support_);
        galois_tool_ = new util::GaloisToolCuda(util::getPowerOfTwo(contextData.parms_.polyModulusDegree()));
    }
    
}