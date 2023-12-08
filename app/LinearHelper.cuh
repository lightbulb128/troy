#pragma once

#include "../src/troy_cuda.cuh"
#include <iomanip>
#include <sys/time.h>

namespace LinearHelper {

    template <typename T>
    inline void savet(std::ostream& stream, const T* obj) {
        stream.write(reinterpret_cast<const char*>(obj), sizeof(T));
    }
    
    template <typename T>
    inline void loadt(std::istream& stream, T* obj) {
        stream.read(reinterpret_cast<char*>(obj), sizeof(T));
    }

    class Cipher2d;

    class Plain2d {
        
        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;
    
    public:
        
        std::vector<std::vector<Plaintext>> data;
        std::vector<Plaintext>& operator[] (size_t id) {
            return data[id];
        }
        const std::vector<Plaintext>& operator[] (size_t id) const {
            return data[id];
        }
        Plain2d() {}

        
        Cipher2d encrypt(const troyn::Encryptor& encryptor) const;

    };

    class Cipher2d {

        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;

    public:

        std::vector<std::vector<Ciphertext>> data;
        std::vector<Ciphertext>& operator[] (size_t id) {
            return data[id];
        }
        const std::vector<Ciphertext>& operator[] (size_t id) const {
            return data[id];
        }
        Cipher2d() {}

        void save(std::ostream& stream) const {
            size_t n = data.size();
            if (n == 0) return;
            size_t m = data[0].size();
            for (size_t i = 1; i < n; i++) {
                if (data[i].size() != m) {
                    throw std::invalid_argument("Not a rectangle Conv2d.");
                }
            }
            savet(stream, &n);
            savet(stream, &m);
            for (size_t i = 0; i < n; i++) {
                for (size_t j = 0; j < m; j++) {
                    data[i][j].save(stream);
                }
            }
        }

        void load(std::istream& stream) {
            size_t n, m;
            loadt(stream, &n);
            loadt(stream, &m);
            data.clear(); data.reserve(n);
            for (size_t i = 0; i < n; i++) {
                std::vector<Ciphertext> k(m);
                for (size_t j = 0; j < m; j++) {
                    k[j].load(stream);
                }
                data.push_back(std::move(k));
            }
        }

        void load(std::istream& stream, const troyn::SEALContext& context) {
            size_t n, m;
            loadt(stream, &n);
            loadt(stream, &m);
            data.clear(); data.reserve(n);
            for (size_t i = 0; i < n; i++) {
                std::vector<Ciphertext> k(m);
                for (size_t j = 0; j < m; j++) {
                    k[j].load(stream, context);
                }
                data.push_back(std::move(k));
            }
        }

        void modSwitchToNext(const troyn::Evaluator& evaluator) {
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.modSwitchToNextInplace(data[i][j]);
                }
            }
        }

        void relinearize(const troyn::Evaluator& evaluator, const troyn::RelinKeys& rlk) {
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.relinearizeInplace(data[i][j], rlk);
                }
            }
        }
        
        void switch_key(const troyn::Evaluator& evaluator, const troyn::KSwitchKeys& ksk) {
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.applyKeySwitchingInplace(data[i][j], ksk);
                }
            }
        }

        void multiplyScalarInplace(const troyn::BatchEncoder& encoder, const troyn::Evaluator& evaluator, uint64_t scalar) {
            Plaintext p; encoder.encodePolynomial(std::vector<uint64_t>{scalar}, p);
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.multiplyPlainInplace(data[i][j], p);
                }
            }
        }

        void addInplace(
            const troyn::Evaluator& evaluator,
            const Cipher2d& x
        ) {
            if (data.size() != x.data.size()) {
                throw std::invalid_argument("Size incorrect.");
            }
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                if (data[i].size() != x[i].size()) {
                    throw std::invalid_argument("Size incorrect.");
                }
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.addInplace(data[i][j], x[i][j]);
                }
            }
        }

        void addPlainInplace(
            const troyn::Evaluator& evaluator,
            const Plain2d& x
        ) {
            if (data.size() != x.data.size()) {
                throw std::invalid_argument("Size incorrect.");
            }
            size_t n = data.size();
            for (size_t i = 0; i < n; i++) {
                if (data[i].size() != x[i].size()) {
                    throw std::invalid_argument("Size incorrect.");
                }
                size_t m = data[i].size();
                for (size_t j = 0; j < m; j++) {
                    evaluator.addPlainInplace(data[i][j], x[i][j]);
                }
            }
        }

        Cipher2d addPlain(
            const troyn::Evaluator& evaluator,
            const Plain2d& x
        ) const {
            if (data.size() != x.data.size()) {
                throw std::invalid_argument("Size incorrect.");
            }
            size_t n = data.size();
            Cipher2d ret; ret.data.reserve(n);
            for (size_t i = 0; i < n; i++) {
                if (data[i].size() != x[i].size()) {
                    throw std::invalid_argument("Size incorrect.");
                }
                size_t m = data[i].size();
                std::vector<Ciphertext> row; row.resize(m);
                for (size_t j = 0; j < m; j++) {
                    evaluator.addPlain(data[i][j], x[i][j], row[j]);
                }
                ret.data.push_back(std::move(row));
            }
            return ret;
        }

    };

    Cipher2d Plain2d::encrypt(const troyn::Encryptor& encryptor) const {
        Cipher2d ret; ret.data.reserve(data.size());
        size_t n = data.size();
        for (size_t i = 0; i < n; i++) {
            size_t m = data[i].size();
            std::vector<Ciphertext> row; row.reserve(m);
            for (size_t j = 0; j < m; j++) {
                row.push_back(encryptor.encryptSymmetric(data[i][j]));
            }
            ret.data.push_back(std::move(row));
        }
        return ret;
    }


    inline static size_t ceilDiv(size_t a, size_t b) {
        if (a%b==0) return a/b;
        return a/b+1;
    }

    class MatmulHelper {

        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;
        using GaloisKeys = troyn::GaloisKeys;

        size_t batchSize, inputDims, outputDims;
        size_t slotCount;
        size_t batchBlock, inputBlock, outputBlock;
        int objective; 
        bool packLwe;
        // 0: encrypt inputs; 1: encrypt weights
        // 2: for calculating weight gradient

        void determineBlock() {
            size_t bBest = 0, iBest = 0, oBest = 0;
            size_t cBest = 2147483647;
            if (!packLwe) {
                for (size_t b = batchSize; b >= 1; b--) {
                    size_t bc = ceilDiv(batchSize, b);
                    if (b >= slotCount) continue;
                    if (bc * 2 > cBest) continue;
                    for (size_t i = 1; i < slotCount / b; i++) {
                        size_t o = slotCount / b / i;
                        if (o > outputDims) o = outputDims;
                        if (i > inputDims) continue;
                        if (o < 1) continue;
                        size_t c = 0;
                        if (objective == 0) {
                            c = bc * (ceilDiv(inputDims, i) + ceilDiv(outputDims, o));
                        } else if (objective == 1) {
                            c = (bc + ceilDiv(inputDims, i)) * ceilDiv(outputDims, o);
                        } else if (objective == 2) {
                            c = bc * inputDims + (bc + ceilDiv(inputDims, i)) * ceilDiv(outputDims, o);
                        } else {
                            throw std::runtime_error("MatmulHelper: invalid objective");
                        }
                        if (c >= cBest) continue;
                        bBest = b; iBest = i; oBest = o; cBest = c;
                    }
                }
            } else {
                double sqrtn = std::pow(slotCount, 0.33);
                size_t i = 1; while (i * 2 < sqrtn) {i *= 2;}
                if (i > inputDims) {
                    i = 1; while (i < inputDims) i *= 2;
                }
                
                for (size_t b = 1; b <= batchSize; b++) {
                    size_t bc = ceilDiv(batchSize, b);
                    if (b > slotCount) {continue;}
                    size_t o = slotCount / b / i;
                    if (o > outputDims) {o = outputDims;}
                    if (o < 1) {continue;}
                    size_t ic = ceilDiv(inputDims, i);
                    size_t oc = ceilDiv(outputDims, o);
                    size_t c = 0;
                    if (objective == 0) {
                        c = bc * ceilDiv(inputDims, i);
                        c += ceilDiv(bc * ceilDiv(outputDims, o), i);
                    } else if (objective == 1) {
                        c = ceilDiv(outputDims, o) * ceilDiv(inputDims, i);
                        c += ceilDiv(bc * ceilDiv(outputDims, o), i);
                    } else if (objective == 2) {
                        c = bc * ceilDiv(inputDims, i);
                        c += ceilDiv(outputDims, o) * ceilDiv(inputDims, i);
                        c += ceilDiv(bc * ceilDiv(outputDims, o), i);
                    } else {
                        throw std::runtime_error("MatmulHelper: invalid objective");
                    }
                    if (c >= cBest) {continue;}
                    bBest = b; iBest = i; oBest = o; cBest = c;
                }

            }
            batchBlock = bBest;
            inputBlock = iBest;
            outputBlock = oBest;
            // printf("block (%zu, %zu, %zu) -> (%zu, %zu, %zu)\n", batchSize, inputDims, outputDims, batchBlock, inputBlock, outputBlock);
        }

        Plaintext encodeWeightSmall(
            troyn::BatchEncoder& encoder,
            const uint64_t* weights,
            size_t li, size_t ui, size_t lj, size_t uj
        ) {
            size_t slots = slotCount;
            std::vector<uint64_t> vec(inputBlock * outputBlock, 0);
            for (size_t j = lj; j < uj; j++) {
                for (size_t i = li; i < ui; i++) {
                    size_t r = (j-lj) * inputBlock + inputBlock - (i-li) - 1;
                    assert(r < slots);
                    vec[r] = weights[i * outputDims + j];
                }
            }
            Plaintext ret;
            encoder.encodePolynomial(vec, ret);
            return ret;
        }

    public:

        // Plain2d encodedWeights;

        MatmulHelper(size_t batchSize, size_t inputDims, size_t outputDims, size_t slotCount, int objective = 0, bool packLwe = true):
            batchSize(batchSize), inputDims(inputDims), outputDims(outputDims),
            slotCount(slotCount), objective(objective), packLwe(packLwe)
        {
            determineBlock();
        }

        Plain2d encodeWeights(
            troyn::BatchEncoder& encoder,
            const uint64_t* weights
        ) {
            // if (weights.size() != inputDims * outputDims) {
            //     throw std::invalid_argument("Weight size incorrect.");
            // }
            size_t height = inputDims, width = outputDims;
            size_t h = inputBlock, w = outputBlock;
            Plain2d encodedWeights;
            encodedWeights.data.clear();
            encodedWeights.data.reserve(ceilDiv(height, h));
            for (size_t li = 0; li < height; li += h) {
                size_t ui = (li + h > height) ? height : (li + h);
                std::vector<Plaintext> encodedRow; encodedRow.reserve(ceilDiv(width, w));
                for (size_t lj = 0; lj < width; lj += w) {
                    size_t uj = (lj + w > width) ? width : (lj + w);
                    encodedRow.push_back(
                        encodeWeightSmall(encoder, weights, li, ui, lj, uj)
                    );
                }
                encodedWeights.data.push_back(std::move(encodedRow));
            }
            return encodedWeights;
        }

        Plain2d encodeInputs(
            troyn::BatchEncoder& encoder,
            const uint64_t* inputs
        ) {
            // if (inputs.size() != inputDims * batchSize) {
            //     throw std::invalid_argument("Input size incorrect.");
            // }
            size_t vecsize = inputBlock;
            Plain2d ret;
            ret.data.reserve(batchSize);
            for (size_t li = 0; li < batchSize; li += batchBlock) {
                size_t ui = (li + batchBlock > batchSize) ? batchSize : li + batchBlock;
                std::vector<Plaintext> encodedRow;
                encodedRow.reserve(ceilDiv(inputDims, vecsize));
                for (size_t lj = 0; lj < inputDims; lj += vecsize) {
                    size_t uj = (lj + vecsize > inputDims) ? inputDims : lj + vecsize;
                    std::vector<uint64_t> vec(slotCount, 0);
                    for (size_t i = li; i < ui; i++)
                        for (size_t j = lj; j < uj; j++)
                            vec[(i - li) * inputBlock * outputBlock + (j - lj)] = inputs[i * inputDims + j];
                    Plaintext encoded;
                    encoder.encodePolynomial(vec, encoded);
                    encodedRow.push_back(std::move(encoded));
                }
                ret.data.push_back(std::move(encodedRow));
            }
            return ret;
        }

        Cipher2d encryptInputs(
            const troyn::Encryptor& encryptor,
            troyn::BatchEncoder& encoder, 
            const uint64_t* inputs
        ) {
            Plain2d plain = encodeInputs(encoder, inputs);
            return plain.encrypt(encryptor);
        }

        Cipher2d matmul(const troyn::Evaluator& evaluator, const Cipher2d& a, const Plain2d& w) {
            Cipher2d ret; ret.data.reserve(ceilDiv(batchSize, batchBlock));
            size_t outputVectorCount = ceilDiv(outputDims, outputBlock);
            if (a.data.size() != ceilDiv(batchSize, batchBlock)) {
                throw std::invalid_argument("Input batchsize incorrect.");
            }
            if (w.data.size() != ceilDiv(inputDims, inputBlock)) {
                throw std::invalid_argument("Weight input dimension incorrect.");
            }
            for (size_t b = 0; b < ceilDiv(batchSize, batchBlock); b++) {
                std::vector<Ciphertext> outVecs(outputVectorCount);
                for (size_t i = 0; i < w.data.size(); i++) {
                    for (size_t j = 0; j < w[i].size(); j++) {
                        Ciphertext prod;
                        evaluator.multiplyPlain(a[b][i], w[i][j], prod);
                        if (i==0) outVecs[j] = std::move(prod);
                        else {
                            evaluator.addInplace(outVecs[j], prod);
                        }
                    }
                }
                ret.data.push_back(std::move(outVecs));
            }
            return ret;
        }

        Cipher2d matmulCipher(const troyn::Evaluator& evaluator, const Cipher2d& a, const Cipher2d& w) {
            Cipher2d ret; ret.data.reserve(ceilDiv(batchSize, batchBlock));
            size_t outputVectorCount = ceilDiv(outputDims, outputBlock);
            if (a.data.size() != ceilDiv(batchSize, batchBlock)) {
                throw std::invalid_argument("Input batchsize incorrect.");
            }
            if (w.data.size() != ceilDiv(inputDims, inputBlock)) {
                throw std::invalid_argument("Weight input dimension incorrect.");
            }
            for (size_t b = 0; b < ceilDiv(batchSize, batchBlock); b++) {
                std::vector<Ciphertext> outVecs(outputVectorCount);
                for (size_t i = 0; i < w.data.size(); i++) {
                    for (size_t j = 0; j < w[i].size(); j++) {
                        Ciphertext prod;
                        evaluator.multiply(a[b][i], w[i][j], prod);
                        if (i==0) outVecs[j] = std::move(prod);
                        else {
                            evaluator.addInplace(outVecs[j], prod);
                        }
                    }
                }
                ret.data.push_back(std::move(outVecs));
            }
            return ret;
        }

        Cipher2d matmulReverse(const troyn::Evaluator& evaluator, const Plain2d& a, const Cipher2d& w) {
            Cipher2d ret; ret.data.reserve(ceilDiv(batchSize, batchBlock));
            size_t outputVectorCount = ceilDiv(outputDims, outputBlock);
            if (a.data.size() != ceilDiv(batchSize, batchBlock)) {
                throw std::invalid_argument("Input batchsize incorrect.");
            }
            if (w.data.size() != ceilDiv(inputDims, inputBlock)) {
                throw std::invalid_argument("Weight input dimension incorrect.");
            }
            for (size_t b = 0; b < ceilDiv(batchSize, batchBlock); b++) {
                std::vector<Ciphertext> outVecs(outputVectorCount);
                for (size_t i = 0; i < w.data.size(); i++) {
                    for (size_t j = 0; j < w[i].size(); j++) {
                        Ciphertext prod;
                        evaluator.multiplyPlain(w[i][j], a[b][i], prod);
                        if (i==0) outVecs[j] = std::move(prod);
                        else {
                            evaluator.addInplace(outVecs[j], prod);
                        }
                    }
                }
                ret.data.push_back(std::move(outVecs));
            }
            return ret;
        }

        Plain2d encodeOutputs(
            troyn::BatchEncoder& encoder, 
            const uint64_t* outputs
        ) {
            size_t vecsize = outputBlock;
            Plaintext pt;
            if (!this->packLwe) {
                Plain2d ret; ret.data.reserve(batchSize);
                for (size_t li = 0; li < batchSize; li += batchBlock) {
                    size_t ui = (li + batchBlock > batchSize) ? batchSize : (li + batchBlock);
                    std::vector<Plaintext> encodedRow;
                    encodedRow.reserve(ceilDiv(outputDims, vecsize));
                    for (size_t lj = 0; lj < outputDims; lj += vecsize) {
                        size_t uj = (lj + vecsize > outputDims) ? outputDims : (lj + vecsize);
                        std::vector<uint64_t> buffer(slotCount, 0);
                        for (size_t i = li; i < ui; i++)
                            for (size_t j = lj; j < uj; j++) 
                                buffer[(i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + inputBlock - 1] = outputs[i * outputDims + j];
                        encoder.encodePolynomial(buffer, pt);
                        encodedRow.push_back(std::move(pt));
                    }
                    ret.data.push_back(std::move(encodedRow));
                }
                return ret;
            } else {
                Plain2d plain2d; plain2d.data.reserve(batchSize);
                plain2d.data.push_back(std::vector<Plaintext>());
                size_t batchBlockCount = ceilDiv(this->batchSize, this->batchBlock);
                size_t outputBlockCount = ceilDiv(this->outputDims, this->outputBlock);
                auto ret = std::vector<std::vector<uint64_t>>(ceilDiv(batchBlockCount * outputBlockCount, this->inputBlock), std::vector<uint64_t>(this->slotCount, 0)); 
                size_t li = 0; size_t di = 0; while (li < this->batchSize) {
                    size_t ui = std::min(this->batchSize, li + this->batchBlock);
                    size_t lj = 0; size_t dj = 0; while (lj < this->outputDims) {
                        size_t uj = std::min(this->outputDims, lj + vecsize);
                        size_t cipherId = di * ceilDiv(this->outputDims, this->outputBlock) + dj;
                        size_t packedId = cipherId / this->inputBlock;
                        size_t packedOffset = cipherId % this->inputBlock;
                        for (size_t i = li; i < ui; i++) {
                            for (size_t j = lj; j < uj; j++) {
                                ret[packedId][(i - li) * this->inputBlock * this->outputBlock + (j - lj) * this->inputBlock + packedOffset] 
                                    = outputs[i * this->outputDims + j];
                            }
                        }
                        dj += 1;
                        lj += vecsize; 
                    }
                    di += 1;
                    li += this->batchBlock;
                }
                plain2d.data[0].reserve(ret.size());
                for (size_t i = 0; i < ret.size(); i++) {
                    encoder.encodePolynomial(ret[i], pt);
                    plain2d.data[0].push_back(std::move(pt));
                }
                return plain2d;
            }
        }

        std::vector<uint64_t> decryptOutputs(
            troyn::BatchEncoder& encoder,
            troyn::Decryptor& decryptor,
            const Cipher2d& outputs
        ) {
            std::vector<uint64_t> dec(batchSize * outputDims);
            size_t vecsize = outputBlock;
                Plaintext pt;
            if (!this->packLwe) {
                std::vector<uint64_t> buffer(slotCount);
                size_t di = 0;
                for (size_t li = 0; li < batchSize; li += batchBlock) {
                    size_t ui = (li + batchBlock > batchSize) ? batchSize : (li + batchBlock);
                    size_t dj = 0;
                    for (size_t lj = 0; lj < outputDims; lj += vecsize) {
                        size_t uj = (lj + vecsize > outputDims) ? outputDims : (lj + vecsize);
                        decryptor.decrypt(outputs[di][dj], pt);
                        encoder.decodePolynomial(pt, buffer);
                        for (size_t i = li; i < ui; i++)
                            for (size_t j = lj; j < uj; j++) 
                                dec[i * outputDims + j] = buffer[(i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + inputBlock - 1];
                        dj += 1;
                    }
                    di += 1;
                }
            } else {
                std::vector<std::vector<uint64_t>> buffer(outputs[0].size(), std::vector<uint64_t>(slotCount, 0));
                for (size_t i = 0; i < outputs.data[0].size(); i++) {
                        decryptor.decrypt(outputs[0][i], pt);
                        encoder.decodePolynomial(pt, buffer[i]);
                }
                size_t li = 0; size_t di = 0; while (li < this->batchSize) {
                    size_t ui = std::min(this->batchSize, li + this->batchBlock);
                    size_t lj = 0; size_t dj = 0; while (lj < this->outputDims) {
                        size_t uj = std::min(this->outputDims, lj + vecsize);
                        size_t cipherId = di * ceilDiv(this->outputDims, this->outputBlock) + dj;
                        size_t packedId = cipherId / this->inputBlock;
                        size_t packedOffset = cipherId % this->inputBlock;
                        for (size_t i = li; i < ui; i++) {
                            for (size_t j = lj; j < uj; j++) {
                                dec[i * outputDims + j] = buffer[packedId][(i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + packedOffset];
                            }
                        }
                        dj += 1;
                        lj += vecsize; 
                    }
                    di += 1;
                    li += this->batchBlock;
                }
            }
            return dec;
        }

        Cipher2d packOutputs(const troyn::Evaluator& evaluator, const GaloisKeys& autoKey, const Cipher2d& cipher) {
            if (!this->packLwe) {
                throw std::invalid_argument("PackLWE not enabled");
            }
            if (cipher.data.size() == 0 || cipher.data[0].size() == 0) {
                Cipher2d ret; ret.data.push_back(std::vector<Ciphertext>());
                return ret;
            }
            size_t packSlots = this->inputBlock;
            size_t totalCount = cipher.data.size() * cipher.data[0].size();
            std::vector<Ciphertext> output; output.reserve(ceilDiv(totalCount, packSlots));
            Ciphertext current; bool currentSet = false;
            size_t currentSlot = 0;
            
            size_t field_trace_logn = 0;
            size_t field_trace_n = 1;
            while (field_trace_n != slotCount / packSlots) {
                field_trace_logn += 1;
                field_trace_n *= 2;
            }

            Ciphertext buffer = cipher.data[0][0];
            Ciphertext shifted = buffer;
            for (size_t i = 0; i < cipher.data.size(); i++) {
                for (size_t j = 0; j < cipher.data[0].size(); j++) {
                    size_t shift = packSlots - 1;
                    const Ciphertext& ciphertext = cipher.data[i][j];
                    if (shift != 0) {
                        evaluator.negacyclicShift(ciphertext, 2 * slotCount - shift, buffer);
                    } else {
                        buffer = ciphertext;
                    }
                    evaluator.divideByPolyModulusDegreeInplace(buffer, slotCount / packSlots);
                    evaluator.fieldTraceInplace(buffer, autoKey, field_trace_logn);
                    shift = currentSlot;
                    if (shift != 0) {
                        evaluator.negacyclicShift(buffer, shift, shifted);
                    } else {
                        shifted = buffer;
                    }
                    if (currentSet == false) {
                        current = shifted;
                        currentSet = true;
                    } else {
                        evaluator.addInplace(current, shifted);
                    }
                    currentSlot += 1;
                    if (currentSlot == packSlots) {
                        currentSlot = 0; currentSet = false;
                        output.push_back(std::move(current));
                    }
                }
            }
            if (currentSet) {
                output.push_back(std::move(current));
            }
            Cipher2d ret; ret.data.push_back(output);
            return ret;
        }

        void serializeEncodedWeights(const Plain2d& w, std::ostream& stream) {
            size_t rows = w.data.size();
            size_t cols = w[0].size();
            if (rows == 0) throw std::invalid_argument("No rows in weight matrix.");
            if (cols == 0) throw std::invalid_argument("No columns in weight matrix.");
            for (size_t i=0; i<rows; i++) {
                if (w[i].size() != cols) throw std::invalid_argument("Weight matrix is not rectangular.");
            }
            savet(stream, &rows);
            savet(stream, &cols);
            for (size_t i = 0; i < rows; i++) {
                for (size_t j = 0; j < cols; j++) {
                    w[i][j].save(stream);
                }
            }
        }

        Plain2d deserializeEncodedWeights(std::istream& stream) {
            size_t rows, cols;
            loadt(stream, &rows);
            loadt(stream, &cols);
            Plain2d ret; ret.data.reserve(rows);
            for (size_t i = 0; i < rows; i++) {
                std::vector<Plaintext> row; row.reserve(cols);
                for (size_t j = 0; j < cols; j++) {
                    Plaintext pt;
                    pt.load(stream);
                    row.push_back(std::move(pt));
                }
                ret.data.push_back(std::move(row));
            }
            return ret;
        }

        void serializeOutputs(troy::EvaluatorCuda &evaluator, const Cipher2d& x, std::ostream& stream) {
            if (!this->packLwe) {
                size_t vecsize = outputBlock;
                Plaintext pt;
                size_t di = 0;
                for (size_t li = 0; li < batchSize; li += batchBlock) {
                    size_t ui = (li + batchBlock > batchSize) ? batchSize : (li + batchBlock);
                    size_t dj = 0;
                    for (size_t lj = 0; lj < outputDims; lj += vecsize) {
                        size_t uj = (lj + vecsize > outputDims) ? outputDims : (lj + vecsize);
                        std::vector<size_t> required((ui - li) * (uj - lj)); size_t rid = 0;
                        for (size_t i = li; i < ui; i++)
                            for (size_t j = lj; j < uj; j++) 
                                required[rid++] = (i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + inputBlock - 1;
                        x[di][dj].saveTerms(stream, evaluator, required);
                        dj += 1;
                    }
                    di += 1;
                }
            } else {
                size_t count = ceilDiv(batchSize, batchBlock) * ceilDiv(outputDims, outputBlock);
                count = ceilDiv(count, inputBlock);
                if (count != x.data[0].size()) {
                    throw std::invalid_argument("Output ciphertext count incorrect");
                }
                for (size_t i = 0; i < x.data[0].size(); i++) {
                    x[0][i].save(stream);
                }
            }
        }

        Cipher2d deserializeOutputs(troy::EvaluatorCuda &evaluator, std::istream& stream) {
            if (!this->packLwe) {
                size_t vecsize = outputBlock;
                Plaintext pt;
                Cipher2d ret; ret.data.reserve(ceilDiv(batchSize, batchBlock));
                for (size_t li = 0; li < batchSize; li += batchBlock) {
                    size_t ui = (li + batchBlock > batchSize) ? batchSize : (li + batchBlock);
                    std::vector<Ciphertext> row; row.reserve(ceilDiv(outputDims, vecsize));
                    for (size_t lj = 0; lj < outputDims; lj += vecsize) {
                        size_t uj = (lj + vecsize > outputDims) ? outputDims : (lj + vecsize);
                        std::vector<size_t> required((ui - li) * (uj - lj)); size_t rid = 0;
                        for (size_t i = li; i < ui; i++)
                            for (size_t j = lj; j < uj; j++) 
                                required[rid++] = (i - li) * inputBlock * outputBlock + (j - lj) * inputBlock + inputBlock - 1;
                        Ciphertext c;
                        c.loadTerms(stream, evaluator, required);
                        row.push_back(std::move(c));
                    }
                    ret.data.push_back(std::move(row));
                }
                return ret;
            } else {
                size_t count = ceilDiv(batchSize, batchBlock) * ceilDiv(outputDims, outputBlock);
                count = ceilDiv(count, inputBlock);
                Cipher2d ret; ret.data.push_back(std::vector<Ciphertext>());
                ret[0].reserve(count);
                for (size_t i = 0; i < count; i++) {
                    Ciphertext c; c.load(stream);
                    ret[0].push_back(std::move(c));
                }
                return ret;
            }
        }

    };

    class Conv2dHelper {

        using Plaintext = troyn::Plaintext;
        using Ciphertext = troyn::Ciphertext;

        size_t batchSize;
        size_t blockHeight, blockWidth, kernelHeight, kernelWidth;
        size_t imageHeight, imageWidth;
        size_t inputChannels, outputChannels;
        size_t blockBatch, blockInputChannels, blockOutputChannels;
        size_t slotCount;
        int objective;

    public:

        Conv2dHelper(
            size_t batchSize, 
            size_t imageHeight, size_t imageWidth, 
            size_t kernelHeight, size_t kernelWidth,
            size_t inputChannels, size_t outputChannels,
            size_t slotCount, int objective = 0
        ):
            batchSize(batchSize),
            imageHeight(imageHeight), 
            imageWidth(imageWidth), 
            kernelHeight(kernelHeight), 
            kernelWidth(kernelWidth),
            inputChannels(inputChannels),
            outputChannels(outputChannels),
            slotCount(slotCount),
            objective(objective)
        {
            size_t best = 2147483647;
            // find b, h, w, ci, co, such that minimizes (ceil(B/b)*ceil((H-kh+1)/(h-kh+1))*ceil((W-kh+1)/(h-kh+1))*(ceil(Ci/ci)+ceil(Co/co)))
            size_t bestB, bestH, bestW, bestCi, bestCo;
            for (size_t b = batchSize; b >= 1; b--) {
                size_t upper = slotCount / b;
                for (size_t h = std::min(imageHeight, upper); h >= kernelHeight; h--) {
                    size_t upper = slotCount / b / h;
                    for (size_t w = std::min(imageWidth, upper); w >= kernelWidth; w--) {
                        size_t upper = slotCount / b / h / w;
                        for (size_t co = std::min(outputChannels, upper); co >= 1; co--) {
                            size_t ci = slotCount / b / h / w / co;
                            ci = std::min(ci, inputChannels);
                            if (ci == 0) continue;
                            size_t inputCipherSize = (
                                ceilDiv(batchSize, b) * 
                                ceilDiv(imageHeight - kernelHeight + 1, h - kernelHeight + 1) * 
                                ceilDiv(imageWidth - kernelWidth + 1, w - kernelWidth + 1) * 
                                ceilDiv(inputChannels, ci)
                            );
                            size_t outputCipherSize = (
                                ceilDiv(batchSize, b) * 
                                ceilDiv(imageHeight - kernelHeight + 1, h - kernelHeight + 1) * 
                                ceilDiv(imageWidth - kernelWidth + 1, w - kernelWidth + 1) * 
                                ceilDiv(outputChannels, co)
                            );
                            size_t weightCipherSize = (
                                ceilDiv(inputChannels, ci) * 
                                ceilDiv(outputChannels, co)
                            );
                            size_t current = 0;
                            if (objective == 0) {
                                current = inputCipherSize + outputCipherSize;
                            } else if (objective == 1) {
                                current = weightCipherSize + outputCipherSize;
                            } else if (objective == 2) {
                                current = outputCipherSize + inputCipherSize + weightCipherSize;
                            } else {
                                throw std::runtime_error("Conv2dHelper: invalid objective");
                            }
                            if (current < best) {
                                best = current;
                                bestB = b;
                                bestH = h;
                                bestW = w;
                                bestCi = ci;
                                bestCo = co;
                            }
                        }
                    }
                }
            }
            blockBatch = bestB;
            blockHeight = bestH;
            blockWidth = bestW;
            blockInputChannels = bestCi;
            blockOutputChannels = bestCo;
            // printf("Conv2dHelper: blockBatch = %zu, blockHeight = %zu, blockWidth = %zu, blockInputChannels = %zu, blockOutputChannels = %zu\n", blockBatch, blockHeight, blockWidth, blockInputChannels, blockOutputChannels);
        }



        void printVector(const std::vector<uint64_t>& r) {
            std::cout << "[";
            for (size_t i = 0; i < r.size(); i++) {
                if (i!=0) std::cout << ", ";
                std::cout << r[i];
            }
            std::cout << "]" << std::endl;
        }

        void printVector(const std::vector<uint64_t>& r, size_t terms) {
            std::cout << "[";
            for (size_t i = 0; i < std::min(r.size(), terms); i++) {
                if (i!=0) std::cout << ", ";
                std::cout << r[i];
            }
            std::cout << "]" << std::endl;
        }

        Plain2d encodeWeights(
            troyn::BatchEncoder& encoder, 
            std::vector<uint64_t> weights
        ) {
            if (weights.size() != inputChannels * outputChannels * kernelHeight * kernelWidth) {
                throw std::invalid_argument("Weights shape incorrect.");
            }
            size_t blockSize = blockHeight * blockWidth;
            Plain2d encodedWeights;
            encodedWeights.data.clear();
            encodedWeights.data.reserve(ceilDiv(outputChannels, blockOutputChannels));
            for (size_t loc = 0; loc < outputChannels; loc += blockOutputChannels) {
                size_t uoc = std::min(loc + blockOutputChannels, outputChannels);
                std::vector<Plaintext> currentChannel;
                currentChannel.reserve(ceilDiv(inputChannels, blockInputChannels));
                for (size_t lic = 0; lic < inputChannels; lic += blockInputChannels) {
                    size_t uic = std::min(lic + blockInputChannels, inputChannels);
                    std::vector<uint64_t> spread(blockInputChannels * blockOutputChannels * blockHeight * blockWidth, 0);
                    for (size_t oc = loc; oc < uoc; oc++) {
                        for (size_t ic = lic; ic < uic; ic++) {
                            for (size_t ki = 0; ki < kernelHeight; ki++) {
                                for (size_t kj = 0; kj < kernelWidth; kj++) {
                                    // spread[channel_slots - 1 - (j - lic), :k_h, :k_w] = np.flip(weight[oc, j])
                                    size_t spreadIndex = (oc - loc) * blockInputChannels * blockSize + (blockInputChannels - 1 - (ic - lic)) * blockSize + ki * blockWidth + kj;
                                    size_t weightIndex = ((oc * inputChannels) + ic) * (kernelHeight * kernelWidth) + (kernelHeight - ki - 1) * kernelWidth + (kernelWidth - kj - 1);
                                    spread[spreadIndex] = weights[weightIndex];
                                }
                            }
                        }
                    }
                    Plaintext pt; encoder.encodePolynomial(spread, pt);
                    currentChannel.push_back(std::move(pt));
                }
                encodedWeights.data.push_back(std::move(currentChannel));
            }
            return encodedWeights;
        }

        size_t getTotalBatchSize() {
            size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
            size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
            size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
            return ceilDiv(batchSize, blockBatch) * sh * sw;
        }

        Plain2d encodeInputs(
            troyn::BatchEncoder& encoder, 
            const std::vector<uint64_t>& inputs
        ) {
            if (inputs.size() != batchSize * inputChannels * imageHeight * imageWidth) {
                throw std::invalid_argument("Inputs shape incorrect.");
            }
            size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
            size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
            size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
            size_t imageSize = imageHeight * imageWidth;
            size_t blockSize = blockHeight * blockWidth;
            size_t totalBatchSize = ceilDiv(batchSize, blockBatch) * sh * sw;
            Plain2d ret; ret.data.reserve(totalBatchSize);
            for (size_t lb = 0; lb < batchSize; lb += blockBatch) {
                size_t ub = std::min(lb + blockBatch, batchSize);
                for (size_t ih = 0; ih < sh; ih++) {
                    for (size_t iw = 0; iw < sw; iw++) {
                        size_t si = ih * (blockHeight - kh);
                        size_t sj = iw * (blockWidth - kw);
                        size_t ui = std::min(si + blockHeight, imageHeight);
                        size_t uj = std::min(sj + blockWidth, imageWidth);
                        std::vector<Plaintext> group; group.reserve(ceilDiv(inputChannels, blockInputChannels));
                        for (size_t lci = 0; lci < inputChannels; lci += blockInputChannels) {
                            size_t uci = std::min(lci + blockInputChannels, inputChannels);
                            std::vector<uint64_t> vec(slotCount, 0);
                            for (size_t b = 0; b < ub-lb; b++) {
                                for (size_t tci = 0; tci < uci-lci; tci++) {
                                    for (size_t ti = si; ti < ui; ti++) {
                                        for (size_t tj = sj; tj < uj; tj++) {
                                            size_t inputIndex = (lb + b) * inputChannels * imageSize + (lci + tci) * imageSize + ti * imageWidth + tj;
                                            size_t vecIndex = b * blockInputChannels * blockOutputChannels * blockSize 
                                                + tci * blockSize + (ti - si) * blockWidth + (tj - sj);
                                            // printf("inputIndex: %lu, vecIndex: %lu, b=%lu, tci=%lu,ti-si=%lu, tj-sj=%ld\n", inputIndex, vecIndex, b, tci, ti-si, tj-sj);
                                            vec[vecIndex] = inputs[inputIndex];
                                            // printf("ok inputIndex: %lu, vecIndex: %lu\n", inputIndex, vecIndex);
                                        }
                                    }
                                }
                            }
                            // printf("encode lb=%lu, ub=%lu, ih=%lu, iw=%lu, lci=%lu, uci=%lu, vecsize=%lu\n", lb, ub, ih, iw, lci, uci, vec.size());
                            Plaintext pt; encoder.encodePolynomial(vec, pt);
                            // printf("encode ok\n");
                            group.push_back(std::move(pt));
                        }
                        ret.data.push_back(std::move(group));
                    }
                }
            }
            return ret;
        }

        Cipher2d encryptInputs(
            const troyn::Encryptor& encryptor,
            troyn::BatchEncoder& encoder, 
            const std::vector<uint64_t>& inputs
        ) {
            Plain2d plain = encodeInputs(encoder, inputs);
            return plain.encrypt(encryptor);
        }

        Cipher2d conv2d(const troyn::Evaluator& evaluator, const Cipher2d& a, const Plain2d& encodedWeights) {

            // Timer tim; auto t1 = tim.registerTimer("muladds");
            // size_t muladds = 0;

            size_t totalBatchSize = getTotalBatchSize();
            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                size_t groupLen = ceilDiv(outputChannels, blockOutputChannels);
                std::vector<Ciphertext> group; group.reserve(groupLen);
                for (size_t oc = 0; oc < groupLen; oc++) {
                    Ciphertext cipher;
                    for (size_t i = 0; i < a[b].size(); i++) {
                        Ciphertext prod;
                        // tim.tick(t1);
                        evaluator.multiplyPlain(a[b][i], encodedWeights[oc][i], prod);
                        // muladds ++;
                        // tim.tock(t1);
                        if (i==0) cipher = std::move(prod);
                        else evaluator.addInplace(cipher, prod);
                    }
                    group.push_back(std::move(cipher));
                }
                ret.data.push_back(std::move(group));
            }
            // printTimer(tim.gather(muladds));
            return ret;
        }

        Cipher2d conv2dCipher(const troyn::Evaluator& evaluator, const Cipher2d& a, const Cipher2d& encodedWeights) {
            size_t totalBatchSize = getTotalBatchSize();
            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                size_t groupLen = ceilDiv(outputChannels, blockOutputChannels);
                std::vector<Ciphertext> group; group.reserve(groupLen);
                for (size_t oc = 0; oc < groupLen; oc++) {
                    Ciphertext cipher;
                    for (size_t i = 0; i < a[b].size(); i++) {
                        Ciphertext prod;
                        evaluator.multiply(a[b][i], encodedWeights[oc][i], prod);
                        if (i==0) cipher = std::move(prod);
                        else evaluator.addInplace(cipher, prod);
                    }
                    group.push_back(std::move(cipher));
                }
                ret.data.push_back(std::move(group));
            }
            return ret;
        }

        Cipher2d conv2dReverse(const troyn::Evaluator& evaluator, const Plain2d& a, const Cipher2d& encodedWeights) {
            size_t totalBatchSize = getTotalBatchSize();
            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                size_t groupLen = ceilDiv(outputChannels, blockOutputChannels);
                std::vector<Ciphertext> group; group.reserve(groupLen);
                for (size_t oc = 0; oc < groupLen; oc++) {
                    Ciphertext cipher;
                    for (size_t i = 0; i < a[b].size(); i++) {
                        Ciphertext prod;
                        evaluator.multiplyPlain(encodedWeights[oc][i], a[b][i], prod);
                        if (i==0) cipher = std::move(prod);
                        else evaluator.addInplace(cipher, prod);
                    }
                    group.push_back(std::move(cipher));
                }
                ret.data.push_back(std::move(group));
            }
            return ret;
        }

        Plain2d encodeOutputs(
            troyn::BatchEncoder& encoder,
            const std::vector<uint64_t>& outputs
        ) {
            size_t interval = blockWidth * blockHeight;
            std::vector<uint64_t> mask(slotCount, 0);
            auto totalBatchSize = getTotalBatchSize();
            size_t yh = blockHeight - kernelHeight + 1;
            size_t yw = blockWidth  - kernelWidth  + 1;
            size_t oyh = imageHeight - kernelHeight + 1;
            size_t oyw = imageWidth - kernelWidth + 1;
            if (outputs.size() != batchSize * outputChannels * oyh * oyw) {
                throw std::invalid_argument("Outputs shape incorrect.");
            }
            Plain2d ret; ret.data.reserve(totalBatchSize);
            size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
            size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
            size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
            assert(totalBatchSize == ceilDiv(batchSize, blockBatch) * sh * sw);
            Plaintext encoded;
            std::vector<uint64_t> buffer;
            for (size_t eb = 0; eb < totalBatchSize; eb++) {
                size_t ob = eb / (sh * sw);
                size_t si = (eb % (sh * sw)) / sw;
                size_t sj = eb % sw;
                size_t lb = ob * blockBatch, ub = std::min(lb + blockBatch, batchSize);
                std::vector<Plaintext> group; group.reserve(ceilDiv(outputChannels, blockOutputChannels));
                for (size_t lc = 0; lc < outputChannels; lc += blockOutputChannels) {
                    size_t uc = std::min(lc + blockOutputChannels, outputChannels);
                    for (size_t b = lb; b < ub; b++) {
                        for (size_t c = lc; c < uc; c++) {
                            for (size_t i = 0; i < yh; i++) {
                                for (size_t j = 0; j < yw; j++) {
                                    size_t maskIndex = ((b - lb) * blockInputChannels * blockOutputChannels + (c - lc) * blockInputChannels + blockInputChannels - 1) * interval + (blockHeight - yh + i) * blockWidth + (blockWidth - yw + j);
                                    size_t originalIndex = b * outputChannels * oyh * oyw + c * oyh * oyw + (si * yh + i) * oyw + (sj * yw + j);
                                    if (si * yh + i < oyh && sj * yw + j < oyw)  mask[maskIndex] = outputs[originalIndex];
                                }
                            }
                        }
                    }
                    Plaintext encoded; encoder.encodePolynomial(mask, encoded);
                    group.push_back(std::move(encoded));
                }
                ret.data.push_back(std::move(group));
            }
            return ret;
        }

        std::vector<uint64_t> decryptOutputs(
            troyn::BatchEncoder& encoder,
            troyn::Decryptor& decryptor,
            const Cipher2d& outputs
        ) {
            size_t interval = blockWidth * blockHeight;
            auto totalBatchSize = getTotalBatchSize();
            size_t yh = blockHeight - kernelHeight + 1;
            size_t yw = blockWidth  - kernelWidth  + 1;
            size_t oyh = imageHeight - kernelHeight + 1;
            size_t oyw = imageWidth - kernelWidth + 1;
            std::vector<uint64_t> ret(batchSize * outputChannels * oyh * oyw, 0);
            size_t kh = kernelHeight - 1, kw = kernelWidth - 1;
            size_t sh = ceilDiv(imageHeight - kh, blockHeight - kh);
            size_t sw = ceilDiv(imageWidth - kw, blockWidth - kw);
            assert(totalBatchSize == ceilDiv(batchSize, blockBatch) * sh * sw);
            Plaintext encoded;
            std::vector<uint64_t> buffer;
            for (size_t eb = 0; eb < totalBatchSize; eb++) {
                size_t ob = eb / (sh * sw);
                size_t si = (eb % (sh * sw)) / sw;
                size_t sj = eb % sw;
                size_t lb = ob * blockBatch, ub = std::min(lb + blockBatch, batchSize);
                for (size_t lc = 0; lc < outputChannels; lc += blockOutputChannels) {
                    size_t uc = std::min(lc + blockOutputChannels, outputChannels);
                    // printf("Decrypting block [%lu][%lu]\n", eb, lc / blockOutputChannels);
                    decryptor.decrypt(outputs[eb][lc / blockOutputChannels], encoded);
                    encoder.decodePolynomial(encoded, buffer);
                    for (size_t b = lb; b < ub; b++) {
                        for (size_t c = lc; c < uc; c++) {
                            for (size_t i = 0; i < yh; i++) {
                                for (size_t j = 0; j < yw; j++) {
                                    size_t maskIndex = ((b - lb) * blockInputChannels * blockOutputChannels + (c - lc) * blockInputChannels + blockInputChannels - 1) * interval + (blockHeight - yh + i) * blockWidth + (blockWidth - yw + j);
                                    size_t originalIndex = b * outputChannels * oyh * oyw + c * oyh * oyw + (si * yh + i) * oyw + (sj * yw + j);
                                    // printf("Original[%lu][%lu][%lu][%lu] <- idx[%lu]\n", b, c, si * yh + i, sj * yw + j, maskIndex);
                                    if (si * yh + i < oyh && sj * yw + j < oyw) {
                                        ret[originalIndex] = buffer[maskIndex];
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return ret;
        }

        void serializeOutputs(troy::EvaluatorCuda &evaluator, const Cipher2d& x, std::ostream& stream) {
            auto totalBatchSize = getTotalBatchSize();
            size_t interval = blockWidth * blockHeight;
            
            size_t yh = blockHeight - kernelHeight + 1;
            size_t yw = blockWidth  - kernelWidth  + 1;

            std::vector<size_t> required;
            required.reserve(yh * yw * blockBatch * blockOutputChannels);

            for (size_t b = 0; b < blockBatch; b++) {
                for (size_t c = 0; c < blockOutputChannels; c++) {
                    for (size_t i = 0; i < yh; i++) {
                        for (size_t j = 0; j < yw; j++) {
                            size_t maskIndex = (b * blockInputChannels * blockOutputChannels + c * blockInputChannels + blockInputChannels - 1) * interval + (blockHeight - yh + i) * blockWidth + (blockWidth - yw + j);
                            required.push_back(maskIndex);
                        }
                    }
                }
            }

            for (size_t b = 0; b < totalBatchSize; b++) {
                for (size_t oc = 0; oc < ceilDiv(outputChannels, blockOutputChannels); oc++) 
                    x[b][oc].saveTerms(stream, evaluator, required);
            }
        }

        Cipher2d deserializeOutputs(troy::EvaluatorCuda &evaluator, std::istream& stream) {
            auto totalBatchSize = getTotalBatchSize();
            size_t interval = blockWidth * blockHeight;
            
            size_t yh = blockHeight - kernelHeight + 1;
            size_t yw = blockWidth  - kernelWidth  + 1;

            std::vector<size_t> required;
            required.reserve(yh * yw * blockBatch * blockOutputChannels);

            for (size_t b = 0; b < blockBatch; b++) {
                for (size_t c = 0; c < blockOutputChannels; c++) {
                    for (size_t i = 0; i < yh; i++) {
                        for (size_t j = 0; j < yw; j++) {
                            size_t maskIndex = (b * blockInputChannels * blockOutputChannels + c * blockInputChannels + blockInputChannels - 1) * interval + (blockHeight - yh + i) * blockWidth + (blockWidth - yw + j);
                            required.push_back(maskIndex);
                        }
                    }
                }
            }

            Cipher2d ret; ret.data.reserve(totalBatchSize);
            for (size_t b = 0; b < totalBatchSize; b++) {
                std::vector<Ciphertext> row(outputChannels);
                for (size_t oc = 0; oc < ceilDiv(outputChannels, blockOutputChannels); oc++) 
                    row[oc].loadTerms(stream, evaluator, required);
                ret.data.push_back(std::move(row));
            }
            return ret;
        }

    };

}