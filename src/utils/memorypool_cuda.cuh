#include "../kernelprovider.cuh"
#include <map>

namespace troy {

    namespace util {

        class MemoryPoolCuda {

        private:
            static MemoryPoolCuda singleton;
            MemoryPoolCuda() {}

            std::multimap<size_t, void*> pointers;

            inline void* get(size_t require) {
                auto iterator = pointers.lower_bound(require);
                if (iterator == pointers.end()) {
                    return reinterpret_cast<void*>(KernelProvider::malloc<char>(require));
                } else {
                    void* p = iterator->second;
                    pointers.erase(iterator);
                    return p;
                }
            }

            inline void insert(void* ptr, size_t size) {
                pointers.insert(std::make_pair(size, ptr));
            }

            ~MemoryPoolCuda() {
                for (auto& pair: pointers) {
                    KernelProvider::free(pair.second);
                }
            }

        public:

            inline static void* Get(size_t require) {
                return singleton.get(require);
            }

            inline static void Free(void* ptr, size_t size) {
                singleton.insert(ptr, size);
            }

        };

    }

}