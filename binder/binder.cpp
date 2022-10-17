#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>

#include "../src/troy_cuda.cuh"

namespace py = pybind11;

using namespace troym;

PYBIND11_MODULE(pytroy, m) {
    
    py::class_<Plaintext>(m, "Plaintext")
        .def("parms_id", &Plaintext::parmsID);

}